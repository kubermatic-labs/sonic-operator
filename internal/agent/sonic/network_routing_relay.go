// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

type routingSpecMeta struct {
	SwitchRef struct {
		Name string `json:"name"`
	} `json:"switchRef"`
	ManagementPolicy string `json:"managementPolicy"`
}

type routingBGPSpec struct {
	routingSpecMeta
	Mode     string   `json:"mode,omitempty"`
	VRF      string   `json:"vrf"`
	LocalASN uint32   `json:"localASN"`
	RouterID string   `json:"routerID"`
	Prefixes []string `json:"prefixes"`
}

type routingPeerSpec struct {
	routingSpecMeta
	VRF             string   `json:"vrf"`
	Address         string   `json:"address"`
	RemoteASN       uint32   `json:"remoteASN"`
	LocalAddress    string   `json:"localAddress"`
	AddressFamilies []string `json:"addressFamilies"`
	AdminState      string   `json:"adminState"`
	MaxPrefixes     *uint32  `json:"maxPrefixes"`
}

type routingRelaySpec struct {
	routingSpecMeta
	VLANID      uint32   `json:"vlanID"`
	VRF         string   `json:"vrf"`
	IPv4Servers []string `json:"ipv4Servers"`
	IPv6Servers []string `json:"ipv6Servers"`
}

// Decode tokens first: encoding/json otherwise accepts duplicate and case-folded
// field names. No raw values are included in errors (specs may contain secrets).
func routingDecode(r *agent.NetworkRequest, kind string, out any, fields string) error {
	if r == nil || r.Kind != kind {
		return fmt.Errorf("expected %s request", kind)
	}
	if len(r.Spec) == 0 || len(r.Spec) > 1<<20 {
		return fmt.Errorf("invalid spec size")
	}
	allowed := map[string]bool{"switchRef": true, "managementPolicy": true}
	for _, field := range strings.Fields(fields) {
		allowed[field] = true
	}
	d := json.NewDecoder(bytes.NewReader(r.Spec))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return fmt.Errorf("spec must be a JSON object")
	}
	seen := map[string]bool{}
	for d.More() {
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return fmt.Errorf("invalid JSON field")
		}
		if seen[key] {
			return fmt.Errorf("duplicate JSON field")
		}
		if !allowed[key] {
			return fmt.Errorf("unknown JSON field")
		}
		seen[key] = true
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return fmt.Errorf("invalid JSON value")
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("null fields are not supported")
		}
		if key == "switchRef" {
			var ref struct {
				Name string `json:"name"`
			}
			if err := routingDecode(&agent.NetworkRequest{Kind: "reference", Spec: value}, "reference", &ref, "name"); err != nil {
				return err
			}
		}
	}
	if _, err := d.Token(); err != nil {
		return fmt.Errorf("invalid JSON object")
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	d = json.NewDecoder(bytes.NewReader(r.Spec))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return fmt.Errorf("invalid %s spec field type or value", kind)
	}
	return nil
}

var routingVRFPattern = regexp.MustCompile(`^Vrf[A-Za-z0-9_-]{1,12}$`)

func routingVRF(db vlanChangeDB, vrf *string) error {
	if *vrf == "" {
		*vrf = "default"
	}
	if *vrf == "default" {
		return nil
	}
	if !routingVRFPattern.MatchString(*vrf) {
		return fmt.Errorf("vrf must be default or VrfNAME (maximum 15 characters)")
	}
	if _, exists := db["VRF|"+*vrf]; !exists {
		return fmt.Errorf("vrf does not exist")
	}
	return nil
}

func routingAddress(value string, ipv4 *bool) (netip.Addr, error) {
	a, err := netip.ParseAddr(value)
	if err != nil || a.Is4In6() || a.Zone() != "" || !a.IsGlobalUnicast() || a.IsLoopback() || a == netip.MustParseAddr("255.255.255.255") {
		return netip.Addr{}, fmt.Errorf("address must be an unscoped, non-link-local unicast IP")
	}
	if ipv4 != nil && a.Is4() != *ipv4 {
		return netip.Addr{}, fmt.Errorf("address must be IPv%d", map[bool]int{true: 4, false: 6}[*ipv4])
	}
	return a, nil
}

func routingPrefixes(values []string) ([]string, error) {
	result := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		p, err := netip.ParsePrefix(value)
		if err != nil || p.Addr().Is4In6() || p.Masked() != p || p.String() != value {
			return nil, fmt.Errorf("prefixes must be canonical IPv4/IPv6 networks")
		}
		if p.Addr().IsMulticast() || p.Addr().IsLinkLocalUnicast() || p.Addr().IsLoopback() {
			return nil, fmt.Errorf("prefixes cannot be multicast, link-local or loopback")
		}
		if seen[value] {
			return nil, fmt.Errorf("duplicate prefix")
		}
		seen[value] = true
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

func routingExportName(vrf, family string) string {
	h := sha256.Sum256([]byte(vrf))
	return fmt.Sprintf("SONIC_OPERATOR_%x_%s", h[:8], family)
}

func routingExportPolicy(vrf string, prefixes []string) vlanChangeDB {
	desired := vlanChangeDB{}
	for _, af := range []string{"ipv4_unicast", "ipv6_unicast"} {
		name := routingExportName(vrf, af)
		mode, anyPrefix, maxLen := "IPv4", "0.0.0.0/0", "32"
		if af == "ipv6_unicast" {
			mode, anyPrefix, maxLen = "IPv6", "::/0", "128"
		}
		desired["PREFIX_SET|"+name] = map[string]string{"mode": mode}
		seq := 1
		for _, p := range prefixes {
			if strings.Contains(p, ":") != (af == "ipv6_unicast") {
				continue
			}
			desired[fmt.Sprintf("PREFIX|%s|%d|%s|exact", name, seq, p)] = map[string]string{"action": "permit"}
			seq++
		}
		desired["PREFIX|"+name+"|4294967295|"+anyPrefix+"|0.."+maxLen] = map[string]string{"action": "deny"}
	}
	return desired
}

func routingUnified(db vlanChangeDB) error {
	if db["DEVICE_METADATA|localhost"]["frr_mgmt_framework_config"] != "true" {
		return fmt.Errorf("traditional bgpcfgd is unsupported: explicit prefixes/export filters and maxPrefixes cannot be enforced; provision unified frrcfgd out of band (frr_mgmt_framework_config=true), do not simply change metadata on a running switch")
	}
	return nil
}

// Reject unmanaged origination/import policy rather than erasing it or claiming
// that an empty prefixes list suppresses settings owned by somebody else.
func routingNoImplicitAdvertisements(db vlanChangeDB, vrf string, prefixes []string) error {
	if _, _, err := evpnIsolatedConfig(db); err != nil {
		return err
	}
	wanted := map[string]bool{}
	for _, p := range prefixes {
		af := "ipv4_unicast"
		if strings.Contains(p, ":") {
			af = "ipv6_unicast"
		}
		wanted["BGP_GLOBALS_AF_NETWORK|"+vrf+"|"+af+"|"+p] = true
	}
	for key, fields := range db {
		for _, table := range []string{"ROUTE_REDISTRIBUTE", "BGP_GLOBALS_AF_AGGREGATE_ADDR"} {
			if strings.HasPrefix(key, table+"|"+vrf+"|") {
				return fmt.Errorf("existing %s conflicts with explicit-only advertisements", table)
			}
		}
		if strings.HasPrefix(key, "BGP_GLOBALS_AF_NETWORK|"+vrf+"|") && (!wanted[key] || fields["policy"] != "" || fields["backdoor"] == "true") {
			return fmt.Errorf("existing network conflicts with explicit prefixes; removal is not supported")
		}
		if strings.HasPrefix(key, "BGP_GLOBALS_AF|"+vrf+"|") {
			if key == evpnGlobalKey && evpnGlobalConfigValid(fields) {
				continue
			}
			for field, value := range fields {
				if (strings.HasPrefix(field, "redistribute") || strings.HasPrefix(field, "import") || strings.HasPrefix(field, "export") || strings.HasPrefix(field, "advertise") || strings.HasPrefix(field, "default-originate")) && value != "false" && value != "" {
					return fmt.Errorf("existing address-family import/export policy is unsupported")
				}
			}
		}
	}
	return nil
}

func planNetworkBGP(db vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
	var s routingBGPSpec
	if err := routingDecode(r, "BGP", &s, "mode vrf localASN routerID prefixes"); err != nil {
		return nil, err
	}
	if err := routingVRF(db, &s.VRF); err != nil {
		return nil, err
	}
	if s.LocalASN == 0 {
		return nil, fmt.Errorf("localASN must be nonzero")
	}
	v4 := true
	id, err := routingAddress(s.RouterID, &v4)
	if err != nil {
		return nil, fmt.Errorf("routerID: %w", err)
	}
	s.RouterID = id.String()
	s.Prefixes, err = routingPrefixes(s.Prefixes)
	if err != nil {
		return nil, err
	}
	if s.Mode == "Traditional" {
		return planTraditionalBGP(db, s)
	}
	if s.Mode != "" && s.Mode != "Unified" {
		return nil, fmt.Errorf("unsupported BGP backend mode")
	}
	if err := routingUnified(db); err != nil {
		return nil, err
	}
	if err := routingNoImplicitAdvertisements(db, s.VRF, s.Prefixes); err != nil {
		return nil, err
	}
	asn := strconv.FormatUint(uint64(s.LocalASN), 10)
	if current := db["BGP_GLOBALS|"+s.VRF]["local_asn"]; current != "" && current != asn {
		return nil, fmt.Errorf("localASN updates are not supported by frrcfgd")
	}
	desired := routingExportPolicy(s.VRF, s.Prefixes)
	// Reserved export sets must not contain extra entries: additive writes would
	// leave those entries active, potentially leaking routes.
	for _, af := range []string{"ipv4_unicast", "ipv6_unicast"} {
		for key := range db {
			if strings.HasPrefix(key, "PREFIX|"+routingExportName(s.VRF, af)+"|") {
				if _, ok := desired[key]; !ok {
					return nil, fmt.Errorf("existing export filter contains extra entries; removal/reordering is not supported")
				}
			}
		}
	}
	desired["BGP_GLOBALS|"+s.VRF] = map[string]string{"local_asn": asn, "router_id": s.RouterID, "default_ipv4_unicast": "false", "default_shutdown": "true"}
	for _, p := range s.Prefixes {
		af := "ipv4_unicast"
		if strings.Contains(p, ":") {
			af = "ipv6_unicast"
		}
		desired["BGP_GLOBALS_AF_NETWORK|"+s.VRF+"|"+af+"|"+p] = map[string]string{"backdoor": "false"}
	}
	if !networkSubset(db, desired) {
		for key, fields := range db {
			if (strings.HasPrefix(key, "BGP_NEIGHBOR|"+s.VRF+"|") && fields["admin_status"] != "down") || strings.HasPrefix(key, "BGP_PEER_GROUP|"+s.VRF+"|") || strings.HasPrefix(key, "BGP_GLOBALS_LISTEN_PREFIX|"+s.VRF+"|") {
				return nil, fmt.Errorf("BGP policy changes require all peers Down and no dynamic peer groups before FRR preflight")
			}
		}
	}
	plan := &networkPlan{Identity: "BGP|" + s.VRF, Desired: desired, Runtime: func(ctx context.Context, _ *SonicAgent) (bool, json.RawMessage, error) {
		return observeRoutingBGP(ctx, runRoutingRead, s.VRF, s.LocalASN, s.RouterID, s.Prefixes, nil)
	}}
	if !networkSubset(db, desired) {
		plan.Preflight = func(ctx context.Context, _ *SonicAgent) error {
			return routingShutdownPreflight(ctx, runRoutingRead, s.VRF, s.LocalASN, "")
		}
	}
	return evpnGuardUnicastPlan(plan, db), nil
}

//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func planNetworkBGPPeer(db vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
	var s routingPeerSpec
	if err := routingDecode(r, "BGPPeer", &s, "vrf address remoteASN localAddress addressFamilies adminState maxPrefixes"); err != nil {
		return nil, err
	}
	if err := routingVRF(db, &s.VRF); err != nil {
		return nil, err
	}
	address, err := routingAddress(s.Address, nil)
	if err != nil {
		return nil, err
	}
	s.Address = address.String()
	if s.RemoteASN == 0 {
		return nil, fmt.Errorf("remoteASN must be nonzero")
	}
	if s.AdminState == "" {
		s.AdminState = "Down"
	}
	if s.AdminState != "Down" && s.AdminState != "Up" {
		return nil, fmt.Errorf("adminState must be Up or Down")
	}
	if s.MaxPrefixes == nil {
		value := uint32(1000)
		s.MaxPrefixes = &value
	}
	if *s.MaxPrefixes == 0 {
		return nil, fmt.Errorf("maxPrefixes must be nonzero")
	}
	if len(s.AddressFamilies) == 0 {
		return nil, fmt.Errorf("addressFamilies must not be empty")
	}
	families := map[string]bool{}
	for _, family := range s.AddressFamilies {
		if (family != "ipv4Unicast" && family != "ipv6Unicast") || families[family] {
			return nil, fmt.Errorf("invalid or duplicate addressFamilies")
		}
		families[family] = true
	}
	if s.LocalAddress != "" {
		v4 := address.Is4()
		local, err := routingAddress(s.LocalAddress, &v4)
		if err != nil {
			return nil, fmt.Errorf("localAddress: %w", err)
		}
		s.LocalAddress = local.String()
		found := false
		for key := range db {
			parts := strings.Split(key, "|")
			if len(parts) != 3 || (parts[0] != "INTERFACE" && parts[0] != "PORTCHANNEL_INTERFACE" && parts[0] != "VLAN_INTERFACE" && parts[0] != "LOOPBACK_INTERFACE") {
				continue
			}
			prefix, err := netip.ParsePrefix(parts[2])
			vrf := db[parts[0]+"|"+parts[1]]["vrf_name"]
			if vrf == "" {
				vrf = "default"
			}
			if err == nil && prefix.Addr() == local && vrf == s.VRF {
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("localAddress requires an interface address in the same VRF")
		}
	}
	if err := routingUnified(db); err != nil {
		return nil, err
	}
	global := db["BGP_GLOBALS|"+s.VRF]
	localASN, err := strconv.ParseUint(global["local_asn"], 10, 32)
	if err != nil || localASN == 0 || global["default_ipv4_unicast"] != "false" || global["default_shutdown"] != "true" {
		return nil, fmt.Errorf("configure SwitchBGP with safe defaults before peers")
	}
	var prefixes []string
	for key := range db {
		if strings.HasPrefix(key, "BGP_GLOBALS_AF_NETWORK|"+s.VRF+"|") {
			parts := strings.Split(key, "|")
			if len(parts) != 4 {
				return nil, fmt.Errorf("invalid existing BGP network key")
			}
			prefixes = append(prefixes, parts[3])
		}
	}
	prefixes, err = routingPrefixes(prefixes)
	if err != nil {
		return nil, err
	}
	if err := routingNoImplicitAdvertisements(db, s.VRF, prefixes); err != nil {
		return nil, err
	}
	if present, _, err := evpnIsolatedConfig(db); err != nil {
		return nil, err
	} else if present && s.AdminState == "Up" {
		if _, err := evpnConfiguredPeerPolicy(db, s.Address); err != nil {
			return nil, err
		}
		if db["BGP_NEIGHBOR_AF|default|"+s.Address+"|"+evpnAF]["admin_status"] != "up" {
			return nil, fmt.Errorf("EVPN AF must be staged Up before parent activation")
		}
	}
	policy := routingExportPolicy(s.VRF, prefixes)
	for key, fields := range policy {
		for f, v := range fields {
			if db[key][f] != v {
				return nil, fmt.Errorf("configure SwitchBGP export filters before peers")
			}
		}
	}
	for _, af := range []string{"ipv4_unicast", "ipv6_unicast"} {
		for key := range db {
			if strings.HasPrefix(key, "PREFIX|"+routingExportName(s.VRF, af)+"|") {
				if _, ok := policy[key]; !ok {
					return nil, fmt.Errorf("unexpected export filter entry")
				}
			}
		}
	}
	key := "BGP_NEIGHBOR|" + s.VRF + "|" + s.Address
	if db[key]["peer_group_name"] != "" {
		return nil, fmt.Errorf("peer-group inheritance is unsupported")
	}
	desired := vlanChangeDB{key: {"asn": strconv.FormatUint(uint64(s.RemoteASN), 10), "admin_status": strings.ToLower(s.AdminState)}}
	if s.LocalAddress != "" {
		desired[key]["local_addr"] = s.LocalAddress
	} else if db[key]["local_addr"] != "" {
		return nil, fmt.Errorf("removal of localAddress is unsupported")
	}
	for existingKey := range db {
		if strings.HasPrefix(existingKey, "BGP_NEIGHBOR_AF|"+s.VRF+"|"+s.Address+"|") && !strings.HasSuffix(existingKey, "|ipv4_unicast") && !strings.HasSuffix(existingKey, "|ipv6_unicast") {
			// The complete exact disabled EVPN contract was validated above.
			// Do not claim this other resource's AF field in desired/ownership.
			if s.VRF == "default" && strings.HasSuffix(existingKey, "|"+evpnAF) {
				continue
			}
			return nil, fmt.Errorf("existing peer has unsupported address families")
		}
	}
	for _, af := range []string{"ipv4_unicast", "ipv6_unicast"} {
		family := "ipv4Unicast"
		if af == "ipv6_unicast" {
			family = "ipv6Unicast"
		}
		afKey := "BGP_NEIGHBOR_AF|" + s.VRF + "|" + s.Address + "|" + af
		if !families[family] {
			if fields := db[afKey]; fields["admin_status"] != "" && fields["admin_status"] != "down" {
				return nil, fmt.Errorf("removing an active address family is unsupported")
			}
			continue
		}
		if db[afKey]["max_prefix_restart_interval"] != "" || db[afKey]["max_prefix_warning_only"] == "true" || db[afKey]["default_rmap"] != "" {
			return nil, fmt.Errorf("existing max-prefix/default-originate policy conflicts with safety contract")
		}
		desired[afKey] = map[string]string{"admin_status": "up", "max_prefix_limit": strconv.FormatUint(uint64(*s.MaxPrefixes), 10), "max_prefix_warning_threshold": "100", "prefix_list_out": routingExportName(s.VRF, af), "send_default_route": "false"}
	}
	// CONFIG_DB events are not a transaction in FRR. Never enable a new peer in
	// the same operation that creates its limits and outbound filter.
	if s.AdminState == "Up" {
		if db[key]["admin_status"] != "up" && db[key]["admin_status"] != "down" {
			return nil, fmt.Errorf("create and verify a complete Down peer before requesting Up")
		}
		for k, fields := range desired {
			for f, v := range fields {
				if k == key && f == "admin_status" {
					continue
				}
				if db[k][f] != v {
					return nil, fmt.Errorf("stage peer policy while Down and verify runtime before requesting Up")
				}
			}
		}
	}
	if len(db[key]) > 0 && db[key]["admin_status"] != "down" {
		for k, fields := range desired {
			for f, v := range fields {
				if k == key && f == "admin_status" {
					continue
				}
				if db[k][f] != v {
					return nil, fmt.Errorf("shutdown peer in a separate operation before modifying policy")
				}
			}
		}
	}
	plan := &networkPlan{Identity: "BGPPeer|" + s.VRF + "|" + s.Address, Desired: desired, Runtime: func(ctx context.Context, _ *SonicAgent) (bool, json.RawMessage, error) {
		return observeRoutingBGP(ctx, runRoutingRead, s.VRF, uint32(localASN), global["router_id"], prefixes, &s)
	}}
	if s.AdminState == "Up" && db[key]["admin_status"] == "down" {
		staged := s
		staged.AdminState = "Down"
		plan.Preflight = func(ctx context.Context, _ *SonicAgent) error {
			return routingPeerPreflight(ctx, runRoutingRead, uint32(localASN), global["router_id"], prefixes, staged)
		}
	} else if !networkSubset(db, desired) {
		policyChanged := false
		for k, fields := range desired {
			for field, value := range fields {
				if k == key && field == "admin_status" {
					continue
				}
				if db[k][field] != value {
					policyChanged = true
				}
			}
		}
		if policyChanged {
			plan.Preflight = func(ctx context.Context, _ *SonicAgent) error {
				return routingShutdownPreflight(ctx, runRoutingRead, s.VRF, uint32(localASN), s.Address)
			}
		}
	}
	guarded := evpnGuardUnicastPlan(plan, db)
	if s.AdminState == "Up" && db["BGP_NEIGHBOR_AF|default|"+s.Address+"|"+evpnAF] != nil {
		before := guarded.Preflight
		guarded.Preflight = func(ctx context.Context, m *SonicAgent) error {
			current, _, err := m.vlanChangeSnapshot(ctx)
			if err != nil {
				return err
			}
			if err := evpnParentActivation(ctx, m, current, s.Address); err != nil {
				return err
			}
			return before(ctx, m)
		}
	}
	return guarded, nil
}

//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func planNetworkDHCPRelay(db vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
	var s routingRelaySpec
	if err := routingDecode(r, "DHCPRelay", &s, "vlanID vrf ipv4Servers ipv6Servers"); err != nil {
		return nil, err
	}
	if s.VLANID < 1 || s.VLANID > 4094 {
		return nil, fmt.Errorf("vlanID must be 1..4094")
	}
	if err := routingVRF(db, &s.VRF); err != nil {
		return nil, err
	}
	if len(s.IPv4Servers)+len(s.IPv6Servers) == 0 {
		return nil, fmt.Errorf("empty relay server lists are unsupported; removal is outside additive scope")
	}
	for index, servers := range []*[]string{&s.IPv4Servers, &s.IPv6Servers} {
		seen := map[string]bool{}
		for i, value := range *servers {
			v4 := index == 0
			address, err := routingAddress(value, &v4)
			if err != nil {
				return nil, err
			}
			if seen[address.String()] {
				return nil, fmt.Errorf("duplicate relay server")
			}
			seen[address.String()] = true
			(*servers)[i] = address.String()
		}
		sort.Strings(*servers)
	}
	vlan := "Vlan" + strconv.FormatUint(uint64(s.VLANID), 10)
	if db["VLAN|"+vlan]["vlanid"] != strconv.FormatUint(uint64(s.VLANID), 10) {
		return nil, fmt.Errorf("VLAN must exist")
	}
	svi, exists := db["VLAN_INTERFACE|"+vlan]
	if !exists {
		return nil, fmt.Errorf("VLAN requires an SVI")
	}
	vrf := svi["vrf_name"]
	if vrf == "" {
		vrf = "default"
	}
	if vrf != s.VRF {
		return nil, fmt.Errorf("relay VRF must match SVI VRF")
	}
	if svi["vnet_name"] != "" {
		return nil, fmt.Errorf("VNET relay is unsupported")
	}
	families := map[bool]bool{}
	for key := range db {
		if strings.HasPrefix(key, "VLAN_INTERFACE|"+vlan+"|") {
			prefix, err := netip.ParsePrefix(strings.TrimPrefix(key, "VLAN_INTERFACE|"+vlan+"|"))
			if err == nil && !prefix.Addr().Is4In6() && prefix.Addr().IsGlobalUnicast() {
				families[prefix.Addr().Is4()] = true
			}
		}
	}
	if len(s.IPv4Servers) > 0 && !families[true] || len(s.IPv6Servers) > 0 && !families[false] {
		return nil, fmt.Errorf("each relay family requires a same-family SVI address")
	}
	native := db["DEVICE_METADATA|localhost"]["has_sonic_dhcpv4_relay"] == "True"
	if s.VRF != "default" && (len(s.IPv6Servers) > 0 || !native) {
		return nil, fmt.Errorf("non-default VRF is only proven for native DHCPv4 relay, not legacy IPv4 or IPv6")
	}
	if db["DEVICE_METADATA|localhost"]["subtype"] == "DualToR" {
		return nil, fmt.Errorf("DualToR relay is outside this per-VLAN contract")
	}
	if len(s.IPv4Servers) > 0 && (db["FEATURE|dhcp_server"]["state"] == "enabled" || db["FEATURE|dhcp_server"]["state"] == "always_enabled") {
		return nil, fmt.Errorf("DHCP server feature conflicts with relay management")
	}
	desired := vlanChangeDB{}
	if len(s.IPv4Servers) > 0 {
		key, field := "VLAN|"+vlan, "dhcp_servers@"
		if native {
			key, field = "DHCPV4_RELAY|"+vlan, "dhcpv4_servers@"
		}
		for _, f := range []string{"server_vrf", "source_interface", "link_selection", "vrf_selection", "server_id_override"} {
			if v := db["DHCPV4_RELAY|"+vlan][f]; v != "" && v != "disable" {
				return nil, fmt.Errorf("existing relay source/VRF override is unsupported")
			}
		}
		value := strings.Join(s.IPv4Servers, ",")
		desired[key] = map[string]string{field: value}
	}
	if len(s.IPv6Servers) > 0 {
		key := "DHCP_RELAY|" + vlan
		desired[key] = map[string]string{"dhcpv6_servers@": strings.Join(s.IPv6Servers, ",")}
	}
	plan := &networkPlan{Identity: "DHCPRelay|" + vlan, Desired: desired, Runtime: func(ctx context.Context, m *SonicAgent) (bool, json.RawMessage, error) {
		return routingRelayRuntime(ctx, routingRelayOperations(m), desired, vlan, native, s.IPv4Servers, s.IPv6Servers)
	}}
	// Keep this callback in post-state plans too: recovery must still activate a
	// journaled update after Redis changed but the agent exited before restart.
	if !native || len(s.IPv6Servers) > 0 {
		plan.Preflight = func(ctx context.Context, m *SonicAgent) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			return routingRelayPrepareStorage(m.networkJournalDir)
		}
		plan.Activate = func(ctx context.Context, m *SonicAgent) error {
			return activateRoutingRelay(ctx, routingRelayOperations(m), desired, vlan, native, s.IPv4Servers, s.IPv6Servers)
		}
	}
	return plan, nil
}

func routingServerSetEqual(value string, servers []string) bool {
	parts := strings.Split(value, ",")
	if len(parts) != len(servers) {
		return false
	}
	for i, part := range parts {
		address, err := netip.ParseAddr(part)
		if err != nil {
			return false
		}
		parts[i] = address.String()
	}
	sort.Strings(parts)
	want := append([]string(nil), servers...)
	sort.Strings(want)
	return strings.Join(parts, ",") == strings.Join(want, ",")
}

// The engine still requires durable ownership and exact old-value match.
func routingRelayMutableField(key, field string) bool {
	table, name, ok := strings.Cut(key, "|")
	if !ok || !strings.HasPrefix(name, "Vlan") {
		return false
	}
	id, err := strconv.ParseUint(strings.TrimPrefix(name, "Vlan"), 10, 16)
	if err != nil || id < 1 || id > 4094 || name != "Vlan"+strconv.FormatUint(id, 10) {
		return false
	}
	return table == "VLAN" && field == "dhcp_servers@" || table == "DHCPV4_RELAY" && field == "dhcpv4_servers@" || table == "DHCP_RELAY" && field == "dhcpv6_servers@"
}
