// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

// L2 only. In particular these types deliberately have no gateway, ESI, L3VNI,
// global advertise-all-vni, peer-group, or user-supplied route-map fields.
type evpnTunnelSpec struct {
	routingSpecMeta
	Name          string `json:"name"`
	SourceAddress string `json:"sourceAddress"`
	EVPNNVO       string `json:"evpnNVO"`
}

type evpnMapSpec struct {
	routingSpecMeta
	Tunnel             string   `json:"tunnel"`
	VLANID             uint32   `json:"vlanID"`
	VNI                uint32   `json:"vni"`
	RouteDistinguisher string   `json:"routeDistinguisher"`
	ImportRouteTargets []string `json:"importRouteTargets"`
	ExportRouteTargets []string `json:"exportRouteTargets"`
}

type evpnPeerSpec struct {
	routingSpecMeta
	Role               string   `json:"role,omitempty"`
	ImportRouteTargets []string `json:"importRouteTargets,omitempty"`
	ExportRouteTargets []string `json:"exportRouteTargets,omitempty"`
	VRF                string   `json:"vrf"`
	Address            string   `json:"address"`
	RemoteASN          uint32   `json:"remoteASN"`
	LocalAddress       string   `json:"localAddress"`
	AdminState         string   `json:"adminState"`
	MappingRefs        []struct {
		Name string `json:"name"`
	} `json:"mappingRefs,omitempty"`
	Mappings []agent.EVPNMappingSnapshot `json:"mappings,omitempty"`
}

var evpnName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,31}$`)
var evpnInterface = regexp.MustCompile(`^(Ethernet|PortChannel|Loopback)[0-9]+$`)

const evpnAF = "l2vpn_evpn"
const evpnUpUnsupported = "EVPN Up unsupported: per-VNI RTs do not enforce peer export isolation; a verified native RT export allowlist and shared SwitchBGPPeer activation guard are required before AF activation"

func planNetworkVXLANTunnel(db vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
	var s evpnTunnelSpec
	if err := routingDecode(r, "VXLANTunnel", &s, "name sourceAddress evpnNVO"); err != nil {
		return nil, err
	}
	if !evpnName.MatchString(s.Name) || !evpnName.MatchString(s.EVPNNVO) {
		return nil, fmt.Errorf("invalid tunnel or NVO name")
	}
	v4 := true
	source, err := routingAddress(s.SourceAddress, &v4)
	if err != nil {
		return nil, err
	}
	s.SourceAddress = source.String()
	if _, err := evpnLocalInterface(db, source); err != nil {
		return nil, err
	}
	if err := evpnSafeConfig(db); err != nil {
		return nil, err
	}
	for key, row := range db {
		if strings.HasPrefix(key, "VXLAN_TUNNEL|") && key != "VXLAN_TUNNEL|"+s.Name {
			return nil, fmt.Errorf("only one local L2 VTEP is supported")
		}
		if strings.HasPrefix(key, "VXLAN_EVPN_NVO|") && (key != "VXLAN_EVPN_NVO|"+s.EVPNNVO || row["source_vtep"] != s.Name) {
			return nil, fmt.Errorf("conflicting NVO")
		}
	}
	desired := vlanChangeDB{"VXLAN_TUNNEL|" + s.Name: {"src_ip": s.SourceAddress}, "VXLAN_EVPN_NVO|" + s.EVPNNVO: {"source_vtep": s.Name}}
	if err := evpnExactExisting(db, desired); err != nil {
		return nil, err
	}
	if !networkSubset(db, desired) && db[evpnGlobalKey]["advertise-all-vni"] == "true" {
		return nil, fmt.Errorf("disable global EVPN advertisement before tunnel changes")
	}
	p := &networkPlan{Identity: "VXLANTunnel|" + s.Name, Desired: desired}
	p.Preflight = func(ctx context.Context, m *SonicAgent) error {
		return evpnBootstrapPreflight(ctx, m, s.SourceAddress)
	}
	p.Runtime = func(ctx context.Context, m *SonicAgent) (bool, json.RawMessage, error) {
		oid, _, err := evpnTunnelASIC(ctx, qosRedisRead{m}, s.Name, s.SourceAddress)
		return evpnObservation(oid != "" && err == nil, "correlated VXLAN tunnel and termination", map[string]any{"tunnelOID": oid}, err)
	}
	return p, nil
}

//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func planNetworkVLANVNI(db vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
	var s evpnMapSpec
	if err := routingDecode(r, "VLANVNI", &s, "tunnel vlanID vni routeDistinguisher importRouteTargets exportRouteTargets"); err != nil {
		return nil, err
	}
	if !evpnName.MatchString(s.Tunnel) || s.VLANID < 1 || s.VLANID > 4094 || s.VNI < 1 || s.VNI > 16777215 {
		return nil, fmt.Errorf("invalid tunnel, VLAN or VNI")
	}
	if err := evpnRD(s.RouteDistinguisher); err != nil {
		return nil, err
	}
	var err error
	if s.ImportRouteTargets, err = evpnRTs(s.ImportRouteTargets); err != nil {
		return nil, err
	}
	if s.ExportRouteTargets, err = evpnRTs(s.ExportRouteTargets); err != nil {
		return nil, err
	}
	if err := evpnSafeConfig(db); err != nil {
		return nil, err
	}
	vlan, vni := fmt.Sprintf("Vlan%d", s.VLANID), strconv.FormatUint(uint64(s.VNI), 10)
	if db["VLAN|"+vlan]["vlanid"] != strconv.FormatUint(uint64(s.VLANID), 10) {
		return nil, fmt.Errorf("VLAN must already exist with matching vlanid")
	}
	source := db["VXLAN_TUNNEL|"+s.Tunnel]["src_ip"]
	a, err := routingAddress(source, nil)
	if err != nil || !a.Is4() {
		return nil, fmt.Errorf("existing IPv4 tunnel required")
	}
	if _, err := evpnLocalInterface(db, a); err != nil {
		return nil, err
	}
	nvos := 0
	for key, row := range db {
		if strings.HasPrefix(key, "VXLAN_EVPN_NVO|") && row["source_vtep"] == s.Tunnel {
			nvos++
		}
	}
	if nvos != 1 {
		return nil, fmt.Errorf("existing unique NVO for tunnel required")
	}
	mapKey := fmt.Sprintf("VXLAN_TUNNEL_MAP|%s|map_%d_%s", s.Tunnel, s.VNI, vlan)
	vniKey := "BGP_GLOBALS_EVPN_VNI|default|" + evpnAF + "|" + vni
	desired := vlanChangeDB{mapKey: {"vlan": vlan, "vni": vni}, vniKey: {"route-distinguisher": s.RouteDistinguisher}}
	// frrcfgd's native RT table is keyed by RT, with a *hyphenated* field.
	// Combining a shared import/export RT into 'both' avoids duplicate keys.
	for _, rt := range s.ImportRouteTargets {
		desired["BGP_GLOBALS_EVPN_VNI_RT|default|"+evpnAF+"|"+vni+"|"+rt] = map[string]string{"route-target-type": "import"}
	}
	for _, rt := range s.ExportRouteTargets {
		key := "BGP_GLOBALS_EVPN_VNI_RT|default|" + evpnAF + "|" + vni + "|" + rt
		typ := "export"
		if desired[key] != nil {
			typ = "both"
		}
		desired[key] = map[string]string{"route-target-type": typ}
	}
	for key, row := range db {
		if strings.HasPrefix(key, "VXLAN_TUNNEL_MAP|") && key != mapKey && (row["vni"] == vni || row["vlan"] == vlan) {
			return nil, fmt.Errorf("VNI or VLAN already mapped")
		}
		if strings.HasPrefix(key, "VLAN_INTERFACE|"+vlan) && (key == "VLAN_INTERFACE|"+vlan || strings.HasPrefix(key, "VLAN_INTERFACE|"+vlan+"|")) {
			return nil, fmt.Errorf("L2 VNI cannot have an SVI (gateway/IRB out of scope)")
		}
		if strings.HasPrefix(key, "BGP_GLOBALS_EVPN_VNI|") && key != vniKey && row["route-distinguisher"] == s.RouteDistinguisher {
			return nil, fmt.Errorf("duplicate route distinguisher")
		}
		if strings.HasPrefix(key, "BGP_GLOBALS_EVPN_VNI_RT|") {
			parts := strings.Split(key, "|")
			if len(parts) != 5 {
				return nil, fmt.Errorf("invalid existing VNI RT identity")
			}
			if parts[3] == vni && desired[key] == nil {
				return nil, fmt.Errorf("extra existing VNI route target")
			}
			if parts[3] != vni && (slices.Contains(s.ImportRouteTargets, parts[4]) || slices.Contains(s.ExportRouteTargets, parts[4])) {
				return nil, fmt.Errorf("route target shared with another local VNI; isolation required")
			}
		}
	}
	if err := evpnExactExisting(db, desired); err != nil {
		return nil, err
	}
	if !networkSubset(db, desired) && db[evpnGlobalKey]["advertise-all-vni"] == "true" {
		for key, row := range db {
			if strings.HasPrefix(key, "BGP_NEIGHBOR|") && row["admin_status"] != "down" {
				return nil, fmt.Errorf("shutdown neighbors before initialized mapping changes")
			}
		}
	}
	p := &networkPlan{Identity: fmt.Sprintf("VLANVNI|%s|%d", s.Tunnel, s.VLANID), Desired: desired}
	p.Preflight = func(ctx context.Context, m *SonicAgent) error {
		if err := evpnInitializedMappingPreflight(ctx, m, r, s, desired); err != nil {
			return err
		}
		if err := evpnBootstrapPreflight(ctx, m, source); err != nil {
			return err
		}
		config, err := runRoutingRead(ctx, routingBGPConfig)
		if err != nil {
			return err
		}
		return evpnFRRVNI(config, db["BGP_GLOBALS|default"]["local_asn"], s, false)
	}
	p.Runtime = func(ctx context.Context, m *SonicAgent) (bool, json.RawMessage, error) {
		config, err := runRoutingRead(ctx, routingBGPConfig)
		if err != nil {
			return evpnObservation(false, "FRR read failed", nil, err)
		}
		if _, err := evpnFRRParse(config, db); err != nil {
			return evpnObservation(false, err.Error(), nil, nil)
		}
		if err := evpnFRRVNI(config, db["BGP_GLOBALS|default"]["local_asn"], s, true); err != nil {
			return evpnObservation(false, err.Error(), nil, nil)
		}
		ok, err := evpnMapASIC(ctx, qosRedisRead{m}, s.Tunnel, source, s.VLANID, s.VNI)
		if err != nil {
			return evpnObservation(false, "mapping ASIC probe failed", nil, err)
		}
		evidence, err := evpnForwardingObservation(ctx, m, []evpnMapSpec{s})
		return evpnObservation(ok, "FRR RD/RT plus tunnel-linked ASIC VLAN/VNI mapping", evidence, err)
	}
	return p, nil
}

//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func planNetworkEVPNPeer(db vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
	var s evpnPeerSpec
	if r == nil {
		return nil, fmt.Errorf("EVPN peer request required")
	}
	if err := mlagJSON(r.Spec, &s, false); err != nil {
		return nil, err
	}
	if err := routingDecode(r, "EVPNPeer", &s, "vrf address remoteASN localAddress adminState mappingRefs mappings role importRouteTargets exportRouteTargets"); err != nil {
		return nil, err
	}
	if s.VRF == "" {
		s.VRF = "default"
	}
	if s.VRF != "default" || s.RemoteASN == 0 {
		return nil, fmt.Errorf("EVPN requires default VRF and nonzero remoteASN")
	}
	address, err := routingAddress(s.Address, nil)
	if err != nil {
		return nil, err
	}
	v4 := address.Is4()
	local, err := routingAddress(s.LocalAddress, &v4)
	if err != nil || local == address {
		return nil, fmt.Errorf("distinct localAddress of peer address family required")
	}
	s.Address, s.LocalAddress = address.String(), local.String()
	if s.Role == "" {
		s.Role = "Leaf"
	}
	if s.Role != "Leaf" && s.Role != "Transit" {
		return nil, fmt.Errorf("invalid EVPN role")
	}
	if s.Role == "Leaf" && (len(s.ImportRouteTargets) != 0 || len(s.ExportRouteTargets) != 0) {
		return nil, fmt.Errorf("leaf policy derives RTs from mapping references")
	}
	if s.Role == "Transit" || len(s.MappingRefs) != 0 || len(s.Mappings) != 0 {
		return planNetworkEVPNPolicyPeer(db, r, s)
	}
	if s.AdminState == "" {
		s.AdminState = "Down"
	}
	if s.AdminState != "Down" && s.AdminState != "Up" {
		return nil, fmt.Errorf("adminState must be Down or Up")
	}
	// Fail before returning a writable plan. A VNI RT is an import selector and
	// origination attribute, not a neighbor export filter (transit routes leak).
	if s.AdminState == "Up" {
		return nil, fmt.Errorf("%s", evpnUpUnsupported)
	}
	if err := evpnSafeConfig(db); err != nil {
		return nil, err
	}
	if _, err := evpnLocalInterface(db, local); err != nil {
		return nil, err
	}
	key := "BGP_NEIGHBOR|default|" + s.Address
	neighbor := db[key]
	if neighbor["asn"] != strconv.FormatUint(uint64(s.RemoteASN), 10) || neighbor["local_addr"] != s.LocalAddress || neighbor["admin_status"] != "down" || neighbor["peer_group"] != "" {
		return nil, fmt.Errorf("matching SwitchBGPPeer must already be staged Down")
	}
	desired := vlanChangeDB{"BGP_NEIGHBOR_AF|default|" + s.Address + "|" + evpnAF: {"admin_status": "down"}}
	if err := evpnExactExisting(db, desired); err != nil {
		return nil, err
	}
	p := &networkPlan{Identity: "EVPNPeer|default|" + s.Address, Desired: desired}
	p.Preflight = func(ctx context.Context, m *SonicAgent) error {
		if err := evpnNative(ctx); err != nil {
			return err
		}
		if err := evpnOwnedPeer(m, db, key); err != nil {
			return err
		}
		if err := evpnUnderlay(ctx, db, s.LocalAddress, s.Address); err != nil {
			return err
		}
		return evpnPeerFRR(ctx, db, s)
	}
	p.Runtime = func(ctx context.Context, _ *SonicAgent) (bool, json.RawMessage, error) {
		err := evpnPeerFRR(ctx, db, s)
		if err != nil {
			return evpnObservation(false, "staged FRR neighbor/disabled EVPN AF not verified", nil, err)
		}
		return evpnObservation(true, "existing FRR neighbor shutdown and EVPN AF disabled; not session establishment", nil, nil)
	}
	return p, nil
}

func evpnRD(value string) error {
	left, right, ok := strings.Cut(value, ":")
	n, err := strconv.ParseUint(right, 10, 32)
	if !ok || err != nil || strconv.FormatUint(n, 10) != right {
		return fmt.Errorf("RD/RT must be canonical ASN:number or IPv4:number")
	}
	if a, err := netip.ParseAddr(left); err == nil {
		if !a.Is4() || a.String() != left || n > 65535 {
			return fmt.Errorf("IPv4 RD/RT requires 16-bit assigned number")
		}
		return nil
	}
	asn, err := strconv.ParseUint(left, 10, 32)
	if err != nil || asn == 0 || strconv.FormatUint(asn, 10) != left || (asn > 65535 && n > 65535) {
		return fmt.Errorf("invalid ASN RD/RT encoding")
	}
	return nil
}

func evpnRTs(values []string) ([]string, error) {
	if len(values) == 0 || len(values) > 64 {
		return nil, fmt.Errorf("1..64 explicit import/export route targets required")
	}
	result := slices.Clone(values)
	slices.Sort(result)
	for i, value := range result {
		if err := evpnRD(value); err != nil {
			return nil, err
		}
		if i > 0 && value == result[i-1] {
			return nil, fmt.Errorf("duplicate route target")
		}
	}
	return result, nil
}

func evpnLocalInterface(db vlanChangeDB, address netip.Addr) (string, error) {
	found := ""
	for key := range db {
		parts := strings.Split(key, "|")
		if len(parts) != 3 {
			continue
		}
		prefix, err := netip.ParsePrefix(parts[2])
		if err != nil || prefix.Addr() != address {
			continue
		}
		if parts[0] == "MGMT_INTERFACE" {
			return "", fmt.Errorf("management source address forbidden")
		}
		if parts[0] != "LOOPBACK_INTERFACE" && parts[0] != "INTERFACE" && parts[0] != "PORTCHANNEL_INTERFACE" {
			continue
		}
		vrf := db[parts[0]+"|"+parts[1]]["vrf_name"]
		if !evpnInterface.MatchString(parts[1]) || (vrf != "" && vrf != "default") || found != "" {
			return "", fmt.Errorf("source must be unique on a default-VRF data-plane interface")
		}
		found = parts[1]
	}
	if found == "" {
		return "", fmt.Errorf("source requires an existing configured loopback or routed data-plane address")
	}
	return found, nil
}

//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func evpnSafeConfig(db vlanChangeDB) error {
	if err := routingUnified(db); err != nil {
		return err
	}
	g := db["BGP_GLOBALS|default"]
	asn, err := strconv.ParseUint(g["local_asn"], 10, 32)
	v4 := true
	if _, e := routingAddress(g["router_id"], &v4); e != nil || err != nil || asn == 0 || g["default_ipv4_unicast"] != "false" || g["default_shutdown"] != "false" {
		return fmt.Errorf("existing SwitchBGP with routerID and safe defaults required")
	}
	for key, row := range db {
		if strings.HasPrefix(key, "VXLAN_VRF_MAP|") || strings.HasPrefix(key, "MCLAG_") || strings.HasPrefix(key, "EVPN_ETHERNET_SEGMENT|") || (strings.HasPrefix(key, "VRF|") && row["vni"] != "") {
			return fmt.Errorf("MLAG/ESI/L3VNI coexistence is outside L2-only scope")
		}
		if strings.HasPrefix(key, "VXLAN_TUNNEL|") && (len(row) != 1 || row["src_ip"] == "") {
			return fmt.Errorf("only source-only VXLAN tunnels supported")
		}
		if strings.HasPrefix(key, "BGP_PEER_GROUP|") || strings.HasPrefix(key, "BGP_GLOBALS_LISTEN_PREFIX|") {
			return fmt.Errorf("dynamic/inherited BGP peers are unsupported")
		}
		if strings.HasPrefix(key, "BGP_NEIGHBOR|") && row["admin_status"] != "down" {
			parts := strings.Split(key, "|")
			if len(parts) != 3 || parts[1] != "default" || row["admin_status"] != "up" {
				return fmt.Errorf("unsupported live BGP neighbor")
			}
			if _, err := evpnConfiguredPeerPolicy(db, parts[2]); err != nil {
				return fmt.Errorf("active neighbor requires EVPN policy: %w", err)
			}
		}
		if strings.HasPrefix(key, "BGP_NEIGHBOR_AF|") && strings.HasSuffix(strings.ToLower(key), "|"+evpnAF) && (len(row) != 1 || row["admin_status"] != "down") {
			parts := strings.Split(key, "|")
			if len(parts) != 4 || parts[1] != "default" || parts[3] != evpnAF {
				return fmt.Errorf("invalid EVPN AF key")
			}
			if _, err := evpnConfiguredPeerPolicy(db, parts[2]); err != nil {
				return err
			}
		}
		if strings.HasPrefix(key, "BGP_GLOBALS_EVPN_RT|") || (strings.HasPrefix(key, "BGP_GLOBALS_AF|") && strings.HasSuffix(strings.ToLower(key), "|"+evpnAF) && len(row) != 0) {
			if key != evpnGlobalKey || !evpnGlobalConfigValid(row) {
				return fmt.Errorf("unsupported global EVPN advertisement policy")
			}
		}
	}
	return nil
}

func evpnExactExisting(db, desired vlanChangeDB) error {
	for key, want := range desired {
		for field, value := range db[key] {
			if want[field] != value {
				return fmt.Errorf("conflicting or unsupported existing field on %s", key)
			}
		}
	}
	return nil
}

// Called with the engine's existing network journal lock held. Do not re-lock.
func evpnOwnedPeer(m *SonicAgent, db vlanChangeDB, key string) error {
	root, err := os.OpenRoot(m.networkJournalDir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	state, err := loadNetworkJournal(&vlanAuthorityJournal{root: root})
	if err != nil {
		return err
	}
	r := state.Records["BGPPeer|"+strings.TrimPrefix(key, "BGP_NEIGHBOR|")]
	if r == nil || r.Kind != "BGPPeer" || r.OwnerID == "" || r.Pending != nil || !networkSubset(db, r.Fields) {
		return fmt.Errorf("durably staged operator-owned SwitchBGPPeer required")
	}
	want := map[string]string{"asn": db[key]["asn"], "local_addr": db[key]["local_addr"], "admin_status": db[key]["admin_status"]}
	if !maps.Equal(r.Owned[key], want) {
		return fmt.Errorf("SwitchBGPPeer must own neighbor ASN/source/shutdown fields")
	}
	return nil
}

func evpnObservation(ok bool, reason string, evidence map[string]any, err error) (bool, json.RawMessage, error) {
	if evidence == nil {
		evidence = map[string]any{}
	}
	evidence["applied"], evidence["reason"] = ok && err == nil, reason
	raw, _ := json.Marshal(evidence)
	return ok && err == nil, raw, err
}
