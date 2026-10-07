// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"bytes"
	"context"
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

// SONiC 202511: sonic-portchannel.yang, sonic-vrf.yang and sonic-static-route.yang;
// consumers: sonic-swss 7917e3d7c70dfdde6a34c6f5886118dab316f187 cfgmgr/
// {teammgr,intfmgr,vrfmgr}.cpp and installed bgpcfgd/managers_static_rt.py.
// The planners own only the emitted fields. The shared writer arbitrates field
// conflicts/ownership and merges them; none of these functions mutate snapshots.
var (
	lagL3PortChannelName = regexp.MustCompile(`^PortChannel(0|[1-9][0-9]{0,3})$`)
	lagL3VRFName         = regexp.MustCompile(`^Vrf[a-zA-Z0-9_-]+$`)
)

// Deliberately bounded canonical subset of SONiC's interface_name grammar.
func lagL3LoopbackManaged(name string) bool {
	n, err := strconv.ParseUint(strings.TrimPrefix(name, "Loopback"), 10, 16)
	return err == nil && n <= 4095 && name == "Loopback"+strconv.FormatUint(n, 10)
}

type lagL3Selectors struct {
	SwitchRef struct {
		Name string `json:"name"`
	} `json:"switchRef,omitempty"`
	ManagementPolicy string `json:"managementPolicy,omitempty"`
}

type lagL3PortChannelSpec struct {
	lagL3Selectors
	Name       string   `json:"name"`
	Members    []string `json:"members"`
	MinLinks   *uint32  `json:"minLinks,omitempty"`
	LACPMode   string   `json:"lacpMode,omitempty"`
	FastRate   bool     `json:"fastRate,omitempty"`
	MTU        *uint32  `json:"mtu,omitempty"`
	AdminState string   `json:"adminState,omitempty"`
}

type lagL3VRFSpec struct {
	lagL3Selectors
	Name string `json:"name"`
}

type lagL3InterfaceSpec struct {
	lagL3Selectors
	Name      string   `json:"name"`
	VRF       string   `json:"vrf,omitempty"`
	Addresses []string `json:"addresses"`
}

type lagL3NextHop struct {
	Address       string  `json:"address"`
	InterfaceName string  `json:"interfaceName,omitempty"`
	Distance      *uint32 `json:"distance,omitempty"`
}

type lagL3RouteSpec struct {
	lagL3Selectors
	VRF      string         `json:"vrf,omitempty"`
	Prefix   string         `json:"prefix"`
	NextHops []lagL3NextHop `json:"nextHops"`
}

// Reject duplicate keys and nulls as well as unknown fields. encoding/json alone
// accepts duplicate fields (last wins), case-insensitive spellings and null scalars.
func lagL3Decode(r *agent.NetworkRequest, kind string, out any) error {
	if err := agent.ValidateNetworkRequest(r, false); err != nil {
		return err
	}
	if r.Kind != kind {
		return fmt.Errorf("expected %s request", kind)
	}
	d := json.NewDecoder(bytes.NewReader(r.Spec))
	if err := lagL3JSONValue(d); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("trailing spec JSON")
	}
	d = json.NewDecoder(bytes.NewReader(r.Spec))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return fmt.Errorf("invalid %s spec: %w", kind, err)
	}
	return nil
}

func lagL3JSONValue(d *json.Decoder) error {
	tok, err := d.Token()
	if err != nil {
		return err
	}
	if tok == nil {
		return fmt.Errorf("null spec fields are unsupported")
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	for d.More() {
		if delim == '{' {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || name == "" || seen[name] {
				return fmt.Errorf("invalid or duplicate JSON field")
			}
			// Exact API spellings only, including the two ignored selectors.
			switch name {
			case "switchRef", "name", "managementPolicy", "members", "minLinks", "lacpMode", "fastRate", "mtu", "adminState", "vrf", "addresses", "prefix", "nextHops", "address", "interfaceName", "distance":
			default:
				return fmt.Errorf("unknown spec field %q", name)
			}
			seen[name] = true
		}
		if err := lagL3JSONValue(d); err != nil {
			return err
		}
	}
	_, err = d.Token()
	return err
}

func vlanMemberNameValid(name string) bool {
	_, ethernet := ethernetNumber(name)
	return ethernet || lagL3PortChannelName.MatchString(name)
}

func lagL3InterfaceTable(name string) string {
	if lagL3LoopbackManaged(name) {
		return "LOOPBACK_INTERFACE"
	}
	if _, ok := ethernetNumber(name); ok {
		return "INTERFACE"
	}
	if lagL3PortChannelName.MatchString(name) {
		return "PORTCHANNEL_INTERFACE"
	}
	if strings.HasPrefix(name, "Vlan") {
		n, err := strconv.ParseUint(strings.TrimPrefix(name, "Vlan"), 10, 16)
		if err == nil && n > 0 && n < 4095 && name == fmt.Sprintf("Vlan%d", n) {
			return "VLAN_INTERFACE"
		}
	}
	return ""
}

func lagL3VRF(db vlanChangeDB, vrf string) (string, error) {
	if vrf == "" || vrf == "default" {
		return "default", nil
	}
	if len(vrf) > 15 || !lagL3VRFName.MatchString(vrf) {
		return "", fmt.Errorf("invalid VRF; mgmt and noncanonical names are unsupported")
	}
	if len(db["VRF|"+vrf]) == 0 {
		return "", fmt.Errorf("VRF %s does not exist", vrf)
	}
	return vrf, nil
}

func lagL3InterfaceExists(db vlanChangeDB, name string) error {
	table := map[string]string{"INTERFACE": "PORT", "PORTCHANNEL_INTERFACE": "PORTCHANNEL", "VLAN_INTERFACE": "VLAN"}[lagL3InterfaceTable(name)]
	if table == "" || len(db[table+"|"+name]) == 0 {
		return fmt.Errorf("canonical data interface %s does not exist", name)
	}
	if table == "VLAN" && db[table+"|"+name]["vlanid"] != strings.TrimPrefix(name, "Vlan") {
		return fmt.Errorf("invalid VLAN identity")
	}
	return nil
}

func lagL3Routed(db vlanChangeDB, name string) bool {
	key := lagL3InterfaceTable(name) + "|" + name
	for k := range db {
		if k == key || strings.HasPrefix(k, key+"|") {
			return true
		}
	}
	return false
}

// A narrow grammar for dependency absence, not permission to rewrite these rows.
// Unsupported native extensions remain intact and block unsafe topology changes.
//
//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func lagL3DependencyGrammar(key string, fields map[string]string) error {
	parts := strings.Split(key, "|")
	if len(parts) < 2 || len(fields) == 0 {
		return fmt.Errorf("malformed network dependency")
	}
	table, name := parts[0], parts[1]
	switch table {
	case "PORTCHANNEL":
		if len(parts) != 2 || !lagL3PortChannelName.MatchString(name) {
			return fmt.Errorf("noncanonical LAG dependency")
		}
		for field, value := range fields {
			switch field {
			case "admin_status":
				if value != "up" && value != "down" {
					return fmt.Errorf("invalid LAG admin state")
				}
			case "min_links", "mtu":
				n, err := strconv.ParseUint(value, 10, 16)
				if err != nil || n == 0 || n > 9216 {
					return fmt.Errorf("invalid LAG numeric field")
				}
			case "fast_rate", "fallback":
				if value != "true" && value != "false" {
					return fmt.Errorf("invalid LAG boolean")
				}
			case "lacp_key":
				if value != "auto" {
					n, err := strconv.ParseUint(value, 10, 16)
					if err != nil || n == 0 {
						return fmt.Errorf("invalid LACP key")
					}
				}
			case "description":
			default:
				return fmt.Errorf("unsupported LAG dependency field %s", field)
			}
		}
	case "PORTCHANNEL_MEMBER":
		if len(parts) != 3 || !lagL3PortChannelName.MatchString(name) {
			return fmt.Errorf("invalid LAG member dependency")
		}
		if _, ok := ethernetNumber(parts[2]); !ok || len(fields) != 1 || fields["NULL"] != "NULL" {
			return fmt.Errorf("invalid LAG member dependency")
		}
	case "INTERFACE", "PORTCHANNEL_INTERFACE", "VLAN_INTERFACE", "LOOPBACK_INTERFACE":
		if lagL3InterfaceTable(name) != table || (len(parts) != 2 && len(parts) != 3) {
			return fmt.Errorf("invalid L3 dependency identity")
		}
		if len(parts) == 3 {
			p, err := netip.ParsePrefix(parts[2])
			if err != nil || p.String() != parts[2] || p.Addr().Is4In6() {
				return fmt.Errorf("invalid L3 dependency prefix")
			}
			if len(fields) != 1 || fields["NULL"] != "NULL" {
				return fmt.Errorf("unknown L3 address fields")
			}
		} else {
			for field, value := range fields {
				switch field {
				case "NULL":
					if value != "NULL" {
						return fmt.Errorf("invalid placeholder")
					}
				case "vrf_name":
					if len(value) > 15 || !lagL3VRFName.MatchString(value) {
						return fmt.Errorf("invalid VRF dependency")
					}
				default:
					return fmt.Errorf("unsupported L3 dependency field %s", field)
				}
			}
		}
	case "VRF":
		if len(parts) != 2 || len(name) > 15 || !lagL3VRFName.MatchString(name) {
			return fmt.Errorf("invalid VRF dependency")
		}
		for field, value := range fields {
			if field != "NULL" || value != "NULL" {
				return fmt.Errorf("unsupported VRF dependency field")
			}
		}
	default:
		return fmt.Errorf("unsupported network dependency table")
	}
	return nil
}

// Validate LAG members including existing, unmanaged members. Checking only the
// requested additions would miss an incompatible member retained by additive merge.
func lagL3Members(db vlanChangeDB, name string) ([]string, error) {
	members := []string{}
	for key, fields := range db {
		if !strings.HasPrefix(key, "PORTCHANNEL_MEMBER|") {
			continue
		}
		parts := strings.Split(key, "|")
		if len(parts) != 3 || !lagL3PortChannelName.MatchString(parts[1]) {
			return nil, fmt.Errorf("unknown LAG member grammar")
		}
		if _, ok := ethernetNumber(parts[2]); !ok {
			return nil, fmt.Errorf("noncanonical LAG member")
		}
		if len(fields) != 1 || fields["NULL"] != "NULL" {
			return nil, fmt.Errorf("unsupported LAG member fields")
		}
		if parts[1] == name {
			members = append(members, parts[2])
		}
	}
	sort.Strings(members)
	return members, nil
}

//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func lagL3PortFree(db vlanChangeDB, name, ownLAG string) error {
	if err := lagL3InterfaceExists(db, name); err != nil {
		return err
	}
	ref := regexp.MustCompile(`(^|[^a-zA-Z0-9])` + regexp.QuoteMeta(name) + `([^a-zA-Z0-9]|$)`)
	for key, fields := range db {
		table, _, _ := strings.Cut(key, "|")
		switch table {
		case "PREFIX_SET", "PREFIX", "DHCPV4_RELAY", "DHCP_RELAY":
			if err := lagL3CrossFeatureGrammar(db, key, fields); err != nil {
				return err
			}
			if table == "PREFIX_SET" || table == "PREFIX" {
				continue
			}
		case "PORTCHANNEL", "PORTCHANNEL_MEMBER", "INTERFACE", "PORTCHANNEL_INTERFACE", "VLAN_INTERFACE", "LOOPBACK_INTERFACE", "VRF":
			if err := lagL3DependencyGrammar(key, fields); err != nil {
				return err
			}
		case "VLAN", "VLAN_MEMBER":
			parts := strings.Split(key, "|")
			if len(parts) < 2 || lagL3InterfaceTable(parts[1]) != "VLAN_INTERFACE" {
				return fmt.Errorf("unknown VLAN dependency identity")
			}
			if table == "VLAN" {
				if len(parts) != 2 || fields["vlanid"] != strings.TrimPrefix(parts[1], "Vlan") {
					return fmt.Errorf("invalid VLAN dependency")
				}
				for field := range fields {
					if field != "vlanid" && field != "description" && field != "dhcp_servers@" {
						return fmt.Errorf("unknown or legacy VLAN dependency field")
					}
				}
			} else if len(parts) != 3 || !vlanMemberNameValid(parts[2]) || len(fields) != 1 || (fields["tagging_mode"] != "tagged" && fields["tagging_mode"] != "untagged") {
				return fmt.Errorf("unknown VLAN membership selector")
			}
		}
		if key == "PORT|"+name || key == "PORTCHANNEL|"+name {
			continue
		}
		if table == "BREAKOUT_CFG" {
			_, identity, _ := strings.Cut(key, "|")
			if _, valid := ethernetNumber(identity); !valid || len(fields) != 1 || !vlanAuthorityBreakoutMode.MatchString(fields["brkout_mode"]) {
				return fmt.Errorf("unknown breakout grammar")
			}
			continue
		}
		if ownLAG != "" && key == "PORTCHANNEL_MEMBER|"+ownLAG+"|"+name {
			continue
		}
		if ref.MatchString(key) {
			return fmt.Errorf("interface %s dependency in %s", name, key)
		}
		for f, v := range fields {
			if ref.MatchString(f) || ref.MatchString(v) {
				return fmt.Errorf("interface %s dependency in %s", name, key)
			}
		}
		switch table {
		case "PORT", "PORTCHANNEL", "PORTCHANNEL_MEMBER", "INTERFACE", "PORTCHANNEL_INTERFACE", "VLAN_INTERFACE", "LOOPBACK_INTERFACE", "VLAN", "VLAN_MEMBER", "VRF", "STATIC_ROUTE", "DHCPV4_RELAY", "DHCP_RELAY", "CONFIG_DB_INITIALIZED", "DEVICE_METADATA", "AUTO_TECHSUPPORT", "AUTO_TECHSUPPORT_FEATURE", "BANNER_MESSAGE", "BGP_DEVICE_GLOBAL", "BGP_NEIGHBOR", "BGP_GLOBALS", "BGP_GLOBALS_AF", "BGP_GLOBALS_AF_NETWORK", "BGP_NEIGHBOR_AF", "CRM", "FEATURE", "FLEX_COUNTER_TABLE", "KDUMP", "LOGGER", "MGMT_INTERFACE", "MGMT_PORT", "MGMT_VRF_CONFIG", "NTP", "NTP_SERVER", "PASSW_HARDENING", "SNMP", "SNMP_COMMUNITY", "SNMP_LOCATION", "SNMP_CONTACT", "SYSLOG_CONFIG", "SYSLOG_CONFIG_FEATURE", "SYSLOG_SERVER", "SYSTEM_DEFAULTS", "VERSIONS", "TACPLUS", "TACPLUS_SERVER", "AAA", "DNS_NAMESERVER":
		default:
			return fmt.Errorf("unsupported dependency table %s; inspect before assigning %s", table, name)
		}
	}
	return nil
}

func vlanLAGMemberSafe(db vlanChangeDB, name string) error {
	if err := lagL3InterfaceExists(db, name); err != nil {
		return err
	}
	if lagL3Routed(db, name) {
		return fmt.Errorf("VLAN member %s is routed", name)
	}
	if !lagL3PortChannelName.MatchString(name) {
		return nil
	}
	members, err := lagL3Members(db, name)
	if err != nil {
		return err
	}
	if len(members) == 0 {
		return fmt.Errorf("VLAN LAG has no members")
	}
	for _, member := range members {
		if err := lagL3PortFree(db, member, name); err != nil {
			return err
		}
	}
	return nil
}

//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func planNetworkPortChannel(db vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
	var spec lagL3PortChannelSpec
	if err := lagL3Decode(r, "PortChannel", &spec); err != nil {
		return nil, err
	}
	if !lagL3PortChannelName.MatchString(spec.Name) {
		return nil, fmt.Errorf("canonical PortChannel0..9999 required")
	}
	if spec.LACPMode != "" && spec.LACPMode != "active" {
		return nil, fmt.Errorf("unsupported lacpMode: SONiC teammgr hardcodes active; passive has no CONFIG_DB consumer")
	}
	minLinks, mtu := uint32(1), uint32(9100)
	if spec.MinLinks != nil {
		minLinks = *spec.MinLinks
	}
	if spec.MTU != nil {
		mtu = *spec.MTU
	}
	if spec.AdminState == "" {
		spec.AdminState = "Up"
	}
	if spec.AdminState != "Up" && spec.AdminState != "Down" {
		return nil, fmt.Errorf("adminState must be Up or Down")
	}
	if minLinks < 1 || minLinks > 1024 || mtu < 1280 || mtu > 9216 || len(spec.Members) == 0 || len(spec.Members) > 1024 {
		return nil, fmt.Errorf("invalid minLinks, MTU (1280..9216), or member count")
	}
	want := map[string]string{"admin_status": strings.ToLower(spec.AdminState), "mtu": fmt.Sprint(mtu), "min_links": fmt.Sprint(minLinks), "fast_rate": strconv.FormatBool(spec.FastRate)}
	if old := db["PORTCHANNEL|"+spec.Name]; old != nil {
		// teammgr only calls addLag once. Rewriting these fields later is inert.
		for _, field := range []string{"min_links", "fast_rate"} {
			value := old[field]
			if field == "fast_rate" && value == "" {
				value = "false"
			}
			if value != want[field] {
				return nil, fmt.Errorf("existing LAG %s is creation-only; recreate outside additive scope", field)
			}
		}
	}
	members, err := lagL3Members(db, spec.Name)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	desired := vlanChangeDB{"PORTCHANNEL|" + spec.Name: want}
	for _, member := range spec.Members {
		if _, ok := ethernetNumber(member); !ok || seen[member] {
			return nil, fmt.Errorf("unique canonical Ethernet members required")
		}
		seen[member] = true
		desired["PORTCHANNEL_MEMBER|"+spec.Name+"|"+member] = map[string]string{"NULL": "NULL"}
	}
	for _, member := range members {
		seen[member] = true
	}
	if int(minLinks) > len(seen) {
		return nil, fmt.Errorf("minLinks exceeds resulting member count")
	}
	speed := ""
	for member := range seen {
		if err := lagL3PortFree(db, member, spec.Name); err != nil {
			return nil, err
		}
		fields := db["PORT|"+member]
		n, err := strconv.ParseUint(fields["speed"], 10, 32)
		if err != nil || n == 0 || (speed != "" && speed != fields["speed"]) {
			return nil, fmt.Errorf("LAG members require known equal speeds")
		}
		speed = fields["speed"]
		portMTU := fields["mtu"]
		if portMTU == "" {
			portMTU = "9100"
		}
		if portMTU != want["mtu"] {
			return nil, fmt.Errorf("member MTU differs from LAG; normalize explicitly before assignment")
		}
	}
	return &networkPlan{Identity: "PortChannel|" + spec.Name, Desired: desired, Runtime: func(ctx context.Context, m *SonicAgent) (bool, json.RawMessage, error) {
		return lagL3PortChannelRuntime(ctx, spec.Name, spec.Members, want, m.lagL3ReadApp, m.getLinkByName, lagL3Run)
	}}, nil
}

func planNetworkVRF(db vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
	var spec lagL3VRFSpec
	if err := lagL3Decode(r, "VRF", &spec); err != nil {
		return nil, err
	}
	if len(spec.Name) > 15 || !lagL3VRFName.MatchString(spec.Name) {
		return nil, fmt.Errorf("VRF must be VrfNAME, at most 15 bytes; default/mgmt are reserved")
	}
	// The NULL placeholder creates an otherwise empty native hash. Do not own
	// fallback or vni: those unrelated fields must survive reconciliation.
	desired := vlanChangeDB{"VRF|" + spec.Name: {"NULL": "NULL"}}
	return &networkPlan{Identity: "VRF|" + spec.Name, Desired: desired, Runtime: func(ctx context.Context, m *SonicAgent) (bool, json.RawMessage, error) {
		return lagL3VRFRuntime(ctx, spec.Name, m.lagL3ReadApp, m.getLinkByName)
	}}, nil
}

//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func planNetworkL3Interface(db vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
	var spec lagL3InterfaceSpec
	if err := lagL3Decode(r, "L3Interface", &spec); err != nil {
		return nil, err
	}
	if !lagL3LoopbackManaged(spec.Name) {
		if err := lagL3InterfaceExists(db, spec.Name); err != nil {
			return nil, err
		}
	}
	vrf, err := lagL3VRF(db, spec.VRF)
	if err != nil {
		return nil, err
	}
	if len(spec.Addresses) == 0 || len(spec.Addresses) > 256 {
		return nil, fmt.Errorf("1..256 addresses required; removal is outside additive scope")
	}
	table := lagL3InterfaceTable(spec.Name)
	if table == "VLAN_INTERFACE" {
		// Enforce the L2-only invariant in both creation orders. This runs on
		// pending-request replanning too, before either pre/post-state recovery.
		for key, fields := range db {
			if strings.HasPrefix(key, "VXLAN_TUNNEL_MAP|") && fields["vlan"] == spec.Name {
				return nil, fmt.Errorf("SVI conflicts with existing L2 VXLAN VLAN mapping; gateway/IRB is unsupported")
			}
		}
	}
	key := table + "|" + spec.Name
	old := db[key]
	oldVRF := old["vrf_name"]
	if oldVRF == "" {
		oldVRF = "default"
	}
	if old["vnet_name"] != "" {
		return nil, fmt.Errorf("VNET binding is unsupported")
	}
	if lagL3Routed(db, spec.Name) && oldVRF != vrf {
		return nil, fmt.Errorf("VRF binding is immutable")
	}
	// Remove only this interface's known L3 rows from the dependency view.
	view := vlanChangeDB{}
	for k, f := range db {
		// Adding addresses to an already routed interface does not invalidate
		// routes consuming it. Initial L2-to-L3 conversion remains fail-closed.
		if strings.HasPrefix(k, "STATIC_ROUTE|") && lagL3Routed(db, spec.Name) {
			continue
		}
		if k != key && !strings.HasPrefix(k, key+"|") {
			view[k] = f
		}
	}
	if table != "VLAN_INTERFACE" && table != "LOOPBACK_INTERFACE" {
		if table == "PORTCHANNEL_INTERFACE" {
			members, err := lagL3Members(db, spec.Name)
			if err != nil {
				return nil, err
			}
			for _, member := range members {
				if err := lagL3PortFree(db, member, spec.Name); err != nil {
					return nil, err
				}
				delete(view, "PORTCHANNEL_MEMBER|"+spec.Name+"|"+member)
			}
		}
		if err := lagL3PortFree(view, spec.Name, ""); err != nil {
			return nil, err
		}
	}
	base := map[string]string{"NULL": "NULL"}
	if vrf != "default" {
		base = map[string]string{"vrf_name": vrf}
	}
	desired := vlanChangeDB{key: base}
	seen := map[netip.Addr]bool{}
	addresses := []string{}
	for _, address := range spec.Addresses {
		p, err := netip.ParsePrefix(address)
		if err != nil || !p.Addr().IsGlobalUnicast() || p.Addr().Is4In6() || seen[p.Addr()] {
			return nil, fmt.Errorf("unique unicast interface CIDRs required")
		}
		if table == "LOOPBACK_INTERFACE" && p.String() != address {
			return nil, fmt.Errorf("canonical loopback CIDRs required")
		}
		seen[p.Addr()] = true
		// Prefix.String retains host bits; Masked is only for route networks.
		address = p.String()
		for k := range db {
			parts := strings.Split(k, "|")
			if len(parts) != 3 || lagL3InterfaceTable(parts[1]) != parts[0] {
				continue
			}
			existing, e := netip.ParsePrefix(parts[2])
			if e != nil {
				return nil, fmt.Errorf("malformed existing interface prefix")
			}
			binding := db[parts[0]+"|"+parts[1]]["vrf_name"]
			if binding == "" {
				binding = "default"
			}
			if binding == vrf && existing.Addr() == p.Addr() && (parts[1] != spec.Name || existing != p || parts[2] != address) {
				return nil, fmt.Errorf("address already assigned with a conflicting interface/prefix or spelling")
			}
		}
		desired[key+"|"+address] = map[string]string{"NULL": "NULL"}
		addresses = append(addresses, address)
	}
	plan := &networkPlan{Identity: "L3Interface|" + spec.Name, Desired: desired, Runtime: func(ctx context.Context, m *SonicAgent) (bool, json.RawMessage, error) {
		return lagL3InterfaceRuntime(ctx, spec.Name, vrf, addresses, m.lagL3ReadApp, m.getLinkByName)
	}}
	if table == "LOOPBACK_INTERFACE" {
		plan.Persisted = networkFieldPersistence(desired)
	}
	return plan, nil
}

//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func planNetworkStaticRoute(db vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
	var spec lagL3RouteSpec
	if err := lagL3Decode(r, "StaticRoute", &spec); err != nil {
		return nil, err
	}
	vrf, err := lagL3VRF(db, spec.VRF)
	if err != nil {
		return nil, err
	}
	prefix, err := netip.ParsePrefix(spec.Prefix)
	if err != nil || prefix.Addr().Is4In6() || prefix != prefix.Masked() || prefix.String() != spec.Prefix {
		return nil, fmt.Errorf("canonical IPv4/IPv6 route network required")
	}
	if len(spec.NextHops) == 0 || len(spec.NextHops) > 64 {
		return nil, fmt.Errorf("1..64 next hops required")
	}
	mode := db["DEVICE_METADATA|localhost"]["docker_routing_config_mode"]
	framework := db["DEVICE_METADATA|localhost"]["frr_mgmt_framework_config"]
	if framework != "" && framework != "false" && framework != "true" {
		return nil, fmt.Errorf("invalid frr_mgmt_framework_config")
	}
	unified := framework == "true"
	if mode != "" && mode != "separated" && !(unified && mode == "unified") {
		return nil, fmt.Errorf("unsupported routing config mode %q", mode)
	}
	if unified {
		// frrcfgd does not implement advertise or install the traditional tag-2
		// filter. Refuse existing redistribution rather than silently advertising
		// this route. Explicit BGP network statements remain separately owned.
		for key, fields := range db {
			if strings.HasPrefix(key, "ROUTE_REDISTRIBUTE|"+vrf+"|") {
				return nil, fmt.Errorf("existing redistribution conflicts with non-advertising static route")
			}
			if strings.HasPrefix(key, "BGP_GLOBALS_AF|"+vrf+"|") {
				for field, value := range fields {
					if strings.HasPrefix(field, "redistribute") && value != "false" && value != "" {
						return nil, fmt.Errorf("existing redistribution conflicts with static route")
					}
				}
			}
		}
	}
	key := "STATIC_ROUTE|" + vrf + "|" + spec.Prefix
	if vrf == "default" && db["STATIC_ROUTE|"+spec.Prefix] != nil {
		return nil, fmt.Errorf("legacy default STATIC_ROUTE key already claims this prefix")
	}
	// These change the semantics of the parallel next-hop vectors. Do not add
	// new vectors beside unmanaged policy that might redirect or advertise them.
	for field, value := range db[key] {
		// The unified startup template counts every field's comma-separated
		// values, including unknown ones. Reject inert/extended fields rather
		// than emit a route that works dynamically but disappears on restart.
		if unified && field != "nexthop" && field != "ifname" && field != "distance" {
			return nil, fmt.Errorf("unsupported existing unified route field %s", field)
		}
		switch field {
		case "nexthop", "ifname", "distance", "NULL":
		case "advertise", "bfd", "blackhole":
			if value != "false" {
				return nil, fmt.Errorf("unsupported existing route %s", field)
			}
		default:
			return nil, fmt.Errorf("unsupported existing route field %s", field)
		}
	}
	seen := map[string]bool{}
	for i := range spec.NextHops {
		h := &spec.NextHops[i]
		ip, err := netip.ParseAddr(h.Address)
		if err != nil || ip.Is4In6() || ip.Zone() != "" || ip.Is4() != prefix.Addr().Is4() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() {
			return nil, fmt.Errorf("unicast next-hop address must match route family")
		}
		if ip.IsLinkLocalUnicast() && h.InterfaceName == "" {
			return nil, fmt.Errorf("link-local next hop requires interfaceName")
		}
		h.Address = ip.String()
		if h.Distance == nil {
			n := uint32(1)
			h.Distance = &n
		}
		if *h.Distance < 1 || *h.Distance > 255 {
			return nil, fmt.Errorf("distance must be 1..255")
		}
		if h.InterfaceName != "" {
			if err := lagL3InterfaceExists(db, h.InterfaceName); err != nil {
				return nil, err
			}
			base := db[lagL3InterfaceTable(h.InterfaceName)+"|"+h.InterfaceName]
			bound := base["vrf_name"]
			if bound == "" {
				bound = "default"
			}
			if base == nil || bound != vrf || base["vnet_name"] != "" {
				return nil, fmt.Errorf("next-hop interface must have an L3 binding in route VRF")
			}
			family := false
			for k := range db {
				if strings.HasPrefix(k, lagL3InterfaceTable(h.InterfaceName)+"|"+h.InterfaceName+"|") {
					_, addr, _ := strings.Cut(strings.TrimPrefix(k, lagL3InterfaceTable(h.InterfaceName)+"|"), "|")
					p, e := netip.ParsePrefix(addr)
					if e == nil && p.Addr().Is4() == ip.Is4() {
						family = true
					}
				}
			}
			if !family {
				return nil, fmt.Errorf("next-hop interface lacks route-family address")
			}
		}
		identity := h.Address + "|" + h.InterfaceName
		if seen[identity] {
			return nil, fmt.Errorf("duplicate next hop")
		}
		seen[identity] = true
	}
	sort.Slice(spec.NextHops, func(i, j int) bool {
		a, b := spec.NextHops[i], spec.NextHops[j]
		return a.Address+"|"+a.InterfaceName < b.Address+"|"+b.InterfaceName
	})
	ips, interfaces, distances := []string{}, []string{}, []string{}
	hasInterface := false
	for _, h := range spec.NextHops {
		ips = append(ips, h.Address)
		interfaces = append(interfaces, h.InterfaceName)
		distances = append(distances, fmt.Sprint(*h.Distance))
		hasInterface = hasInterface || h.InterfaceName != ""
	}
	fields := map[string]string{"nexthop": strings.Join(ips, ","), "distance": strings.Join(distances, ","), "advertise": "false"}
	expectedTag := uint32(2)
	if unified {
		// Installed frrcfgd.py static_route_map/hdl_static_route and
		// /usr/local/sonic/frrcfgd/staticd.db.conf.j2 consume these same vectors.
		// No tag configured means tag 0; advertise is NOT a unified field.
		delete(fields, "advertise")
		expectedTag = 0
	}
	if hasInterface {
		fields["ifname"] = strings.Join(interfaces, ",")
	} else if db[key]["ifname"] != "" {
		return nil, fmt.Errorf("existing route has interface constraints; removal is outside additive scope")
	}
	// Route vector changes can delete old next hops inside bgpcfgd. They are not
	// safe scalar updates, even for the same durable owner.
	for _, field := range []string{"nexthop", "ifname", "distance"} {
		if old, ok := db[key][field]; ok && old != fields[field] {
			return nil, fmt.Errorf("existing route %s differs; next-hop replacement is outside additive scope", field)
		}
	}
	return &networkPlan{Identity: "StaticRoute|" + vrf + "|" + spec.Prefix, Desired: vlanChangeDB{key: fields}, Runtime: func(ctx context.Context, m *SonicAgent) (bool, json.RawMessage, error) {
		return lagL3RouteRuntime(ctx, vrf, spec.Prefix, spec.NextHops, expectedTag, lagL3Run)
	}}, nil
}
