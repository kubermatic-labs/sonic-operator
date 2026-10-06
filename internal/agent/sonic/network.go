// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	agenterrors "github.com/ironcore-dev/sonic-operator/internal/agent/errors"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

type networkPlan struct {
	Identity string
	Desired  vlanChangeDB
	// Runtime is read-only. false,nil means nonconvergence; errors propagate
	// with partial configuration/persistence evidence. Activation recovery needs
	// exact applied-runtime proof, not merely matching CONFIG_DB.
	Runtime func(context.Context, *SonicAgent) (bool, json.RawMessage, error)
	// Preflight is read-only and repeatable; called before CAS (also on recovery).
	Preflight func(context.Context, *SonicAgent) error
	// Activate is an allowlisted planner closure, after CAS and durable dispatch.
	// Keep it present in post-state plans; it is never replayed after Dispatched.
	Activate func(context.Context, *SonicAgent) error
}

var _ agent.NetworkAgent = (*SonicAgent)(nil)
var _ agent.NetworkRecoveryAgent = (*SonicAgent)(nil)

// Identity parsing must not depend on mutable desired fields or live dependencies:
// deletion and pending recovery still work after spec edits or dependency drift.
func networkIdentity(r *agent.NetworkRequest) (string, error) {
	d := json.NewDecoder(bytes.NewReader(r.Spec))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return "", fmt.Errorf("network spec must be an object")
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return "", err
		}
		key, ok := token.(string)
		if !ok {
			return "", fmt.Errorf("invalid spec field")
		}
		if _, exists := fields[key]; exists {
			return "", fmt.Errorf("duplicate spec field")
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return "", err
		}
		fields[key] = value
	}
	if _, err := d.Token(); err != nil {
		return "", err
	}
	if _, err := d.Token(); err != io.EOF {
		return "", fmt.Errorf("trailing spec JSON")
	}
	for _, key := range []string{"name", "vrf", "address", "prefix", "policy", "type", "interfaceName", "tunnel"} {
		if raw, ok := fields[key]; ok {
			var value string
			if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &value) != nil {
				return "", fmt.Errorf("invalid network identity field %s", key)
			}
		}
	}
	text := func(key string) string { var value string; _ = json.Unmarshal(fields[key], &value); return value }
	name, vrf := text("name"), text("vrf")
	if vrf == "" {
		vrf = "default"
	}
	validVRF := func(s string) bool { return regexp.MustCompile(`^Vrf[A-Za-z0-9_-]{1,12}$`).MatchString(s) }
	if vrf != "default" && !validVRF(vrf) {
		return "", fmt.Errorf("invalid VRF identity")
	}
	canonicalNumber := func(s, prefix string, max uint64) bool {
		n, e := strconv.ParseUint(strings.TrimPrefix(s, prefix), 10, 32)
		return e == nil && n <= max && s == prefix+strconv.FormatUint(n, 10)
	}
	switch r.Kind {
	case "EVPN":
		return "EVPN|default", nil
	case "MLAG":
		var id uint32
		if json.Unmarshal(fields["domainID"], &id) == nil && id > 0 && id <= 4095 {
			return r.Kind + "|" + strconv.FormatUint(uint64(id), 10), nil
		}
	case "VXLANTunnel":
		if evpnName.MatchString(name) {
			return r.Kind + "|" + name, nil
		}
	case "VLANVNI":
		var id uint32
		if json.Unmarshal(fields["vlanID"], &id) == nil && id > 0 && id <= 4094 && evpnName.MatchString(text("tunnel")) {
			return r.Kind + "|" + text("tunnel") + "|" + strconv.FormatUint(uint64(id), 10), nil
		}
	case "EVPNPeer":
		a, err := netip.ParseAddr(text("address"))
		if vrf == "default" && err == nil && a.Zone() == "" && !a.Is4In6() {
			return r.Kind + "|default|" + a.String(), nil
		}
	case "ACLPolicy":
		if networkTrafficIdentifier.MatchString(name) {
			return r.Kind + "|" + name, nil
		}
	case "Scheduler":
		if networkQoSIdentifier.MatchString(name) {
			return r.Kind + "|" + name, nil
		}
	case "ACLBinding":
		if policy := text("policy"); networkTrafficIdentifier.MatchString(policy) {
			return r.Kind + "|" + policy, nil
		}
	case "QoSMap":
		if typ := text("type"); networkQoSIdentifier.MatchString(name) && (typ == "DSCPToTC" || typ == "Dot1pToTC" || typ == "TCToQueue") {
			return r.Kind + "|" + typ + "|" + name, nil
		}
	case "QoSBinding":
		if iface := text("interfaceName"); canonicalNumber(iface, "Ethernet", 1<<32-1) {
			return r.Kind + "|" + iface, nil
		}
	case "FRRMigration":
		if text("mode") == "Unified" || text("mode") == "Traditional" {
			return "FRRMigration|unified", nil
		}
	case "PortChannel":
		if canonicalNumber(name, "PortChannel", 65535) {
			return r.Kind + "|" + name, nil
		}
	case "VRF":
		if validVRF(name) {
			return r.Kind + "|" + name, nil
		}
	case "L3Interface":
		if canonicalNumber(name, "Ethernet", 1<<32-1) || canonicalNumber(name, "PortChannel", 65535) || (canonicalNumber(name, "Vlan", 4094) && name != "Vlan0") {
			return r.Kind + "|" + name, nil
		}
	case "StaticRoute":
		p, e := netip.ParsePrefix(text("prefix"))
		if e == nil && p == p.Masked() && !p.Addr().Is4In6() {
			return r.Kind + "|" + vrf + "|" + p.String(), nil
		}
	case "BGP":
		return r.Kind + "|" + vrf, nil
	case "BGPPeer":
		a, e := netip.ParseAddr(text("address"))
		if e == nil && a.Zone() == "" && !a.Is4In6() {
			return r.Kind + "|" + vrf + "|" + a.String(), nil
		}
	case "DHCPRelay":
		var id uint32
		if json.Unmarshal(fields["vlanID"], &id) == nil && id > 0 && id <= 4094 {
			return r.Kind + "|Vlan" + strconv.FormatUint(uint64(id), 10), nil
		}
	}
	return "", fmt.Errorf("invalid network identity")
}

func planNetworkResource(db vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
	switch r.Kind {
	case "EVPN":
		return planNetworkEVPN(db, r)
	case "MLAG":
		return planNetworkMLAG(db, r)
	case "VXLANTunnel":
		return planNetworkVXLANTunnel(db, r)
	case "VLANVNI":
		return planNetworkVLANVNI(db, r)
	case "EVPNPeer":
		return planNetworkEVPNPeer(db, r)
	case "ACLPolicy":
		return planNetworkACLPolicy(db, r)
	case "ACLBinding":
		return planNetworkACLBinding(db, r)
	case "QoSMap":
		return planNetworkQoSMap(db, r)
	case "Scheduler":
		return planNetworkScheduler(db, r)
	case "QoSBinding":
		return planNetworkQoSBinding(db, r)
	case "FRRMigration":
		return planNetworkFRRMigration(db, r)
	case "PortChannel":
		return planNetworkPortChannel(db, r)
	case "VRF":
		return planNetworkVRF(db, r)
	case "L3Interface":
		return planNetworkL3Interface(db, r)
	case "StaticRoute":
		return planNetworkStaticRoute(db, r)
	case "BGP":
		return planNetworkBGP(db, r)
	case "BGPPeer":
		return planNetworkBGPPeer(db, r)
	case "DHCPRelay":
		return planNetworkDHCPRelay(db, r)
	default:
		return nil, fmt.Errorf("unsupported network kind")
	}
}

var networkTrafficIdentifier = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)

// QoS names follow the native 32-character map/scheduler schema, including a
// numeric first character. ACL names retain their separate letter-leading rule.
var networkQoSIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$`)

// Defense in depth for planner outputs and durable records. RPC callers never
// supply these tables or fields; kind-specific planners validate their values.
func validateNetworkFields(kind string, desired vlanChangeDB) error {
	allowed := map[string]map[string]string{
		"FRRMigration": {"DEVICE_METADATA": "frr_mgmt_framework_config docker_routing_config_mode"},
		"PortChannel":  {"PORTCHANNEL": "admin_status mtu min_links fast_rate", "PORTCHANNEL_MEMBER": "NULL"},
		"VRF":          {"VRF": "NULL"},
		"L3Interface":  {"INTERFACE": "NULL vrf_name", "PORTCHANNEL_INTERFACE": "NULL vrf_name", "VLAN_INTERFACE": "NULL vrf_name"},
		"StaticRoute":  {"STATIC_ROUTE": "nexthop ifname distance advertise"},
		"BGP":          {"BGP_GLOBALS": "local_asn router_id default_ipv4_unicast default_shutdown", "BGP_GLOBALS_AF_NETWORK": "backdoor", "PREFIX_SET": "mode", "PREFIX": "action"},
		"BGPPeer":      {"BGP_NEIGHBOR": "asn local_addr admin_status", "BGP_NEIGHBOR_AF": "admin_status max_prefix_limit max_prefix_warning_threshold prefix_list_out send_default_route"},
		"DHCPRelay":    {"VLAN": "dhcp_servers@", "DHCP_RELAY": "dhcpv6_servers@", "DHCPV4_RELAY": "dhcpv4_servers@"},
		"MLAG":         {"MCLAG_DOMAIN": "source_ip peer_ip peer_link keepalive_interval session_timeout", "MCLAG_INTERFACE": "if_type"},
		"EVPN":         {"BGP_GLOBALS_AF": "advertise-all-vni advertise-svi-ip advertise-default-gw advertise-ipv4-unicast advertise-ipv6-unicast"},
		"VXLANTunnel":  {"VXLAN_TUNNEL": "src_ip", "VXLAN_EVPN_NVO": "source_vtep"},
		"VLANVNI":      {"VXLAN_TUNNEL_MAP": "vlan vni", "BGP_GLOBALS_EVPN_VNI": "route-distinguisher", "BGP_GLOBALS_EVPN_VNI_RT": "route-target-type"},
		"EVPNPeer":     {"BGP_NEIGHBOR_AF": "admin_status route_map_in@ route_map_out@ send_community unchanged_nexthop", "ROUTE_MAP": "route_operation match_ext_community", "EXTENDED_COMMUNITY_SET": "set_type match_action community_member@"},
		// Policy and binding deliberately reserve disjoint fields on ACL_TABLE.
		"ACLPolicy":  {"ACL_TABLE": "type stage policy_desc", "ACL_RULE": "PRIORITY PACKET_ACTION IP_TYPE SRC_IP DST_IP SRC_IPV6 DST_IPV6 IP_PROTOCOL NEXT_HEADER L4_SRC_PORT L4_DST_PORT"},
		"ACLBinding": {"ACL_TABLE": "ports@"},
		"QoSMap":     {"DSCP_TO_TC_MAP": "", "DOT1P_TO_TC_MAP": "", "TC_TO_QUEUE_MAP": ""},
		"Scheduler":  {"SCHEDULER": "type weight meter_type cir pir cbs pbs"},
		"QoSBinding": {"PORT_QOS_MAP": "dscp_to_tc_map dot1p_to_tc_map tc_to_queue_map", "QUEUE": "scheduler"},
	}[kind]
	if allowed == nil || len(desired) == 0 {
		return fmt.Errorf("empty or unsupported network plan")
	}
	if kind == "FRRMigration" && !reflect.DeepEqual(desired, frrMigrationDesired()) && !reflect.DeepEqual(desired, frrMigrationDesired("Traditional")) {
		return fmt.Errorf("FRR migration requires exactly the target mode metadata")
	}
	for key, fields := range desired {
		table, name, ok := strings.Cut(key, "|")
		if !ok || name == "" || strings.ContainsAny(key, "\x00\r\n") || len(fields) == 0 {
			return fmt.Errorf("invalid network target")
		}
		if !networkTrafficTarget(kind, table, name) {
			return fmt.Errorf("invalid traffic policy target %s", key)
		}
		if !networkRedundancyTarget(kind, table, name) {
			return fmt.Errorf("invalid redundancy target %s", key)
		}
		if kind == "EVPNPeer" && table == "BGP_NEIGHBOR_AF" && fields["admin_status"] != "up" && fields["admin_status"] != "down" {
			return fmt.Errorf("invalid EVPN address-family admin status")
		}
		if kind == "EVPN" && !evpnGlobalConfigValid(fields) {
			return fmt.Errorf("invalid global EVPN fields")
		}
		if kind == "VLANVNI" {
			if rd, ok := fields["route-distinguisher"]; ok && evpnRD(rd) != nil {
				return fmt.Errorf("invalid VNI route distinguisher")
			}
			if typ, ok := fields["route-target-type"]; ok && typ != "import" && typ != "export" && typ != "both" {
				return fmt.Errorf("invalid VNI route target type")
			}
		}
		for field := range fields {
			if kind == "QoSMap" && networkQoSMapField(table, field) {
				continue
			}
			if !slices.Contains(strings.Fields(allowed[table]), field) {
				return fmt.Errorf("unsupported network target table/field %s/%s", table, field)
			}
		}
	}
	return nil
}

// Restrict shared routing tables to the initial default-VRF EVPN scope. In
// particular an EVPN peer must never reserve the shared neighbor's fields.
func networkRedundancyTarget(kind, table, name string) bool {
	canonicalID := func(s string, max uint64) bool {
		n, err := strconv.ParseUint(s, 10, 32)
		return err == nil && n > 0 && n <= max && s == strconv.FormatUint(n, 10)
	}
	switch kind {
	case "EVPN":
		return table == "BGP_GLOBALS_AF" && name == "default|l2vpn_evpn"
	case "MLAG":
		if table == "MCLAG_DOMAIN" {
			return canonicalID(name, 4095)
		}
		if table == "MCLAG_INTERFACE" {
			domain, iface, ok := strings.Cut(name, "|")
			n, err := strconv.ParseUint(strings.TrimPrefix(iface, "PortChannel"), 10, 16)
			return ok && canonicalID(domain, 4095) && err == nil && iface == "PortChannel"+strconv.FormatUint(n, 10)
		}
		return false
	case "VXLANTunnel":
		return (table == "VXLAN_TUNNEL" || table == "VXLAN_EVPN_NVO") && evpnName.MatchString(name)
	case "VLANVNI":
		if table == "VXLAN_TUNNEL_MAP" {
			tunnel, mapping, ok := strings.Cut(name, "|")
			parts := strings.Split(mapping, "_")
			return ok && evpnName.MatchString(tunnel) && len(parts) == 3 && parts[0] == "map" && canonicalID(parts[1], 16777215) && strings.HasPrefix(parts[2], "Vlan") && canonicalID(strings.TrimPrefix(parts[2], "Vlan"), 4094)
		}
		parts := strings.Split(name, "|")
		if len(parts) < 3 || parts[0] != "default" || parts[1] != "l2vpn_evpn" || !canonicalID(parts[2], 16777215) {
			return false
		}
		return (table == "BGP_GLOBALS_EVPN_VNI" && len(parts) == 3) || (table == "BGP_GLOBALS_EVPN_VNI_RT" && len(parts) == 4 && evpnRD(parts[3]) == nil)
	case "EVPNPeer":
		parts := strings.Split(name, "|")
		if table == "EXTENDED_COMMUNITY_SET" {
			return regexp.MustCompile(`^SOEV_[a-f0-9]{20}_[IO]$`).MatchString(name)
		}
		if table == "ROUTE_MAP" {
			return len(parts) == 2 && regexp.MustCompile(`^SOEV_[a-f0-9]{20}_[IO]$`).MatchString(parts[0]) && (parts[1] == "10" || parts[1] == "65535")
		}
		if table != "BGP_NEIGHBOR_AF" || len(parts) != 3 || parts[0] != "default" || parts[2] != "l2vpn_evpn" {
			return false
		}
		a, err := netip.ParseAddr(parts[1])
		return err == nil && a.Zone() == "" && !a.Is4In6() && a.String() == parts[1]
	default:
		return true
	}
}

func validateNetworkActivationPreflight(kind string, p *networkPlan) error {
	if kind == "EVPNPeer" {
		for _, fields := range p.Desired {
			if fields["admin_status"] == "up" && (p.Preflight == nil || p.Runtime == nil) {
				return fmt.Errorf("EVPN Up requires runtime safety preflight and observation")
			}
		}
	}
	return nil
}

func networkTrafficTarget(kind, table, name string) bool {
	switch kind {
	case "ACLPolicy":
		if table == "ACL_RULE" {
			policy, rule, ok := strings.Cut(name, "|")
			return ok && networkTrafficIdentifier.MatchString(policy) && networkTrafficIdentifier.MatchString(rule)
		}
		return table == "ACL_TABLE" && networkTrafficIdentifier.MatchString(name)
	case "ACLBinding":
		return table == "ACL_TABLE" && networkTrafficIdentifier.MatchString(name)
	case "QoSMap", "Scheduler":
		return networkQoSIdentifier.MatchString(name)
	case "QoSBinding":
		iface := name
		if table == "QUEUE" {
			var index string
			var ok bool
			iface, index, ok = strings.Cut(name, "|")
			n, err := strconv.ParseUint(index, 10, 32)
			if !ok || err != nil || index != strconv.FormatUint(n, 10) {
				return false
			}
		} else if table != "PORT_QOS_MAP" {
			return false
		}
		n, err := strconv.ParseUint(strings.TrimPrefix(iface, "Ethernet"), 10, 32)
		return err == nil && iface == "Ethernet"+strconv.FormatUint(n, 10)
	default:
		return true
	}
}

// Numeric map fields are a bounded schema, never a wildcard for Redis fields.
// Planners additionally enforce the actual device's TC and queue capabilities.
func networkQoSMapField(table, field string) bool {
	var max uint64
	switch table {
	case "DSCP_TO_TC_MAP":
		max = 63
	case "DOT1P_TO_TC_MAP":
		max = 7
	case "TC_TO_QUEUE_MAP":
		max = 255
	default:
		return false
	}
	n, err := strconv.ParseUint(field, 10, 8)
	return err == nil && n <= max && field == strconv.FormatUint(n, 10)
}

func networkSubset(db, desired vlanChangeDB) bool {
	for key, fields := range desired {
		if db[key] == nil {
			return false
		}
		for field, value := range fields {
			if actual, ok := db[key][field]; !ok || actual != value {
				return false
			}
		}
	}
	return true
}

// Snapshot only requested fields, not all fields of the target hash.
func networkTarget(db, desired vlanChangeDB) vlanChangeDB {
	out := vlanChangeDB{}
	for key, fields := range desired {
		for field := range fields {
			if value, ok := db[key][field]; ok {
				if out[key] == nil {
					out[key] = map[string]string{}
				}
				out[key][field] = value
			}
		}
	}
	return out
}

func (m *SonicAgent) GetNetworkResource(ctx context.Context, r *agent.NetworkRequest) (*agent.NetworkResult, *agent.Status) {
	return m.networkResource(ctx, r, "get")
}

func (m *SonicAgent) EnsureNetworkResource(ctx context.Context, r *agent.NetworkRequest) (*agent.NetworkResult, *agent.Status) {
	return m.networkResource(ctx, r, "ensure")
}

func (m *SonicAgent) RecoverNetworkResource(ctx context.Context, r *agent.NetworkRequest) (*agent.NetworkResult, *agent.Status) {
	return m.networkResource(ctx, r, "recover")
}

func (m *SonicAgent) networkResource(ctx context.Context, r *agent.NetworkRequest, operation string) (*agent.NetworkResult, *agent.Status) {
	write := operation != "get"
	if err := agent.ValidateNetworkRequest(r, write); err != nil {
		return nil, agenterrors.NewErrorStatus(agenterrors.BAD_REQUEST, err.Error())
	}
	request := *r
	request.Spec = append(json.RawMessage(nil), r.Spec...)
	r = &request
	identity, err := networkIdentity(r)
	if err != nil {
		return nil, agenterrors.NewErrorStatus(agenterrors.BAD_REQUEST, err.Error())
	}
	timeout := 15 * time.Second
	if write {
		timeout = 120 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	m.configMutex.Lock()
	defer m.configMutex.Unlock()
	failure := func(err error) (*agent.NetworkResult, *agent.Status) {
		return nil, agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, err.Error())
	}
	// Every cooperating writer acquires exactly this order, including recovery.
	if m.journalDir != "" {
		j, err := m.lockVLANAuthorityJournal(ctx)
		if err != nil {
			return failure(err)
		}
		defer j.close()
		if write {
			if err := j.checkPending(0); err != nil {
				return failure(err)
			}
		}
	}
	if m.breakoutJournalDir != "" {
		j, err := m.lockBreakoutJournal(ctx)
		if err != nil {
			return failure(err)
		}
		defer j.close()
		record, err := loadBreakoutRecord(j)
		if err != nil {
			return failure(err)
		}
		if write && record != nil && record.Pending {
			return failure(fmt.Errorf("pending breakout blocks network writes"))
		}
	}
	state := &networkJournalState{Version: 1, Records: map[string]*networkRecord{}}
	var journal *vlanAuthorityJournal
	if write || m.networkJournalDir != "" {
		var err error
		journal, err = m.lockNetworkJournal(ctx)
		if err != nil {
			return failure(err)
		}
		defer journal.close()
		state, err = loadNetworkJournal(journal)
		if err != nil {
			return failure(err)
		}
	}
	record := state.Records[identity]
	if r.Kind == "EVPN" && record != nil && len(record.EVPNMappings) > 0 && operation != "recover" {
		var spec evpnGlobalSpec
		if err := mlagJSON(r.Spec, &spec, false); err != nil {
			return failure(err)
		}
		if !reflect.DeepEqual(record.EVPNMappings, spec.Mappings) {
			return failure(fmt.Errorf("global EVPN mapping declaration is durably bound; replacement requires explicit recovery"))
		}
	}
	if record != nil && (record.OwnerID != r.OwnerID || record.Kind != r.Kind) {
		return nil, agenterrors.NewErrorStatus(agenterrors.ALREADY_EXISTS, "network identity owned by a different UID or kind; ownership cannot transfer")
	}
	db, raw, err := m.vlanChangeSnapshot(ctx)
	if err != nil {
		return failure(err)
	}
	planner := m.planNetwork
	if planner == nil {
		planner = planNetworkResource
	}
	if write && record != nil && record.Pending != nil {
		pending := record.Pending
		original, err := planner(db, &pending.Request)
		if err != nil {
			return failure(fmt.Errorf("pending request cannot be planned safely: %w", err))
		}
		if original == nil || original.Identity != identity || !reflect.DeepEqual(original.Desired, pending.After) {
			return failure(fmt.Errorf("pending planner output changed; manual inspection required"))
		}
		if err := validateNetworkActivationPreflight(r.Kind, original); err != nil {
			return failure(err)
		}
		if (original.Activate != nil) != (pending.Activation != "") {
			return failure(fmt.Errorf("pending activation contract changed; manual inspection required"))
		}
		out, st := m.finishNetwork(ctx, journal, state, record, original, db, raw)
		if st == nil && operation == "ensure" {
			// Do not execute the caller's new desired state in the recovery call.
			var previous, current any
			_ = json.Unmarshal(pending.Request.Spec, &previous)
			_ = json.Unmarshal(r.Spec, &current)
			if !reflect.DeepEqual(previous, current) {
				return out, agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, "previous pending network request recovered; retry new desired configuration")
			}
		}
		return out, st
	}
	if operation == "recover" {
		// Absence of pending work is a successful orphan/no-op, including no record.
		return &agent.NetworkResult{Message: "no pending network operation; configuration orphaned unchanged"}, nil
	}
	p, err := planner(db, r)
	if err != nil {
		return nil, agenterrors.NewErrorStatus(agenterrors.BAD_REQUEST, err.Error())
	}
	if p == nil || p.Identity != identity || len(p.Identity) > 1024 {
		return failure(fmt.Errorf("invalid network plan identity"))
	}
	if err := validateNetworkFields(r.Kind, p.Desired); err != nil {
		return failure(err)
	}
	if !write {
		return m.observeNetwork(ctx, db, p, record)
	}
	if err := validateNetworkActivationPreflight(r.Kind, p); err != nil {
		return failure(err)
	}
	fail := func(message string) (*agent.NetworkResult, *agent.Status) {
		out, _ := m.observeNetwork(ctx, db, p, record)
		out.PersistenceVerified = false
		out.Message = message
		return out, agenterrors.NewErrorStatus(agenterrors.ALREADY_EXISTS, message)
	}
	for identity, other := range state.Records {
		if identity != p.Identity && other.Pending != nil {
			return fail("another network operation has pending persistence; reconcile its owner first")
		}
		if identity != p.Identity {
			for key, fields := range p.Desired {
				for field := range fields {
					if _, ok := other.Fields[key][field]; ok {
						return fail("network field already tracked by another identity")
					}
				}
			}
		}
	}
	if record != nil {
		for key, fields := range record.Fields {
			for field := range fields {
				if _, ok := p.Desired[key][field]; !ok {
					return fail("network field removal is outside additive scope; orphan/manual cleanup required")
				}
			}
		}
	}
	owned := vlanChangeDB{}
	if record != nil {
		for key, fields := range record.Owned {
			owned[key] = maps.Clone(fields)
		}
	}
	// Only this migration may replace mode scalars. Approval,
	// raw CONFIG_DB/runtime validation and durable preparation all precede this
	// exception. The ordinary transaction still captures Before and owns After.
	migrationUpdate := r.Kind == "FRRMigration" && (record == nil || !reflect.DeepEqual(record.Fields, p.Desired))
	if migrationUpdate {
		if p.Preflight == nil {
			return fail("FRR migration requires preflight")
		}
		if err := p.Preflight(ctx, m); err != nil {
			return fail("network preflight failed: " + err.Error())
		}
	}
	for key, fields := range p.Desired {
		for field, value := range fields {
			old, exists := db[key][field]
			if previous, ours := owned[key][field]; exists && ours && previous != old {
				return fail("owned network field drifted; inspect before reconciliation")
			}
			if exists && old != value {
				// Only peer/EVPN AF admin state and validated relay destination fields are
				// mutable. Never adopt foreign fields or overwrite ownership drift.
				previous, ours := owned[key][field]
				peerAdmin := r.Kind == "BGPPeer" && strings.HasPrefix(key, "BGP_NEIGHBOR|") && field == "admin_status" && (value == "up" || value == "down")
				evpnAdmin := r.Kind == "EVPNPeer" && strings.HasPrefix(key, "BGP_NEIGHBOR_AF|default|") && strings.HasSuffix(key, "|l2vpn_evpn") && field == "admin_status" && (old == "up" || old == "down") && (value == "up" || value == "down")
				globalEVPNAdmin := r.Kind == "EVPN" && key == evpnGlobalKey && field == "advertise-all-vni" && (old == "true" || old == "false") && (value == "true" || value == "false")
				relayServers := r.Kind == "DHCPRelay" && routingRelayMutableField(key, field)
				modeUpdate := migrationUpdate && frrMigrationModeUpdate(key, field, old, value) && (record == nil || (ours && previous == old))
				if !modeUpdate && (!ours || previous != old || (!peerAdmin && !evpnAdmin && !globalEVPNAdmin && !relayServers)) {
					return fail("conflicting network field; only durably owned peer/EVPN AF admin_status and relay destinations support updates")
				}
			}
			if !exists || (exists && old != value) {
				if owned[key] == nil {
					owned[key] = map[string]string{}
				}
				owned[key][field] = value
			}
		}
	}
	if record != nil && reflect.DeepEqual(record.Fields, p.Desired) && networkSubset(db, p.Desired) && record.Fingerprint == vlanAuthorityHash(db) {
		return m.observeNetwork(ctx, db, p, record)
	}
	if p.Preflight != nil && !migrationUpdate {
		if err := p.Preflight(ctx, m); err != nil {
			return fail("network preflight failed: " + err.Error())
		}
	}
	if record == nil {
		record = &networkRecord{Kind: r.Kind, OwnerID: r.OwnerID}
		state.Records[p.Identity] = record
	}
	before := networkTarget(db, p.Desired)
	post := maps.Clone(db)
	for key, fields := range p.Desired {
		merged := maps.Clone(db[key])
		if merged == nil {
			merged = map[string]string{}
		}
		maps.Copy(merged, fields)
		post[key] = merged
	}
	activation := ""
	if p.Activate != nil {
		if p.Runtime == nil {
			return fail("activation requires exact runtime verification")
		}
		activation = "Prepared"
	}
	record.Pending = &networkPending{Request: *r, Activation: activation, Before: before, After: p.Desired, Owned: owned, PreHash: vlanAuthorityHash(db), PostHash: vlanAuthorityHash(post)}
	if err := storeNetworkJournal(journal, state); err != nil {
		return fail("pending network journal durability uncertain: " + err.Error())
	}
	return m.finishNetwork(ctx, journal, state, record, p, db, raw)
}

func (m *SonicAgent) observeNetwork(ctx context.Context, db vlanChangeDB, p *networkPlan, r *networkRecord) (*agent.NetworkResult, *agent.Status) {
	out := &agent.NetworkResult{ConfigurationVerified: networkSubset(db, p.Desired)}
	for key := range p.Desired {
		if db[key] != nil {
			out.Exists = true
			break
		}
	}
	out.Observed, _ = json.Marshal(networkTarget(db, p.Desired))
	out.PersistenceVerified = out.ConfigurationVerified && r != nil && r.Pending == nil && reflect.DeepEqual(r.Fields, p.Desired) && r.Fingerprint == vlanAuthorityHash(db)
	var probeError error
	if p.Runtime != nil {
		verified, observed, err := p.Runtime(ctx, m)
		probeError = err
		out.RuntimeVerified = verified && err == nil
		if len(observed) != 0 && json.Valid(observed) {
			out.Observed = observed
		} else if len(observed) != 0 {
			probeError = fmt.Errorf("invalid runtime observation JSON")
			out.RuntimeVerified = false
		}
		if err != nil {
			out.Message = "runtime observation failed: " + err.Error()
		}
		latest, _, err := m.vlanChangeSnapshot(ctx)
		if err != nil || vlanAuthorityHash(latest) != vlanAuthorityHash(db) {
			out.ConfigurationVerified, out.RuntimeVerified, out.PersistenceVerified = false, false, false
			out.Message = "configuration changed or could not be read after runtime observation; retry"
			probeError = fmt.Errorf("%s", out.Message)
		}
	} else {
		out.Message = "runtime verification unavailable"
	}
	if probeError != nil {
		return out, agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, "runtime observation failed: "+probeError.Error())
	}
	return out, nil
}

func (m *SonicAgent) finishNetwork(ctx context.Context, j *vlanAuthorityJournal, state *networkJournalState, r *networkRecord, plan *networkPlan, db vlanChangeDB, raw string) (*agent.NetworkResult, *agent.Status) {
	p := r.Pending
	fail := func(message string) (*agent.NetworkResult, *agent.Status) {
		out, _ := m.observeNetwork(ctx, db, plan, r)
		out.PersistenceVerified = false
		out.Message = message
		return out, agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, message)
	}
	hash := vlanAuthorityHash(db)
	if hash != p.PreHash && hash != p.PostHash {
		return fail("pending network operation matches neither full pre nor post snapshot; manual inspection required")
	}
	if hash != p.PostHash && (p.Activation == "Dispatched" || p.Activation == "Verified") {
		return fail("configuration reverted after activation dispatch; manual inspection required")
	}
	if hash != p.PostHash {
		if plan.Preflight != nil {
			if err := plan.Preflight(ctx, m); err != nil {
				return fail("network preflight failed: " + err.Error())
			}
		}
		m.configDirty = true
		applied, err := m.casVLANChange(ctx, raw, p.Before, p.After)
		if err != nil {
			return fail("network CAS outcome uncertain; recover pending request")
		}
		if !applied {
			// Redis definitely performed no writes. Preserve prior confirmed UID
			// ownership, but durably discard this intent so other writers can run.
			r.Pending = nil
			if r.Fields == nil {
				delete(state.Records, plan.Identity)
			}
			if err := storeNetworkJournal(j, state); err != nil {
				r.Pending = p
				state.Records[plan.Identity] = r
				return fail("CAS rejected; pending cleanup durability uncertain; retry")
			}
			return fail("CONFIG_DB changed before network CAS; rejected intent cleared; retry")
		}
	}
	var err error
	db, _, err = m.vlanChangeSnapshot(ctx)
	if err != nil || vlanAuthorityHash(db) != p.PostHash {
		return fail("network post-apply snapshot not verified; persistence pending")
	}
	if p.Activation != "" {
		if plan.Activate == nil || plan.Runtime == nil {
			return fail("pending activation callbacks unavailable")
		}
		if p.Activation == "Prepared" {
			if plan.Preflight != nil {
				if err := plan.Preflight(ctx, m); err != nil {
					return fail("activation preflight failed: " + err.Error())
				}
			}
			latest, _, err := m.vlanChangeSnapshot(ctx)
			if err != nil || vlanAuthorityHash(latest) != p.PostHash {
				return fail("configuration changed before activation dispatch")
			}
			verified, _, err := plan.Runtime(ctx, m)
			if err != nil {
				return fail("activation pre-dispatch probe failed: " + err.Error())
			}
			latest, _, err = m.vlanChangeSnapshot(ctx)
			if err != nil || vlanAuthorityHash(latest) != p.PostHash {
				return fail("configuration changed during pre-dispatch probe")
			}
			if verified {
				// Re-persisting an unchanged resource must not restart a daemon
				// whose exact desired runtime is already active.
				p.Activation = "Verified"
				if err := storeNetworkJournal(j, state); err != nil {
					return fail("activation verification durability uncertain")
				}
			} else {
				// Commit dispatch BEFORE calling the daemon. An unknown outcome is
				// resolved by runtime evidence only; no restart is blindly repeated.
				if ctx.Err() != nil {
					return fail("activation canceled before dispatch")
				}
				p.Activation = "Dispatched"
				if err := storeNetworkJournal(j, state); err != nil {
					return fail("activation dispatch durability uncertain; inspect runtime before retry")
				}
				if err := plan.Activate(ctx, m); err != nil {
					return fail("activation outcome uncertain; runtime verification required: " + err.Error())
				}
			}
		}
		verified, _, err := plan.Runtime(ctx, m)
		if err != nil {
			return fail("activation runtime probe failed: " + err.Error())
		}
		if !verified {
			return fail("activation not verified; will not repeat dispatched command; wait or inspect manually")
		}
		db, _, err = m.vlanChangeSnapshot(ctx)
		if err != nil || vlanAuthorityHash(db) != p.PostHash {
			return fail("configuration changed during activation; manual inspection required")
		}
		if p.Activation != "Verified" {
			p.Activation = "Verified"
			if err := storeNetworkJournal(j, state); err != nil {
				return fail("activation verification durability uncertain")
			}
		}
	}
	// Configuration readiness is independent of link/peer establishment. Persist
	// verified intended config even when runtime is unsupported or not converged.
	if ctx.Err() != nil {
		return fail("network persistence pending; request canceled")
	}
	m.configDirty = true
	if st := m.saveConfigLocked(ctx); st != nil && st.Code != 0 {
		return fail("network persistence pending; save failed or outcome uncertain")
	}
	db, _, err = m.vlanChangeSnapshot(ctx)
	if err != nil || ctx.Err() != nil || vlanAuthorityHash(db) != p.PostHash {
		return fail("network configuration changed during save; persistence pending")
	}
	oldFields, oldOwned, oldHash := r.Fields, r.Owned, r.Fingerprint
	oldMappings := r.EVPNMappings
	if r.Kind == "EVPN" {
		var spec evpnGlobalSpec
		if err := mlagJSON(p.Request.Spec, &spec, false); err != nil {
			return fail("invalid recorded EVPN mapping declaration")
		}
		r.EVPNMappings = spec.Mappings
	}
	r.Fields, r.Owned, r.Fingerprint, r.Pending = p.After, p.Owned, p.PostHash, nil
	// SaveConfig persists the entire DB. Refresh proof for all matching records,
	// otherwise independent controllers repeatedly save each other's stale proof.
	for _, other := range state.Records {
		if other.Pending == nil && networkSubset(db, other.Fields) {
			other.Fingerprint = p.PostHash
		}
	}
	if err := storeNetworkJournal(j, state); err != nil {
		r.Fields, r.Owned, r.Fingerprint, r.Pending = oldFields, oldOwned, oldHash, p
		r.EVPNMappings = oldMappings
		return fail("network save acknowledged but completion durability uncertain; retry")
	}
	m.configDirty = false
	return m.observeNetwork(ctx, db, plan, r)
}
