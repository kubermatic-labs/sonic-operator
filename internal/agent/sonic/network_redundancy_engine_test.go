// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"encoding/json"
	"strings"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

func TestNetworkRedundancyIdentity(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, kind, spec, want string }{
		{"domain min", "MLAG", `{"domainID":1,"members":null}`, "MLAG|1"},
		{"domain max", "MLAG", `{"domainID":4095}`, "MLAG|4095"},
		{"domain zero", "MLAG", `{"domainID":0}`, ""},
		{"domain overflow", "MLAG", `{"domainID":4096}`, ""},
		{"domain negative", "MLAG", `{"domainID":-1}`, ""},
		{"domain fraction", "MLAG", `{"domainID":1.0}`, ""},
		{"domain string", "MLAG", `{"domainID":"1"}`, ""},
		{"domain null", "MLAG", `{"domainID":null}`, ""},
		{"domain duplicate", "MLAG", `{"domainID":1,"domainID":2}`, ""},
		{"tunnel", "VXLANTunnel", `{"name":"vtep1","sourceAddress":null}`, "VXLANTunnel|vtep1"},
		{"tunnel delimiter", "VXLANTunnel", `{"name":"vtep|1"}`, ""},
		{"tunnel null", "VXLANTunnel", `{"name":null}`, ""},
		{"tunnel oversized", "VXLANTunnel", `{"name":"` + strings.Repeat("a", 65) + `"}`, ""},
		{"mapping", "VLANVNI", `{"tunnel":"vtep1","vlanID":1,"vni":null}`, "VLANVNI|vtep1|1"},
		{"mapping max", "VLANVNI", `{"tunnel":"vtep1","vlanID":4094}`, "VLANVNI|vtep1|4094"},
		{"mapping zero", "VLANVNI", `{"tunnel":"vtep1","vlanID":0}`, ""},
		{"mapping overflow", "VLANVNI", `{"tunnel":"vtep1","vlanID":4095}`, ""},
		{"mapping delimiter", "VLANVNI", `{"tunnel":"vtep1|map","vlanID":1}`, ""},
		{"mapping null", "VLANVNI", `{"tunnel":null,"vlanID":1}`, ""},
		{"mapping missing", "VLANVNI", `{"vlanID":1}`, ""},
		{"peer v4", "EVPNPeer", `{"address":"192.0.2.1","adminState":null}`, "EVPNPeer|default|192.0.2.1"},
		{"peer v6 canonical", "EVPNPeer", `{"vrf":"default","address":"2001:0DB8:0::1"}`, "EVPNPeer|default|2001:db8::1"},
		{"peer vrf", "EVPNPeer", `{"vrf":"VrfBlue","address":"192.0.2.1"}`, ""},
		{"peer mapped", "EVPNPeer", `{"address":"::ffff:192.0.2.1"}`, ""},
		{"peer zone", "EVPNPeer", `{"address":"fe80::1%eth0"}`, ""},
		{"peer null vrf", "EVPNPeer", `{"vrf":null,"address":"192.0.2.1"}`, ""},
		{"peer duplicate", "EVPNPeer", `{"address":"192.0.2.1","address":"192.0.2.2"}`, ""},
		{"unknown kind", "evpnpeer", `{"address":"192.0.2.1"}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := networkIdentity(&agent.NetworkRequest{Kind: tc.kind, Spec: json.RawMessage(tc.spec)})
			if got != tc.want || (err == nil) != (tc.want != "") {
				t.Fatalf("identity=%q err=%v want=%q", got, err, tc.want)
			}
		})
	}
}

func TestNetworkRedundancyFieldReservations(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, kind, key, field, value string
		valid                         bool
	}{
		{"domain", "MLAG", "MCLAG_DOMAIN|1", "source_ip", "192.0.2.1", true},
		{"domain timer", "MLAG", "MCLAG_DOMAIN|4095", "session_timeout", "30", true},
		{"member", "MLAG", "MCLAG_INTERFACE|1|PortChannel10", "if_type", "PortChannel", true},
		{"unknown domain field", "MLAG", "MCLAG_DOMAIN|1", "rawFields", "x", false},
		{"unknown table", "MLAG", "PORTCHANNEL|PortChannel10", "admin_status", "up", false},
		{"domain noncanonical", "MLAG", "MCLAG_DOMAIN|01", "source_ip", "192.0.2.1", false},
		{"domain overflow", "MLAG", "MCLAG_DOMAIN|4096", "source_ip", "192.0.2.1", false},
		{"management member", "MLAG", "MCLAG_INTERFACE|1|eth0", "if_type", "PortChannel", false},
		{"extra member component", "MLAG", "MCLAG_INTERFACE|1|PortChannel10|x", "if_type", "PortChannel", false},
		{"tunnel", "VXLANTunnel", "VXLAN_TUNNEL|vtep1", "src_ip", "192.0.2.1", true},
		{"nvo", "VXLANTunnel", "VXLAN_EVPN_NVO|nvo1", "source_vtep", "vtep1", true},
		{"no destination", "VXLANTunnel", "VXLAN_TUNNEL|vtep1", "dst_ip", "192.0.2.2", false},
		{"no mapping via tunnel", "VXLANTunnel", "VXLAN_TUNNEL_MAP|vtep1|map1", "vni", "100", false},
		{"tunnel delimiter", "VXLANTunnel", "VXLAN_TUNNEL|vtep1|other", "src_ip", "192.0.2.1", false},
		{"mapping vlan", "VLANVNI", "VXLAN_TUNNEL_MAP|vtep1|map_100_Vlan10", "vlan", "Vlan10", true},
		{"mapping vni", "VLANVNI", "VXLAN_TUNNEL_MAP|vtep1|map_100_Vlan10", "vni", "100", true},
		{"vni RD", "VLANVNI", "BGP_GLOBALS_EVPN_VNI|default|l2vpn_evpn|100", "route-distinguisher", "65001:100", true},
		{"vni RT import", "VLANVNI", "BGP_GLOBALS_EVPN_VNI_RT|default|l2vpn_evpn|100|65001:100", "route-target-type", "import", true},
		{"vni RT export", "VLANVNI", "BGP_GLOBALS_EVPN_VNI_RT|default|l2vpn_evpn|100|192.0.2.1:100", "route-target-type", "export", true},
		{"vni RT both", "VLANVNI", "BGP_GLOBALS_EVPN_VNI_RT|default|l2vpn_evpn|100|65001:100", "route-target-type", "both", true},
		{"vni RD unknown field", "VLANVNI", "BGP_GLOBALS_EVPN_VNI|default|l2vpn_evpn|100", "route_distinguisher", "65001:100", false},
		{"vni RD invalid", "VLANVNI", "BGP_GLOBALS_EVPN_VNI|default|l2vpn_evpn|100", "route-distinguisher", "65001:*", false},
		{"vni noncanonical", "VLANVNI", "BGP_GLOBALS_EVPN_VNI|default|l2vpn_evpn|0100", "route-distinguisher", "65001:100", false},
		{"vni overflow", "VLANVNI", "BGP_GLOBALS_EVPN_VNI|default|l2vpn_evpn|16777216", "route-distinguisher", "65001:100", false},
		{"vni VRF", "VLANVNI", "BGP_GLOBALS_EVPN_VNI|VrfBlue|l2vpn_evpn|100", "route-distinguisher", "65001:100", false},
		{"vni RT invalid", "VLANVNI", "BGP_GLOBALS_EVPN_VNI_RT|default|l2vpn_evpn|100|65001:*", "route-target-type", "both", false},
		{"vni RT unknown type", "VLANVNI", "BGP_GLOBALS_EVPN_VNI_RT|default|l2vpn_evpn|100|65001:100", "route-target-type", "all", false},
		{"vni RT wrong AF", "VLANVNI", "BGP_GLOBALS_EVPN_VNI_RT|default|ipv4_unicast|100|65001:100", "route-target-type", "both", false},
		{"no global RT", "VLANVNI", "BGP_GLOBALS_EVPN_RT|default|l2vpn_evpn|65001:100", "route-target-type", "both", false},
		{"mapping missing name", "VLANVNI", "VXLAN_TUNNEL_MAP|vtep1", "vni", "100", false},
		{"mapping extra component", "VLANVNI", "VXLAN_TUNNEL_MAP|vtep1|map1|other", "vni", "100", false},
		{"no L3VNI", "VLANVNI", "VRF|VrfBlue", "vni", "100", false},
		{"peer AF", "EVPNPeer", "BGP_NEIGHBOR_AF|default|192.0.2.1|l2vpn_evpn", "admin_status", "down", true},
		{"peer AF up", "EVPNPeer", "BGP_NEIGHBOR_AF|default|2001:db8::1|l2vpn_evpn", "admin_status", "up", true},
		{"peer bad admin", "EVPNPeer", "BGP_NEIGHBOR_AF|default|192.0.2.1|l2vpn_evpn", "admin_status", "Up", false},
		{"peer no shared neighbor", "EVPNPeer", "BGP_NEIGHBOR|default|192.0.2.1", "admin_status", "up", false},
		{"peer no unicast AF", "EVPNPeer", "BGP_NEIGHBOR_AF|default|192.0.2.1|ipv4_unicast", "admin_status", "up", false},
		{"peer no VRF", "EVPNPeer", "BGP_NEIGHBOR_AF|VrfBlue|192.0.2.1|l2vpn_evpn", "admin_status", "up", false},
		{"peer no noncanonical IP", "EVPNPeer", "BGP_NEIGHBOR_AF|default|2001:0db8::1|l2vpn_evpn", "admin_status", "up", false},
		{"peer no raw field", "EVPNPeer", "BGP_NEIGHBOR_AF|default|192.0.2.1|l2vpn_evpn", "rawFields", "x", false},
		{"unknown kind", "CONFIG_DB", "BGP_NEIGHBOR_AF|default|192.0.2.1|l2vpn_evpn", "admin_status", "up", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateNetworkFields(tc.kind, vlanChangeDB{tc.key: {tc.field: tc.value}})
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
		})
	}
}

func TestNetworkRedundancyPlannerDispatch(t *testing.T) {
	t.Parallel()
	db := vlanChangeDB{
		"DEVICE_METADATA|localhost":                 {"frr_mgmt_framework_config": "true"},
		"BGP_GLOBALS|default":                       {"local_asn": "65001", "router_id": "192.0.2.1", "default_ipv4_unicast": "false", "default_shutdown": "false"},
		"LOOPBACK_INTERFACE|Loopback0|192.0.2.1/32": {"NULL": "NULL"},
		"VXLAN_TUNNEL|vtep1":                        {"src_ip": "192.0.2.1"},
		"VXLAN_EVPN_NVO|nvo1":                       {"source_vtep": "vtep1"},
		"VLAN|Vlan10":                               {"vlanid": "10"},
		"BGP_NEIGHBOR|default|192.0.2.2":            {"asn": "65002", "local_addr": "192.0.2.1", "admin_status": "down"},
	}
	for _, tc := range []struct{ kind, spec, identity string }{
		{"MLAG", `{"domainID":1,"peerSwitchRef":{"name":"peer"},"localAddress":"192.0.2.1","peerAddress":"192.0.2.2","peerLink":"PortChannel1","members":["PortChannel2"]}`, "MLAG|1"},
		{"VXLANTunnel", `{"name":"vtep1","sourceAddress":"192.0.2.1","evpnNVO":"nvo1"}`, "VXLANTunnel|vtep1"},
		{"VLANVNI", `{"tunnel":"vtep1","vlanID":10,"vni":100,"routeDistinguisher":"65001:100","importRouteTargets":["65001:100"],"exportRouteTargets":["65001:100"]}`, "VLANVNI|vtep1|10"},
		{"EVPNPeer", `{"address":"192.0.2.2","remoteASN":65002,"localAddress":"192.0.2.1","adminState":"Down"}`, "EVPNPeer|default|192.0.2.2"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			for _, suffix := range []string{"", `,"rawFields":{}`, `,"arbitraryTables":{}`} {
				spec := strings.TrimSuffix(tc.spec, "}") + suffix + "}"
				p, err := planNetworkResource(db, &agent.NetworkRequest{Kind: tc.kind, OwnerID: "uid", Spec: json.RawMessage(spec)})
				if suffix != "" {
					if err == nil {
						t.Fatal("planner accepted raw fields/tables")
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				if p.Identity != tc.identity || p.Preflight == nil || p.Runtime == nil || p.Activate != nil {
					t.Fatalf("planner contract: %+v", p)
				}
				if err := validateNetworkFields(tc.kind, p.Desired); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
