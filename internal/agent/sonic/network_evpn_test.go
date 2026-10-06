// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

const evpnTestMap = `{"tunnel":"vtep1","vlanID":10,"vni":100,"routeDistinguisher":"65001:100","importRouteTargets":["65001:100"],"exportRouteTargets":["65001:100","65001:101"]}`
const evpnTestPeer = `{"address":"192.0.2.2","remoteASN":65002,"localAddress":"192.0.2.1","adminState":"Down"}`
const evpnTestTunnel = `{"name":"vtep1","sourceAddress":"192.0.2.1","evpnNVO":"nvo1"}`
const evpnTestFRR = "router bgp 65001\n bgp router-id 192.0.2.1\n bgp default shutdown\n no bgp default ipv4-unicast\n neighbor 192.0.2.2 remote-as 65002\n neighbor 192.0.2.2 update-source 192.0.2.1\n neighbor 192.0.2.2 shutdown\n"
const evpnTestVNI = " address-family l2vpn evpn\n  vni 100\n   rd 65001:100\n   route-target both 65001:100\n   route-target export 65001:101\n  exit-vni\n exit-address-family\n"

func evpnTestDB() vlanChangeDB {
	return vlanChangeDB{
		"DEVICE_METADATA|localhost":                 {"frr_mgmt_framework_config": "true"},
		"BGP_GLOBALS|default":                       {"local_asn": "65001", "router_id": "192.0.2.1", "default_ipv4_unicast": "false", "default_shutdown": "true"},
		"BGP_NEIGHBOR|default|192.0.2.2":            {"asn": "65002", "local_addr": "192.0.2.1", "admin_status": "down"},
		"LOOPBACK_INTERFACE|Loopback0|192.0.2.1/32": {"NULL": "NULL"},
		"PORT|Ethernet0":                            {"admin_status": "up"},
		"INTERFACE|Ethernet0|198.51.100.1/30":       {"NULL": "NULL"},
		"VLAN|Vlan10":                               {"vlanid": "10"},
		"VXLAN_TUNNEL|vtep1":                        {"src_ip": "192.0.2.1"},
		"VXLAN_EVPN_NVO|nvo1":                       {"source_vtep": "vtep1"},
	}
}

func evpnTestRequest(kind, spec string) *agent.NetworkRequest {
	return &agent.NetworkRequest{Kind: kind, OwnerID: "evpn-owner", Spec: json.RawMessage(spec)}
}

func TestEVPNPlannerNativeContract(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, kind, spec, identity string }{
		{"tunnel", "VXLANTunnel", evpnTestTunnel, "VXLANTunnel|vtep1"},
		{"mapping", "VLANVNI", evpnTestMap, "VLANVNI|vtep1|10"},
		{"peer AF only", "EVPNPeer", evpnTestPeer, "EVPNPeer|default|192.0.2.2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := evpnTestDB()
			p, err := planNetworkResource(db, evpnTestRequest(tc.kind, tc.spec))
			if err != nil {
				t.Fatal(err)
			}
			if p.Identity != tc.identity || p.Preflight == nil || p.Runtime == nil || p.Activate != nil {
				t.Fatalf("unsafe plan: %+v", p)
			}
			if err := validateNetworkFields(tc.kind, p.Desired); err != nil {
				t.Fatal(err)
			}
			if tc.kind == "EVPNPeer" && !reflect.DeepEqual(p.Desired, vlanChangeDB{"BGP_NEIGHBOR_AF|default|192.0.2.2|l2vpn_evpn": {"admin_status": "down"}}) {
				t.Fatal("peer claims shared neighbor fields")
			}
			if tc.kind == "VLANVNI" {
				if p.Desired["BGP_GLOBALS_EVPN_VNI_RT|default|l2vpn_evpn|100|65001:100"]["route-target-type"] != "both" || p.Desired["BGP_GLOBALS_EVPN_VNI_RT|default|l2vpn_evpn|100|65001:101"]["route-target-type"] != "export" {
					t.Fatal("wrong native RT encoding")
				}
			}
			post := maps.Clone(db)
			for key, row := range p.Desired {
				post[key] = maps.Clone(row)
			}
			again, err := planNetworkResource(post, evpnTestRequest(tc.kind, tc.spec))
			if err != nil || !reflect.DeepEqual(p.Desired, again.Desired) {
				t.Fatalf("post-state recovery changed plan: %v", err)
			}
		})
	}
}

func TestEVPNRejectUnsafeSpecsAndDependencies(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, kind, spec string
		mutate           func(vlanChangeDB)
	}{
		{"unknown field", "VLANVNI", strings.TrimSuffix(evpnTestMap, "}") + `,"gateway":"192.0.2.1"}`, nil},
		{"duplicate field", "VLANVNI", strings.TrimSuffix(evpnTestMap, "}") + `,"vni":101}`, nil},
		{"case folded field", "VLANVNI", strings.Replace(evpnTestMap, "vni", "VNI", 1), nil},
		{"null RT", "VLANVNI", strings.Replace(evpnTestMap, `["65001:100"]`, `null`, 1), nil},
		{"auto RD", "VLANVNI", strings.Replace(evpnTestMap, `"routeDistinguisher":"65001:100"`, `"routeDistinguisher":"auto"`, 1), nil},
		{"duplicate RT", "VLANVNI", strings.Replace(evpnTestMap, `["65001:100"]`, `["65001:100","65001:100"]`, 1), nil},
		{"empty export RT", "VLANVNI", strings.Replace(evpnTestMap, `["65001:100","65001:101"]`, `[]`, 1), nil},
		{"management source", "VXLANTunnel", evpnTestTunnel, func(db vlanChangeDB) { db["MGMT_INTERFACE|eth0|192.0.2.1/24"] = map[string]string{"NULL": "NULL"} }},
		{"unconfigured source", "VXLANTunnel", evpnTestTunnel, func(db vlanChangeDB) { delete(db, "LOOPBACK_INTERFACE|Loopback0|192.0.2.1/32") }},
		{"other VRF source", "VXLANTunnel", evpnTestTunnel, func(db vlanChangeDB) { db["LOOPBACK_INTERFACE|Loopback0"] = map[string]string{"vrf_name": "VrfOther"} }},
		{"missing VLAN", "VLANVNI", evpnTestMap, func(db vlanChangeDB) { delete(db, "VLAN|Vlan10") }},
		{"missing tunnel", "VLANVNI", evpnTestMap, func(db vlanChangeDB) { delete(db, "VXLAN_TUNNEL|vtep1") }},
		{"missing NVO", "VLANVNI", evpnTestMap, func(db vlanChangeDB) { delete(db, "VXLAN_EVPN_NVO|nvo1") }},
		{"duplicate VNI", "VLANVNI", evpnTestMap, func(db vlanChangeDB) {
			db["VXLAN_TUNNEL_MAP|vtep1|other"] = map[string]string{"vni": "100", "vlan": "Vlan20"}
		}},
		{"duplicate VLAN", "VLANVNI", evpnTestMap, func(db vlanChangeDB) {
			db["VXLAN_TUNNEL_MAP|vtep1|other"] = map[string]string{"vni": "200", "vlan": "Vlan10"}
		}},
		{"duplicate RD", "VLANVNI", evpnTestMap, func(db vlanChangeDB) {
			db["BGP_GLOBALS_EVPN_VNI|default|l2vpn_evpn|200"] = map[string]string{"route-distinguisher": "65001:100"}
		}},
		{"shared RT", "VLANVNI", evpnTestMap, func(db vlanChangeDB) {
			db["BGP_GLOBALS_EVPN_VNI_RT|default|l2vpn_evpn|200|65001:100"] = map[string]string{"route-target-type": "both"}
		}},
		{"extra RT", "VLANVNI", evpnTestMap, func(db vlanChangeDB) {
			db["BGP_GLOBALS_EVPN_VNI_RT|default|l2vpn_evpn|100|65001:999"] = map[string]string{"route-target-type": "export"}
		}},
		{"SVI", "VLANVNI", evpnTestMap, func(db vlanChangeDB) { db["VLAN_INTERFACE|Vlan10|10.0.0.1/24"] = map[string]string{"NULL": "NULL"} }},
		{"L3VNI", "VLANVNI", evpnTestMap, func(db vlanChangeDB) { db["VRF|VrfBlue"] = map[string]string{"vni": "100"} }},
		{"global advertisements", "VLANVNI", evpnTestMap, func(db vlanChangeDB) {
			db["BGP_GLOBALS_AF|default|l2vpn_evpn"] = map[string]string{"advertise-all-vni": "true"}
		}},
		{"peer Up fails before plan", "EVPNPeer", strings.Replace(evpnTestPeer, "Down", "Up", 1), nil},
		{"missing staged peer", "EVPNPeer", evpnTestPeer, func(db vlanChangeDB) { delete(db, "BGP_NEIGHBOR|default|192.0.2.2") }},
		{"wrong ASN", "EVPNPeer", evpnTestPeer, func(db vlanChangeDB) { db["BGP_NEIGHBOR|default|192.0.2.2"]["asn"] = "65003" }},
		{"enabled shared neighbor", "EVPNPeer", evpnTestPeer, func(db vlanChangeDB) { db["BGP_NEIGHBOR|default|192.0.2.2"]["admin_status"] = "up" }},
		{"foreign AF policy", "EVPNPeer", evpnTestPeer, func(db vlanChangeDB) {
			db["BGP_NEIGHBOR_AF|default|192.0.2.2|l2vpn_evpn"] = map[string]string{"admin_status": "down", "route_map_out": "Foreign"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := evpnTestDB()
			if tc.mutate != nil {
				tc.mutate(db)
			}
			p, err := planNetworkResource(db, evpnTestRequest(tc.kind, tc.spec))
			if err == nil || p != nil {
				t.Fatalf("unsafe plan accepted: %+v", p)
			}
		})
	}
}

func TestEVPNRDEncoding(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, value string
		valid       bool
	}{
		{"AS2 max", "65535:4294967295", true}, {"AS4 max", "4294967295:65535", true}, {"IPv4 max", "192.0.2.1:65535", true},
		{"AS4 overflow", "65536:65536", false}, {"IPv4 overflow", "192.0.2.1:65536", false}, {"wildcard", "65001:*", false}, {"injection", "65001:1\nexit", false}, {"noncanonical", "065001:1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if (evpnRD(tc.value) == nil) != tc.valid {
				t.Fatal("unexpected RD validation")
			}
		})
	}
}

func evpnTestCommands(t *testing.T, config string, override func(*exec.Cmd) ([]byte, error, bool)) context.Context {
	t.Helper()
	ctx := context.WithValue(t.Context(), routingCommandRunnerKey{}, routingCommandRunner(func(cmd *exec.Cmd) ([]byte, error) {
		if strings.Contains(strings.Join(cmd.Args, " "), "show running-config") {
			return []byte(config), nil
		}
		if strings.Contains(strings.Join(cmd.Args, " "), "supervisorctl status") {
			return []byte("frrcfgd RUNNING\nbgpd RUNNING\nzebra RUNNING\n"), nil
		}
		return nil, errors.New("unexpected routing command")
	}))
	return context.WithValue(ctx, evpnCommandRunnerKey{}, evpnCommandRunner(func(cmd *exec.Cmd) ([]byte, error) {
		if override != nil {
			if data, err, ok := override(cmd); ok {
				return data, err
			}
		}
		args := strings.Join(cmd.Args, " ")
		switch {
		case strings.Contains(args, "sha256sum /usr/local/lib/"):
			return []byte(evpnFRRHash + "  /usr/local/lib/python3.11/dist-packages/frrcfgd/frrcfgd.py\n"), nil
		case strings.Contains(args, "sha256sum /usr/local/yang-models/"):
			return []byte(evpnYANGHash + "  /usr/local/yang-models/sonic-vxlan.yang\n"), nil
		case strings.Contains(args, "show version"):
			return []byte("FRRouting 10.4.1 (fixture)"), nil
		case strings.Contains(args, "supervisorctl status"):
			return []byte("frrcfgd RUNNING\nbgpd RUNNING\nzebra RUNNING\norchagent RUNNING\nvxlanmgrd RUNNING\n"), nil
		case args == "ip -j -4 address show dev Loopback0":
			return []byte(`[{"ifname":"Loopback0","flags":["UP"],"addr_info":[{"local":"192.0.2.1","scope":"global"}]}]`), nil
		case args == "ip -j -4 route get 192.0.2.2 from 192.0.2.1":
			return []byte(`[{"dev":"Ethernet0","from":"192.0.2.1"}]`), nil
		case args == "ip -j link show dev Ethernet0":
			return []byte(`[{"ifname":"Ethernet0","operstate":"UP","flags":["UP","LOWER_UP"]}]`), nil
		default:
			return nil, errors.New("unexpected EVPN command: " + args)
		}
	}))
}

func TestEVPNNativeAndUnderlay(t *testing.T) {
	t.Parallel()
	ctx := evpnTestCommands(t, evpnTestFRR, nil)
	if err := evpnNative(ctx); err != nil {
		t.Fatal(err)
	}
	if err := evpnUnderlay(ctx, evpnTestDB(), "192.0.2.1", ""); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, match, response string }{
		{"different consumer", "sha256sum", "deadbeef file"},
		{"daemon down", "supervisorctl", "frrcfgd STOPPED\nbgpd RUNNING"},
		{"different FRR", "show version", "FRRouting 9.0"},
		{"source absent", "address show", `[{"ifname":"Loopback0","flags":["UP"],"addr_info":[]}]`},
		{"management route", "route get", `[{"dev":"eth0","from":"192.0.2.1"}]`},
		{"wrong source", "route get", `[{"dev":"Ethernet0","from":"10.1.1.1"}]`},
		{"unreachable", "route get", `[{"dev":"Ethernet0","from":"192.0.2.1","type":"unreachable"}]`},
		{"link down", "route get", `[{"dev":"Ethernet0","from":"192.0.2.1","flags":["linkdown"]}]`},
		{"no carrier", "link show", `[{"ifname":"Ethernet0","operstate":"DOWN","flags":["UP"]}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := evpnTestCommands(t, evpnTestFRR, func(cmd *exec.Cmd) ([]byte, error, bool) {
				if strings.Contains(strings.Join(cmd.Args, " "), tc.match) {
					return []byte(tc.response), nil, true
				}
				return nil, nil, false
			})
			err := evpnNative(ctx)
			if err == nil {
				err = evpnUnderlay(ctx, evpnTestDB(), "192.0.2.1", "")
			}
			if err == nil {
				t.Fatal("unsafe native/underlay evidence accepted")
			}
		})
	}
}

func TestEVPNFRRIsolationAndVNIScope(t *testing.T) {
	t.Parallel()
	var s evpnMapSpec
	if err := json.Unmarshal([]byte(evpnTestMap), &s); err != nil {
		t.Fatal(err)
	}
	if _, err := evpnFRRParse([]byte(evpnTestFRR+evpnTestVNI), evpnTestDB()); err != nil {
		t.Fatal(err)
	}
	if err := evpnFRRVNI([]byte(evpnTestFRR+evpnTestVNI), "65001", s, true); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, config string }{
		{"enabled neighbor", strings.Replace(evpnTestFRR, " neighbor 192.0.2.2 shutdown\n", "", 1)},
		{"active AF", evpnTestFRR + " address-family l2vpn evpn\n  neighbor 192.0.2.2 activate\n"},
		{"global RT", evpnTestFRR + " address-family l2vpn evpn\n  route-target export 65001:999\n"},
		{"all VNIs", evpnTestFRR + " address-family l2vpn evpn\n  advertise-all-vni\n"},
		{"IRB", evpnTestFRR + strings.Replace(evpnTestVNI, "   rd 65001:100", "   advertise-default-gw", 1)},
		{"wrong VRF", strings.Replace(evpnTestFRR, "router bgp 65001", "router bgp 65001 vrf VrfOther", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := evpnFRRParse([]byte(tc.config), evpnTestDB()); err == nil {
				t.Fatal("unsafe FRR state accepted")
			}
		})
	}
	for _, tc := range []struct{ name, config string }{
		{"wrong VNI", evpnTestFRR + strings.Replace(evpnTestVNI, "vni 100", "vni 200", 1)},
		{"wrong RD", evpnTestFRR + strings.Replace(evpnTestVNI, "rd 65001:100", "rd 65001:200", 1)},
		{"extra RT", evpnTestFRR + strings.Replace(evpnTestVNI, "  exit-vni", "   route-target export 65001:999\n  exit-vni", 1)},
		{"wrong instance", strings.Replace(evpnTestFRR, "router bgp 65001", "router bgp 65001 vrf VrfOther", 1) + evpnTestVNI},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := evpnFRRVNI([]byte(tc.config), "65001", s, true); err == nil {
				t.Fatal("uncorrelated VNI accepted")
			}
		})
	}
}
