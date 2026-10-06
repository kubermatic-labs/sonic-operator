// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"maps"
	"strings"
	"testing"
)

func evpnCoexistFixture(t *testing.T) vlanChangeDB {
	t.Helper()
	db := evpnTestDB()
	maps.Copy(db, routingExportPolicy("default", nil))
	p, err := planNetworkVLANVNI(db, evpnTestRequest("VLANVNI", evpnTestMap))
	if err != nil {
		t.Fatal(err)
	}
	maps.Copy(db, p.Desired)
	db["BGP_NEIGHBOR_AF|default|192.0.2.2|l2vpn_evpn"] = map[string]string{"admin_status": "down"}
	return db
}

const evpnCoexistBGP = `{"localASN":65001,"routerID":"192.0.2.1"}`
const evpnCoexistBGPPeer = `{"address":"192.0.2.2","remoteASN":65002,"localAddress":"192.0.2.1","addressFamilies":["ipv4Unicast"],"adminState":"Down"}`

func TestEVPNUnicastCoexistValidation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		mutate func(vlanChangeDB)
	}{
		{"isolated", nil},
		{"missing export", func(db vlanChangeDB) {
			db["BGP_GLOBALS_EVPN_VNI_RT|default|l2vpn_evpn|100|65001:100"]["route-target-type"] = "import"
			delete(db, "BGP_GLOBALS_EVPN_VNI_RT|default|l2vpn_evpn|100|65001:101")
		}},
		{"missing RD", func(db vlanChangeDB) { delete(db, "BGP_GLOBALS_EVPN_VNI|default|l2vpn_evpn|100") }},
		{"unsupported VNI field", func(db vlanChangeDB) {
			db["BGP_GLOBALS_EVPN_VNI|default|l2vpn_evpn|100"]["advertise-default-gw"] = "true"
		}},
		{"unsupported RT field", func(db vlanChangeDB) {
			db["BGP_GLOBALS_EVPN_VNI_RT|default|l2vpn_evpn|100|65001:100"]["future"] = "true"
		}},
		{"orphan VNI", func(db vlanChangeDB) {
			db["BGP_GLOBALS_EVPN_VNI|default|l2vpn_evpn|200"] = map[string]string{"route-distinguisher": "65001:200"}
		}},
		{"orphan RT", func(db vlanChangeDB) {
			db["BGP_GLOBALS_EVPN_VNI_RT|default|l2vpn_evpn|200|65001:200"] = map[string]string{"route-target-type": "both"}
		}},
		{"global RT", func(db vlanChangeDB) {
			db["BGP_GLOBALS_EVPN_RT|default|l2vpn_evpn|65001:100"] = map[string]string{"route-target-type": "both"}
		}},
		{"active EVPN AF", func(db vlanChangeDB) { db["BGP_NEIGHBOR_AF|default|192.0.2.2|l2vpn_evpn"]["admin_status"] = "up" }},
		{"AF unknown field", func(db vlanChangeDB) {
			db["BGP_NEIGHBOR_AF|default|192.0.2.2|l2vpn_evpn"]["route_map_out"] = "unchecked"
		}},
		{"AF wrong VRF", func(db vlanChangeDB) {
			db["BGP_NEIGHBOR_AF|VrfOther|192.0.2.2|l2vpn_evpn"] = map[string]string{"admin_status": "down"}
		}},
		{"AF wrong case", func(db vlanChangeDB) {
			db["BGP_NEIGHBOR_AF|default|192.0.2.2|L2VPN_EVPN"] = map[string]string{"admin_status": "down"}
		}},
		{"AF missing neighbor", func(db vlanChangeDB) { delete(db, "BGP_NEIGHBOR|default|192.0.2.2") }},
		{"inherited peer", func(db vlanChangeDB) { db["BGP_NEIGHBOR|default|192.0.2.2"]["peer_group_name"] = "group" }},
		{"SVI", func(db vlanChangeDB) { db["VLAN_INTERFACE|Vlan10"] = map[string]string{"NULL": "NULL"} }},
		{"redistribute unicast", func(db vlanChangeDB) {
			db["ROUTE_REDISTRIBUTE|default|connected"] = map[string]string{"protocol": "connected"}
		}},
		{"unrequested network", func(db vlanChangeDB) {
			db["BGP_GLOBALS_AF_NETWORK|default|ipv4_unicast|203.0.113.0/24"] = map[string]string{"backdoor": "false"}
		}},
		{"unicast import", func(db vlanChangeDB) {
			db["BGP_GLOBALS_AF|default|ipv4_unicast"] = map[string]string{"import_vrf": "VrfOther"}
		}},
		{"extra export permit", func(db vlanChangeDB) {
			db["PREFIX|"+routingExportName("default", "ipv4_unicast")+"|100|203.0.113.0/24|exact"] = map[string]string{"action": "permit"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, request := range []struct{ kind, spec string }{{"BGP", evpnCoexistBGP}, {"BGPPeer", evpnCoexistBGPPeer}} {
				db := evpnCoexistFixture(t)
				if tc.mutate != nil {
					tc.mutate(db)
				}
				p, err := planNetworkResource(db, evpnTestRequest(request.kind, request.spec))
				if tc.mutate != nil {
					if err == nil {
						t.Fatalf("%s accepted unsafe coexistence", request.kind)
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				for key := range p.Desired {
					if strings.Contains(key, "EVPN") || strings.HasSuffix(key, "|l2vpn_evpn") || strings.HasPrefix(key, "VXLAN_") {
						t.Fatalf("unicast owner claimed EVPN field %s", key)
					}
				}
			}
		})
	}
	if _, err := planNetworkBGPPeer(evpnCoexistFixture(t), evpnTestRequest("BGPPeer", strings.Replace(evpnCoexistBGPPeer, "Down", "Up", 1))); err == nil {
		t.Fatal("shared neighbor activation bypassed staged EVPN guard")
	}
}

func TestEVPNCoexistRuntimeRejectsUnsafePolicy(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, config string
		valid        bool
	}{
		{"isolated", evpnTestFRR + evpnTestVNI, true},
		{"AF disabled explicitly", evpnTestFRR + strings.Replace(evpnTestVNI, " address-family l2vpn evpn\n", " address-family l2vpn evpn\n  no neighbor 192.0.2.2 activate\n", 1), true},
		{"active AF", evpnTestFRR + strings.Replace(evpnTestVNI, " address-family l2vpn evpn\n", " address-family l2vpn evpn\n  neighbor 192.0.2.2 activate\n", 1), false},
		{"missing VNI", evpnTestFRR, false},
		{"wrong RT", evpnTestFRR + strings.Replace(evpnTestVNI, "65001:101", "65001:999", 1), false},
		{"foreign VNI", evpnTestFRR + strings.Replace(evpnTestVNI, " exit-address-family", "  vni 200\n   rd 65001:200\n  exit-vni\n exit-address-family", 1), false},
		{"global advertise", evpnTestFRR + strings.Replace(evpnTestVNI, " address-family l2vpn evpn\n", " address-family l2vpn evpn\n  advertise-all-vni\n", 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := evpnTestCommands(t, tc.config, nil)
			err := evpnCoexistRuntime(ctx, runRoutingRead, evpnCoexistFixture(t))
			if (err == nil) != tc.valid {
				t.Fatalf("runtime policy: %v", err)
			}
		})
	}
}

func TestEVPNSVIReversePlannerInvariant(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, vlan string
		valid      bool
	}{{"same VLAN", "Vlan10", false}, {"prefix neighbor", "Vlan100", true}} {
		t.Run(tc.name, func(t *testing.T) {
			db := evpnTestDB()
			db["VXLAN_TUNNEL_MAP|foreign|any-name"] = map[string]string{"vlan": tc.vlan, "vni": "100"}
			_, err := planNetworkL3Interface(db, evpnTestRequest("L3Interface", `{"name":"Vlan10","addresses":["203.0.113.1/24"]}`))
			if (err == nil) != tc.valid {
				t.Fatalf("SVI reverse guard: %v", err)
			}
		})
	}
}
