// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"maps"
	"strings"
	"testing"
)

func TestEVPNOperationalPolicyContract(t *testing.T) {
	db := evpnTestDB()
	p, err := evpnBuildPeerPolicy("owner", "192.0.2.2", []string{"65001:100"}, []string{"65001:100"})
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range p.Rows {
		db[k] = v
	}
	db[evpnGlobalKey] = evpnGlobalFields(true)
	db["BGP_NEIGHBOR_AF|default|192.0.2.2|l2vpn_evpn"] = map[string]string{"admin_status": "up", "route_map_in@": p.In, "route_map_out@": p.Out, "send_community": "extended"}
	db["BGP_NEIGHBOR|default|192.0.2.2"]["admin_status"] = "up"
	if err := evpnSafeConfig(db); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(vlanChangeDB){
		func(d vlanChangeDB) { d["ROUTE_MAP|"+p.In+"|65535"] = map[string]string{"route_operation": "permit"} },
		func(d vlanChangeDB) { d["ROUTE_MAP|"+p.In+"|20"] = map[string]string{"route_operation": "permit"} },
		func(d vlanChangeDB) { delete(d, "EXTENDED_COMMUNITY_SET|"+p.Out) },
		func(d vlanChangeDB) {
			d[evpnGlobalKey] = map[string]string{"advertise-all-vni": "true", "advertise-svi-ip": "true"}
		},
	} {
		bad := maps.Clone(db)
		edit(bad)
		if err := evpnSafeConfig(bad); err == nil {
			t.Fatal("unsafe operational config accepted")
		}
	}
}

func TestEVPNOperationalFRRReadback(t *testing.T) {
	db := evpnTestDB()
	p, err := evpnBuildPeerPolicy("owner", "192.0.2.2", []string{"65001:100"}, []string{"65001:100"})
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range p.Rows {
		db[k] = v
	}
	db[evpnGlobalKey] = evpnGlobalFields(true)
	db["BGP_NEIGHBOR_AF|default|192.0.2.2|l2vpn_evpn"] = map[string]string{"admin_status": "up", "route_map_in@": p.In, "route_map_out@": p.Out, "send_community": "extended"}
	db["BGP_NEIGHBOR|default|192.0.2.2"]["admin_status"] = "up"
	config := strings.ReplaceAll(evpnTestFRR, " neighbor 192.0.2.2 shutdown\n", "") + " address-family l2vpn evpn\n  advertise-all-vni\n  neighbor 192.0.2.2 activate\n  neighbor 192.0.2.2 route-map " + p.In + " in\n  neighbor 192.0.2.2 route-map " + p.Out + " out\n  neighbor 192.0.2.2 send-community extended\n exit-address-family\n"
	for _, name := range []string{p.In, p.Out} {
		config += "bgp extcommunity-list standard " + name + " permit rt 65001:100\nroute-map " + name + " permit 10\n match extcommunity " + name + "\n!\nroute-map " + name + " deny 65535\n!\n"
	}
	if _, err := evpnFRRParse([]byte(config), db); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.ReplaceAll(config, "deny 65535", "permit 65535"), strings.ReplaceAll(config, "  advertise-all-vni", "  advertise-default-gw"), strings.ReplaceAll(config, "  neighbor 192.0.2.2 route-map "+p.Out+" out\n", "")} {
		if _, err := evpnFRRParse([]byte(bad), db); err == nil {
			t.Fatal("unsafe live FRR accepted")
		}
	}
}

func TestEVPNParentActivationRequiresAppliedPolicy(t *testing.T) {
	db := evpnTestDB()
	if err := evpnParentActivation(t.Context(), &SonicAgent{}, db, "192.0.2.2"); err == nil {
		t.Fatal("parent activation without EVPN policy accepted")
	}
}

func TestEVPNMappingChangesRequirePeerShutdown(t *testing.T) {
	db := evpnTestDB()
	db[evpnGlobalKey] = evpnGlobalFields(true)
	db["BGP_NEIGHBOR|default|192.0.2.2"]["admin_status"] = "up"
	if _, err := planNetworkVLANVNI(db, evpnTestRequest("VLANVNI", evpnTestMap)); err == nil {
		t.Fatal("new mapping permitted while advertise-all-vni is enabled")
	}
}
