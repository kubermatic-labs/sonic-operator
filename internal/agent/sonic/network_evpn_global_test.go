// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"encoding/json"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

func TestEVPNGlobalDisabledNativeContract(t *testing.T) {
	db := evpnTestDB()
	p, err := planNetworkResource(db, evpnTestRequest("EVPN", `{"tunnel":"vtep1","adminState":"Down"}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Identity != "EVPN|default" || p.Desired["BGP_GLOBALS_AF|default|l2vpn_evpn"]["advertise-all-vni"] != "false" || p.Preflight == nil || p.Runtime == nil {
		t.Fatalf("invalid global plan: %+v", p)
	}
	if err := validateNetworkFields("EVPN", p.Desired); err != nil {
		t.Fatal(err)
	}
	if _, err := planNetworkResource(db, evpnTestRequest("EVPN", `{"tunnel":"vtep1","adminState":"Up"}`)); err == nil {
		t.Fatal("global activation without mapping/policy allowed")
	}
}

func TestEVPNGlobalUpWithExplicitMappings(t *testing.T) {
	db := evpnTestDB()
	m, err := planNetworkVLANVNI(db, evpnTestRequest("VLANVNI", evpnTestMap))
	if err != nil {
		t.Fatal(err)
	}
	for key, row := range m.Desired {
		db[key] = row
	}
	var mapping evpnMapSpec
	if err := json.Unmarshal([]byte(evpnTestMap), &mapping); err != nil {
		t.Fatal(err)
	}
	s := evpnGlobalSpec{Tunnel: "vtep1", AdminState: "Up", Mappings: []agent.EVPNMappingSnapshot{{Name: "mapping", UID: "mapping-uid", Generation: 1, Tunnel: mapping.Tunnel, VLANID: mapping.VLANID, VNI: mapping.VNI, RouteDistinguisher: mapping.RouteDistinguisher, ImportRouteTargets: mapping.ImportRouteTargets, ExportRouteTargets: mapping.ExportRouteTargets}}}
	s.MappingRefs = append(s.MappingRefs, struct {
		Name string `json:"name"`
	}{Name: "mapping"})
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	p, err := planNetworkResource(db, evpnTestRequest("EVPN", string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if p.Desired[evpnGlobalKey]["advertise-all-vni"] != "true" {
		t.Fatal("global activation not planned")
	}
	db["VXLAN_TUNNEL_MAP|vtep1|map_999_Vlan20"] = map[string]string{"vlan": "Vlan20", "vni": "999"}
	if _, err := planNetworkResource(db, evpnTestRequest("EVPN", string(raw))); err == nil {
		t.Fatal("undeclared mapping accepted")
	}
}
