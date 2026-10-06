// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"encoding/json"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

func TestEVPNPeerPolicyStaging(t *testing.T) {
	db := evpnTestDB()
	p, err := planNetworkVLANVNI(db, evpnTestRequest("VLANVNI", evpnTestMap))
	if err != nil {
		t.Fatal(err)
	}
	for key, row := range p.Desired {
		db[key] = row
	}
	var mapping evpnMapSpec
	if err := json.Unmarshal([]byte(evpnTestMap), &mapping); err != nil {
		t.Fatal(err)
	}
	var peer map[string]any
	if err := json.Unmarshal([]byte(evpnTestPeer), &peer); err != nil {
		t.Fatal(err)
	}
	peer["mappingRefs"] = []map[string]string{{"name": "mapping"}}
	peer["mappings"] = []agent.EVPNMappingSnapshot{{Name: "mapping", UID: "mapping-uid", Generation: 1, Tunnel: mapping.Tunnel, VLANID: mapping.VLANID, VNI: mapping.VNI, RouteDistinguisher: mapping.RouteDistinguisher, ImportRouteTargets: mapping.ImportRouteTargets, ExportRouteTargets: mapping.ExportRouteTargets}}
	raw, err := json.Marshal(peer)
	if err != nil {
		t.Fatal(err)
	}
	p, err = planNetworkEVPNPeer(db, evpnTestRequest("EVPNPeer", string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	af := p.Desired["BGP_NEIGHBOR_AF|default|192.0.2.2|l2vpn_evpn"]
	if af["route_map_in@"] == "" || af["route_map_out@"] == "" || af["send_community"] != "extended" || af["admin_status"] != "down" {
		t.Fatalf("missing staged policy: %v", af)
	}
	if err := validateNetworkFields("EVPNPeer", p.Desired); err != nil {
		t.Fatal(err)
	}
	for key, row := range p.Desired {
		db[key] = row
	}
	if _, err := planNetworkEVPNPeer(db, evpnTestRequest("EVPNPeer", string(raw))); err != nil {
		t.Fatalf("cannot reobserve staged policy: %v", err)
	}
	peer["adminState"] = "Up"
	raw, err = json.Marshal(peer)
	if err != nil {
		t.Fatal(err)
	}
	db[evpnGlobalKey] = evpnGlobalFields(true)
	p, err = planNetworkEVPNPeer(db, evpnTestRequest("EVPNPeer", string(raw)))
	if err != nil || p == nil || p.Desired["BGP_NEIGHBOR_AF|default|192.0.2.2|l2vpn_evpn"]["admin_status"] != "up" {
		t.Fatalf("staged activation: %+v %v", p, err)
	}
}

func TestEVPNTransitPeerHasNoLocalVTEPDependency(t *testing.T) {
	db := evpnTestDB()
	delete(db, "VXLAN_TUNNEL|vtep1")
	delete(db, "VXLAN_EVPN_NVO|nvo1")
	r := evpnTestRequest("EVPNPeer", `{"address":"192.0.2.2","remoteASN":65002,"localAddress":"192.0.2.1","role":"Transit","importRouteTargets":["65001:100"],"exportRouteTargets":["65001:100"],"adminState":"Down"}`)
	p, err := planNetworkEVPNPeer(db, r)
	if err != nil {
		t.Fatal(err)
	}
	af := p.Desired["BGP_NEIGHBOR_AF|default|192.0.2.2|l2vpn_evpn"]
	if af["unchanged_nexthop"] != "true" || af["route_map_in@"] == "" {
		t.Fatalf("transit must filter and retain VTEP: %v", af)
	}
}

func TestEVPNTransitRejectsUnresolvedLocalReferences(t *testing.T) {
	r := evpnTestRequest("EVPNPeer", `{"address":"192.0.2.2","remoteASN":65002,"localAddress":"192.0.2.1","role":"Transit","mappingRefs":[{"name":"mapping"}],"importRouteTargets":["65001:100"],"exportRouteTargets":["65001:100"]}`)
	if _, err := planNetworkEVPNPeer(evpnTestDB(), r); err == nil {
		t.Fatal("transit local mapping accepted")
	}
}

func TestEVPNPeerRejectsDuplicateNestedReference(t *testing.T) {
	r := evpnTestRequest("EVPNPeer", `{"address":"192.0.2.2","remoteASN":65002,"localAddress":"192.0.2.1","role":"Transit","importRouteTargets":["65001:100"],"exportRouteTargets":["65001:100"],"mappingRefs":[{"name":"one","name":"two"}]}`)
	if _, err := planNetworkEVPNPeer(evpnTestDB(), r); err == nil {
		t.Fatal("duplicate nested reference accepted")
	}
}

func TestEVPNTransitPolicyCannotChangeOnLiveParent(t *testing.T) {
	db := evpnTestDB()
	r := evpnTestRequest("EVPNPeer", `{"address":"192.0.2.2","remoteASN":65002,"localAddress":"192.0.2.1","role":"Transit","importRouteTargets":["65001:100"],"exportRouteTargets":["65001:100"],"adminState":"Down"}`)
	p, err := planNetworkEVPNPeer(db, r)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range p.Desired {
		db[k] = v
	}
	db["BGP_NEIGHBOR|default|192.0.2.2"]["admin_status"] = "up"
	// A partial attachment is a policy edit even when definitions already exist.
	delete(db["BGP_NEIGHBOR_AF|default|192.0.2.2|l2vpn_evpn"], "route_map_out@")
	if _, err := planNetworkEVPNPeer(db, r); err == nil {
		t.Fatal("policy repair on live parent accepted")
	}
}
