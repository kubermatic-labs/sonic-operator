//go:build integration

// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"encoding/json"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

func TestEVPNMappingSnapshotRequiresDurableOwner(t *testing.T) {
	m, _ := evpnRedisFixture(t)
	ctx := evpnTestCommands(t, evpnTestFRR+evpnTestVNI, nil)
	request := evpnTestRequest("VLANVNI", evpnTestMap)
	out, st := m.EnsureNetworkResource(ctx, request)
	if st != nil || !out.PersistenceVerified {
		t.Fatalf("mapping=%+v %v", out, st)
	}
	var spec evpnMapSpec
	if err := json.Unmarshal(request.Spec, &spec); err != nil {
		t.Fatal(err)
	}
	ref := agent.EVPNMappingSnapshot{Name: "mapping", UID: request.OwnerID, Generation: 1, Tunnel: spec.Tunnel, VLANID: spec.VLANID, VNI: spec.VNI, RouteDistinguisher: spec.RouteDistinguisher, ImportRouteTargets: spec.ImportRouteTargets, ExportRouteTargets: spec.ExportRouteTargets}
	db, _, err := m.vlanChangeSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := evpnOwnedMappings(m, db, []agent.EVPNMappingSnapshot{ref}); err != nil {
		t.Fatal(err)
	}
	ref.UID = "replacement-uid"
	if err := evpnOwnedMappings(m, db, []agent.EVPNMappingSnapshot{ref}); err == nil {
		t.Fatal("foreign mapping owner accepted")
	}
}

func TestEVPNGlobalRequiresOwnedPeerPolicy(t *testing.T) {
	m, db := evpnRedisFixture(t)
	p, err := evpnBuildPeerPolicy("foreign", "192.0.2.2", []string{"65001:100"}, []string{"65001:100"})
	if err != nil {
		t.Fatal(err)
	}
	for key, row := range p.Rows {
		if err := db.HSet(t.Context(), key, row).Err(); err != nil {
			t.Fatal(err)
		}
	}
	key := "BGP_NEIGHBOR_AF|default|192.0.2.2|l2vpn_evpn"
	if err := db.HSet(t.Context(), key, map[string]string{"admin_status": "down", "route_map_in@": p.In, "route_map_out@": p.Out, "send_community": "extended"}).Err(); err != nil {
		t.Fatal(err)
	}
	snapshot, _, err := m.vlanChangeSnapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := evpnOwnedPolicy(m, snapshot, "192.0.2.2"); err == nil {
		t.Fatal("foreign native policy treated as durable peer ownership")
	}
}
