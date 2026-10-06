// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"encoding/json"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

func TestEVPNMappingSnapshotValidation(t *testing.T) {
	db := evpnTestDB()
	var spec evpnMapSpec
	if err := json.Unmarshal([]byte(evpnTestMap), &spec); err != nil {
		t.Fatal(err)
	}
	plan, err := planNetworkVLANVNI(db, evpnTestRequest("VLANVNI", evpnTestMap))
	if err != nil {
		t.Fatal(err)
	}
	for key, row := range plan.Desired {
		db[key] = row
	}
	ref := agent.EVPNMappingSnapshot{Name: "mapping", UID: "mapping-uid", Generation: 1, Tunnel: spec.Tunnel, VLANID: spec.VLANID, VNI: spec.VNI, RouteDistinguisher: spec.RouteDistinguisher, ImportRouteTargets: spec.ImportRouteTargets, ExportRouteTargets: spec.ExportRouteTargets}
	imports, exports, err := evpnMappingTargets(db, []agent.EVPNMappingSnapshot{ref})
	if err != nil || len(imports) != 1 || len(exports) != 2 {
		t.Fatalf("targets=%v/%v err=%v", imports, exports, err)
	}
	for _, edit := range []func(*agent.EVPNMappingSnapshot){
		func(r *agent.EVPNMappingSnapshot) { r.UID = "" },
		func(r *agent.EVPNMappingSnapshot) { r.Generation = 0 },
		func(r *agent.EVPNMappingSnapshot) { r.VNI++ },
		func(r *agent.EVPNMappingSnapshot) { r.ExportRouteTargets = []string{"65001:999"} },
	} {
		bad := ref
		edit(&bad)
		if _, _, err := evpnMappingTargets(db, []agent.EVPNMappingSnapshot{bad}); err == nil {
			t.Fatal("invalid snapshot accepted")
		}
	}
	if _, _, err := evpnMappingTargets(db, []agent.EVPNMappingSnapshot{ref, ref}); err == nil {
		t.Fatal("duplicate mapping accepted")
	}
}
