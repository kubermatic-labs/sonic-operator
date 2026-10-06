//go:build integration

// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"testing"
)

func TestEVPNFreshTunnelDoesNotInventRuntime(t *testing.T) {
	m, db := evpnRedisFixture(t)
	if err := db.Del(t.Context(), "VXLAN_TUNNEL|vtep1", "VXLAN_EVPN_NVO|nvo1").Err(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ASIC_DB", "COUNTERS_DB"} {
		if err := m.clientPool[name].FlushDB(t.Context()).Err(); err != nil {
			t.Fatal(err)
		}
	}
	ctx := evpnTestCommands(t, evpnTestFRR, nil)
	out, st := m.EnsureNetworkResource(ctx, evpnTestRequest("VXLANTunnel", evpnTestTunnel))
	if st != nil || out == nil || !out.ConfigurationVerified || !out.PersistenceVerified || out.RuntimeVerified {
		t.Fatalf("fresh staging must persist without claiming hardware: %+v %v", out, st)
	}
	// Mapping writes trigger native hardware creation, so they must not wait
	// for the tunnel's hardware readiness either.
	out, st = m.EnsureNetworkResource(ctx, evpnTestRequest("VLANVNI", evpnTestMap))
	if st != nil || out == nil || !out.ConfigurationVerified || !out.PersistenceVerified || out.RuntimeVerified {
		t.Fatalf("first mapping must stage without hardware: %+v %v", out, st)
	}
	for name, rows := range evpnASICFixture().db {
		for key, row := range rows {
			if err := m.clientPool[name].HSet(t.Context(), key, row).Err(); err != nil {
				t.Fatal(err)
			}
		}
	}
	ctx = evpnTestCommands(t, evpnTestFRR+evpnTestVNI, nil)
	for _, request := range []struct{ kind, spec string }{{"VXLANTunnel", evpnTestTunnel}, {"VLANVNI", evpnTestMap}} {
		out, st = m.GetNetworkResource(ctx, evpnTestRequest(request.kind, request.spec))
		if st != nil || out == nil || !out.RuntimeVerified || !out.PersistenceVerified {
			t.Fatalf("applied %s not verified: %+v %v", request.kind, out, st)
		}
	}
}
