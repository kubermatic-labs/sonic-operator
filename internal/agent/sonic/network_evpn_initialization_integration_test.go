//go:build integration

// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

func evpnInitializationRequest(t *testing.T) *agent.NetworkRequest {
	t.Helper()
	var mapping evpnMapSpec
	if err := json.Unmarshal([]byte(evpnTestMap), &mapping); err != nil {
		t.Fatal(err)
	}
	s := evpnGlobalSpec{Tunnel: mapping.Tunnel, AdminState: "Up", Mappings: []agent.EVPNMappingSnapshot{{Name: "mapping", UID: "mapping-owner", Generation: 1, Tunnel: mapping.Tunnel, VLANID: mapping.VLANID, VNI: mapping.VNI, RouteDistinguisher: mapping.RouteDistinguisher, ImportRouteTargets: mapping.ImportRouteTargets, ExportRouteTargets: mapping.ExportRouteTargets}}}
	s.MappingRefs = append(s.MappingRefs, struct {
		Name string `json:"name"`
	}{Name: "mapping"})
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return &agent.NetworkRequest{Kind: "EVPN", OwnerID: "global-owner", Spec: raw}
}

func TestEVPNInitializeBeforeNativeVNIReadback(t *testing.T) {
	m, db := evpnRedisFixture(t)
	// No mapping or hardware exists yet. References express the intended set.
	for _, name := range []string{"ASIC_DB", "COUNTERS_DB"} {
		if err := m.clientPool[name].FlushDB(t.Context()).Err(); err != nil {
			t.Fatal(err)
		}
	}
	r := evpnInitializationRequest(t)
	ctx := evpnTestCommands(t, evpnTestFRR, nil)
	m.saveConfig = func(context.Context) *agent.Status {
		return &agent.Status{Code: 500, Message: "interrupted initialization save"}
	}
	out, st := m.EnsureNetworkResource(ctx, r)
	if st == nil || out == nil || out.PersistenceVerified {
		t.Fatalf("lost initialization save failure: %+v %v", out, st)
	}
	m.saveConfig = func(context.Context) *agent.Status { return nil }
	out, st = m.RecoverNetworkResource(ctx, r)
	if st != nil || out == nil || !out.ConfigurationVerified || !out.PersistenceVerified || out.RuntimeVerified {
		t.Fatalf("initialization recovery: %+v %v", out, st)
	}
	// Initialization does not activate a peer. Mapping creation is now possible
	// because native FRR has entered EVPN mode, but hardware is still unverified.
	if db.HGet(t.Context(), "BGP_NEIGHBOR|default|192.0.2.2", "admin_status").Val() != "down" {
		t.Fatal("initialization enabled parent")
	}
	config := evpnTestFRR + " address-family l2vpn evpn\n  advertise-all-vni\n exit-address-family\n"
	ctx = evpnTestCommands(t, config, nil)
	mapping := evpnTestRequest("VLANVNI", evpnTestMap)
	mapping.OwnerID = "mapping-owner"
	foreign := *mapping
	foreign.OwnerID = "replacement-owner"
	if _, st := m.EnsureNetworkResource(ctx, &foreign); st == nil {
		t.Fatal("foreign mapping authorized by global initialization")
	}
	out, st = m.EnsureNetworkResource(ctx, mapping)
	if st != nil || out == nil || !out.PersistenceVerified || out.RuntimeVerified {
		t.Fatalf("mapping after initialization: %+v %v", out, st)
	}
	snapshot, _, err := m.vlanChangeSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var global evpnGlobalSpec
	if err := json.Unmarshal(r.Spec, &global); err != nil {
		t.Fatal(err)
	}
	if err := evpnMappingActivationReady(ctx, m, snapshot, []byte(strings.Replace(evpnTestFRR+evpnTestVNI, " address-family l2vpn evpn\n", " address-family l2vpn evpn\n  advertise-all-vni\n", 1)), global.Mappings); err == nil {
		t.Fatal("missing hardware accepted for activation")
	}
	for name, rows := range evpnASICFixture().db {
		for key, row := range rows {
			if err := m.clientPool[name].HSet(t.Context(), key, row).Err(); err != nil {
				t.Fatal(err)
			}
		}
	}
	ctx = evpnTestCommands(t, strings.Replace(evpnTestFRR+evpnTestVNI, " address-family l2vpn evpn\n", " address-family l2vpn evpn\n  advertise-all-vni\n", 1), nil)
	out, st = m.GetNetworkResource(ctx, r)
	if st != nil || out == nil || !out.RuntimeVerified {
		t.Fatalf("initialized runtime after convergence: %+v %v", out, st)
	}
}

func TestEVPNInitializedGlobalDeclarationCannotDrift(t *testing.T) {
	m, _ := evpnRedisFixture(t)
	r := evpnInitializationRequest(t)
	ctx := evpnTestCommands(t, evpnTestFRR, nil)
	if _, st := m.EnsureNetworkResource(ctx, r); st != nil {
		t.Fatal(st)
	}
	r.Spec = []byte(strings.ReplaceAll(string(r.Spec), "mapping-owner", "replacement-owner"))
	if _, st := m.EnsureNetworkResource(ctx, r); st == nil {
		t.Fatal("global declaration changed without ownership check")
	}
}

func TestEVPNInitializationRejectsNativeActiveNeighbors(t *testing.T) {
	for _, config := range []string{
		strings.Replace(evpnTestFRR, " neighbor 192.0.2.2 shutdown\n", "", 1),
		evpnTestFRR + " neighbor 192.0.2.99 remote-as 65099\n",
		evpnTestFRR + " address-family l2vpn evpn\n  neighbor 192.0.2.2 activate\n exit-address-family\n",
		evpnTestFRR + "!\nrouter bgp 65099 vrf VrfForeign\n neighbor 203.0.113.1 remote-as 65098\n",
		evpnTestFRR + " address-family l2vpn evpn\n  vni 999\n   rd 65001:999\n  exit-vni\n exit-address-family\n",
	} {
		m, _ := evpnRedisFixture(t)
		before, _, err := m.vlanChangeSnapshot(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, st := m.EnsureNetworkResource(evpnTestCommands(t, config, nil), evpnInitializationRequest(t)); st == nil {
			t.Fatal("unsafe native state accepted")
		}
		after, _, err := m.vlanChangeSnapshot(t.Context())
		if err != nil || vlanAuthorityHash(before) != vlanAuthorityHash(after) {
			t.Fatal("failed preflight changed config")
		}
	}
}
