//go:build integration

// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"maps"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/redis/go-redis/v9"
)

func evpnRedisFixture(t *testing.T) (*SonicAgent, *redis.Client) {
	t.Helper()
	m, db, _, _ := networkEngineFixture(t)
	m.planNetwork = planNetworkResource
	m.clientPool["APPL_DB"] = newVLANRedis(t)
	for key, row := range evpnTestDB() {
		if err := db.HSet(t.Context(), key, row).Err(); err != nil {
			t.Fatal(err)
		}
	}
	for name, rows := range evpnASICFixture().db {
		client := newVLANRedis(t)
		m.clientPool[name] = client
		for key, row := range rows {
			if err := client.HSet(t.Context(), key, row).Err(); err != nil {
				t.Fatal(err)
			}
		}
	}
	return m, db
}

func TestEVPNRealRedisPreflightNoWrites(t *testing.T) {
	for _, tc := range []struct {
		name, command, output string
	}{
		{"unreviewed consumer", "sha256sum", "unreviewed file"},
		{"consumer stopped", "supervisorctl", "frrcfgd STOPPED"},
		{"management underlay", "route get", `[{"dev":"eth0","from":"192.0.2.1"}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := evpnRedisFixture(t)
			before, _, err := m.vlanChangeSnapshot(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			ctx := evpnTestCommands(t, evpnTestFRR, func(cmd *exec.Cmd) ([]byte, error, bool) {
				if strings.Contains(strings.Join(cmd.Args, " "), tc.command) {
					return []byte(tc.output), nil, true
				}
				return nil, nil, false
			})
			if _, st := m.EnsureNetworkResource(ctx, evpnTestRequest("VLANVNI", evpnTestMap)); st == nil {
				t.Fatal("unsafe native/underlay evidence passed")
			}
			after, _, err := m.vlanChangeSnapshot(t.Context())
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("preflight failure wrote CONFIG_DB")
			}
		})
	}
}

func TestEVPNRealRedisMappingRecoveryAndRuntime(t *testing.T) {
	m, db := evpnRedisFixture(t)
	req := evpnTestRequest("VLANVNI", evpnTestMap)
	ctx := evpnTestCommands(t, evpnTestFRR, nil)
	m.saveConfig = func(context.Context) *agent.Status { return &agent.Status{Code: 500, Message: "interrupted save"} }
	out, st := m.EnsureNetworkResource(ctx, req)
	if st == nil || out == nil || !out.ConfigurationVerified || out.PersistenceVerified || out.RuntimeVerified {
		t.Fatalf("interrupted save: %+v %v", out, st)
	}
	if db.HGet(t.Context(), "BGP_GLOBALS_EVPN_VNI_RT|default|l2vpn_evpn|100|65001:100", "route-target-type").Val() != "both" {
		t.Fatal("native RT syntax missing")
	}
	m.saveConfig = func(context.Context) *agent.Status { return nil }
	ctx = evpnTestCommands(t, evpnTestFRR+evpnTestVNI, nil)
	out, st = m.RecoverNetworkResource(ctx, req)
	if st != nil || !out.PersistenceVerified || !out.RuntimeVerified {
		t.Fatalf("recovery: %+v %v", out, st)
	}
	if err := m.clientPool["ASIC_DB"].HDel(t.Context(), "VIDTORID", "oid:0x5").Err(); err != nil {
		t.Fatal(err)
	}
	out, st = m.GetNetworkResource(ctx, req)
	if st != nil || !out.ConfigurationVerified || out.RuntimeVerified {
		t.Fatalf("CONFIG_DB-only readiness: %+v %v", out, st)
	}
	// Changed RT policy cannot overwrite additive ownership.
	changed := evpnTestRequest("VLANVNI", strings.Replace(evpnTestMap, "65001:101", "65001:102", 1))
	if _, st := m.EnsureNetworkResource(ctx, changed); st == nil {
		t.Fatal("RT replaced")
	}
}

func TestEVPNRealRedisPeerOwnershipAndAFOnly(t *testing.T) {
	m, db := evpnRedisFixture(t)
	ctx := evpnTestCommands(t, evpnTestFRR, nil)
	req := evpnTestRequest("EVPNPeer", evpnTestPeer)
	if _, st := m.EnsureNetworkResource(ctx, req); st == nil {
		t.Fatal("foreign staged neighbor adopted")
	}
	// Seed the existing SwitchBGPPeer durable ownership, not merely CONFIG_DB.
	snapshot, _, err := m.vlanChangeSnapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	key := "BGP_NEIGHBOR|default|192.0.2.2"
	fields := vlanChangeDB{key: maps.Clone(snapshot[key])}
	j, err := m.lockNetworkJournal(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	state, err := loadNetworkJournal(j)
	if err != nil {
		j.close()
		t.Fatal(err)
	}
	state.Records["BGPPeer|default|192.0.2.2"] = &networkRecord{Kind: "BGPPeer", OwnerID: "bgp-owner", Fields: fields, Owned: fields, Fingerprint: vlanAuthorityHash(snapshot)}
	err = storeNetworkJournal(j, state)
	j.close()
	if err != nil {
		t.Fatal(err)
	}
	out, st := m.EnsureNetworkResource(ctx, req)
	if st != nil || !out.PersistenceVerified || !out.RuntimeVerified {
		t.Fatalf("AF Down: %+v %v", out, st)
	}
	if !reflect.DeepEqual(db.HGetAll(t.Context(), key).Val(), snapshot[key]) {
		t.Fatal("shared neighbor changed")
	}
	before, _, err := m.vlanChangeSnapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, st := m.EnsureNetworkResource(ctx, evpnTestRequest("EVPNPeer", strings.Replace(evpnTestPeer, "Down", "Up", 1))); st == nil {
		t.Fatal("Up without export isolation allowed")
	}
	after, _, err := m.vlanChangeSnapshot(t.Context())
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("Up rejection wrote CONFIG_DB")
	}
}
