//go:build integration

// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"maps"
	"reflect"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/redis/go-redis/v9"
)

func aclEngineFixture(t *testing.T) (*SonicAgent, *redis.Client, map[string]*redis.Client, *int) {
	t.Helper()
	m, config, _, saves := networkEngineFixture(t)
	m.planNetwork = nil // Real dispatch, planner, preflight, CAS, journal and runtime.
	dbs := map[string]*redis.Client{"CONFIG_DB": config}
	for _, name := range []string{"STATE_DB", "ASIC_DB", "COUNTERS_DB"} {
		opts := *config.Options()
		opts.DB = getRedisDBIDByName(name)
		db := redis.NewClient(&opts)
		t.Cleanup(func() { _ = db.Close() })
		dbs[name], m.clientPool[name] = db, db
	}
	if err := config.HSet(t.Context(), "PORT|Ethernet0", "admin_status", "up").Err(); err != nil {
		t.Fatal(err)
	}
	return m, config, dbs, saves
}

func aclSeedNative(t *testing.T, dbs map[string]*redis.Client, native map[string]vlanChangeDB) {
	t.Helper()
	for name, db := range native {
		for key, fields := range db {
			if err := dbs[name].HSet(t.Context(), key, fields).Err(); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestACLEngineStagesBeforeBindingAndRecovers(t *testing.T) {
	m, config, dbs, saves := aclEngineFixture(t)
	native := aclNativeFixture()
	// Initial capability evidence only: CONFIG_DB readiness must not imply ASIC.
	initial := map[string]vlanChangeDB{"STATE_DB": {"ACL_STAGE_CAPABILITY_TABLE|INGRESS": native["STATE_DB"]["ACL_STAGE_CAPABILITY_TABLE|INGRESS"]}, "COUNTERS_DB": {
		"CRM:ACL_STATS:INGRESS:PORT": native["COUNTERS_DB"]["CRM:ACL_STATS:INGRESS:PORT"],
		"CRM:ACL_STATS:INGRESS:LAG":  native["COUNTERS_DB"]["CRM:ACL_STATS:INGRESS:LAG"],
	}}
	aclSeedNative(t, dbs, initial)
	policy := aclRequest("ACLPolicy", aclTestSpec)
	got, st := m.EnsureNetworkResource(t.Context(), policy)
	if st != nil || got == nil || !got.ConfigurationVerified || !got.PersistenceVerified || got.RuntimeVerified || *saves != 1 {
		t.Fatalf("stage %+v %+v", got, st)
	}
	if config.HExists(t.Context(), "ACL_TABLE|EDGE", "ports@").Val() {
		t.Fatal("policy claimed ports")
	}
	binding := aclRequest("ACLBinding", `{"policy":"EDGE","interfaces":["Ethernet0"]}`)
	binding.OwnerID = "binding-owner"
	if _, st := m.EnsureNetworkResource(t.Context(), binding); st == nil || config.HExists(t.Context(), "ACL_TABLE|EDGE", "ports@").Val() {
		t.Fatal("incomplete runtime bound")
	}
	aclSeedNative(t, dbs, native)
	got, st = m.GetNetworkResource(t.Context(), policy)
	if st != nil || !got.RuntimeVerified {
		t.Fatalf("staged runtime %+v %+v", got, st)
	}
	// Interrupt after CAS: binding recovery must retain separate ownership and
	// avoid any policy rewrite while restoring persistence evidence.
	m.saveConfig = func(context.Context) *agent.Status { return &agent.Status{Code: 500, Message: "save interrupted"} }
	got, st = m.EnsureNetworkResource(t.Context(), binding)
	if st == nil || got == nil || !got.ConfigurationVerified || got.PersistenceVerified || got.RuntimeVerified {
		t.Fatalf("interrupted binding %+v %+v", got, st)
	}
	aclFixtureBind(native)
	aclSeedNative(t, dbs, native)
	m.saveConfig = func(context.Context) *agent.Status { *saves++; return nil }
	got, st = m.RecoverNetworkResource(t.Context(), binding)
	if st != nil || got == nil || !got.ConfigurationVerified || !got.PersistenceVerified || !got.RuntimeVerified {
		t.Fatalf("binding recovery %+v %+v", got, st)
	}
	for _, tc := range []struct{ name, vid string }{
		{"port", aclTestPort}, {"group", aclTestGroup}, {"group member", aclTestMember},
	} {
		t.Run("pending applied membership/"+tc.name, func(t *testing.T) {
			rid, err := dbs["ASIC_DB"].HGet(t.Context(), "VIDTORID", tc.vid).Result()
			if err != nil {
				t.Fatal(err)
			}
			if err := dbs["ASIC_DB"].HDel(t.Context(), "VIDTORID", tc.vid).Err(); err != nil {
				t.Fatal(err)
			}
			got, _ := m.GetNetworkResource(t.Context(), binding)
			if got == nil || !got.ConfigurationVerified || got.RuntimeVerified {
				t.Fatalf("requested membership qualified without %s translation: %+v", tc.name, got)
			}
			if err := dbs["ASIC_DB"].HSet(t.Context(), "VIDTORID", tc.vid, rid).Err(); err != nil {
				t.Fatal(err)
			}
			got, st := m.GetNetworkResource(t.Context(), binding)
			if st != nil || !got.RuntimeVerified {
				t.Fatalf("applied membership did not converge: %+v %+v", got, st)
			}
		})
	}
	p, err := planNetworkACLPolicy(nil, policy)
	if err != nil {
		t.Fatal(err)
	}
	before, _, err := m.vlanChangeSnapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	got, st = m.EnsureNetworkResource(t.Context(), policy)
	if st != nil || !got.RuntimeVerified || !got.PersistenceVerified {
		t.Fatalf("policy after binding %+v %+v", got, st)
	}
	after, _, err := m.vlanChangeSnapshot(t.Context())
	if err != nil || !reflect.DeepEqual(before, after) || !reflect.DeepEqual(aclPolicyTarget(after, "EDGE"), p.Desired) {
		t.Fatal("policy overwrote bound fields")
	}
	var s aclPolicySpec
	if err := json.Unmarshal(policy.Spec, &s); err != nil {
		t.Fatal(err)
	}
	s.Rules = append(s.Rules, aclRuleSpec{Name: "NEW", Priority: 200, Action: "Drop"})
	changed := *policy
	changed.Spec, _ = json.Marshal(s)
	if _, st := m.EnsureNetworkResource(t.Context(), &changed); st == nil {
		t.Fatal("active policy extended")
	}
	after, _, err = m.vlanChangeSnapshot(t.Context())
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("rejected mutation wrote config")
	}
}

func TestACLEngineRejectsForeignPartialAndUnsupportedPolicy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(map[string]vlanChangeDB)
	}{
		{"missing capability", func(db map[string]vlanChangeDB) { delete(db["STATE_DB"], "ACL_STAGE_CAPABILITY_TABLE|INGRESS") }},
		{"unsupported action", func(db map[string]vlanChangeDB) {
			db["STATE_DB"]["ACL_STAGE_CAPABILITY_TABLE|INGRESS"]["action_list"] = "REDIRECT_ACTION"
		}},
		{"no capacity", func(db map[string]vlanChangeDB) {
			db["COUNTERS_DB"]["CRM:ACL_STATS:INGRESS:PORT"]["crm_stats_acl_table_available"] = "0"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, config, dbs, saves := aclEngineFixture(t)
			native := aclNativeFixture()
			delete(native["STATE_DB"], "ACL_TABLE_TABLE|EDGE")
			delete(native["COUNTERS_DB"], "ACL_COUNTER_RULE_MAP")
			tc.mutate(native)
			aclSeedNative(t, dbs, native)
			before, _, err := m.vlanChangeSnapshot(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if _, st := m.EnsureNetworkResource(t.Context(), aclRequest("ACLPolicy", aclTestSpec)); st == nil {
				t.Fatal("unsupported stage accepted")
			}
			after, _, err := m.vlanChangeSnapshot(t.Context())
			if err != nil || !reflect.DeepEqual(before, after) || *saves != 0 || config.Exists(t.Context(), "ACL_TABLE|EDGE").Val() != 0 {
				t.Fatal("unsupported stage wrote config")
			}
		})
	}
	t.Run("complete foreign config lacks completion proof", func(t *testing.T) {
		m, config, dbs, _ := aclEngineFixture(t)
		aclSeedNative(t, dbs, aclNativeFixture())
		p, err := planNetworkACLPolicy(nil, aclRequest("ACLPolicy", aclTestSpec))
		if err != nil {
			t.Fatal(err)
		}
		for key, fields := range p.Desired {
			if err := config.HSet(t.Context(), key, maps.Clone(fields)).Err(); err != nil {
				t.Fatal(err)
			}
		}
		if _, st := m.EnsureNetworkResource(t.Context(), aclRequest("ACLBinding", `{"policy":"EDGE","interfaces":["Ethernet0"]}`)); st == nil {
			t.Fatal("foreign partial policy considered complete")
		}
		if config.HExists(t.Context(), "ACL_TABLE|EDGE", "ports@").Val() {
			t.Fatal("foreign policy bound")
		}
	})
}

func TestACLEngineBindingPreflightRunsBeforeCAS(t *testing.T) {
	m, config, dbs, _ := aclEngineFixture(t)
	native := aclNativeFixture()
	initial := map[string]vlanChangeDB{
		"STATE_DB": {"ACL_STAGE_CAPABILITY_TABLE|INGRESS": native["STATE_DB"]["ACL_STAGE_CAPABILITY_TABLE|INGRESS"]},
		"COUNTERS_DB": {
			"CRM:ACL_STATS:INGRESS:PORT": native["COUNTERS_DB"]["CRM:ACL_STATS:INGRESS:PORT"],
			"CRM:ACL_STATS:INGRESS:LAG":  native["COUNTERS_DB"]["CRM:ACL_STATS:INGRESS:LAG"],
		},
	}
	aclSeedNative(t, dbs, initial)
	if _, st := m.EnsureNetworkResource(t.Context(), aclRequest("ACLPolicy", aclTestSpec)); st != nil {
		t.Fatal(st)
	}
	aclSeedNative(t, dbs, native)
	for _, tc := range []struct{ name, db, key, field, value string }{
		{"rule pending", "STATE_DB", "ACL_RULE_TABLE|EDGE|WEB", "status", "Pending creation"},
		{"counter not enabled", "ASIC_DB", aclASIC + "ACL_COUNTER:" + aclTestCounterDefault, "SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT", "false"},
		{"table not applied", "ASIC_DB", "VIDTORID", aclTestTable, "oid:0x0"},
		{"entry not applied", "ASIC_DB", "VIDTORID", aclTestEntryWeb, "oid:0x0"},
		{"counter not applied", "ASIC_DB", "VIDTORID", aclTestCounterWeb, "oid:0x0"},
		{"port not applied", "ASIC_DB", "VIDTORID", aclTestPort, "oid:0x0"},
		{"table translation missing", "ASIC_DB", "VIDTORID", aclTestTable, ""},
		{"entry translation missing", "ASIC_DB", "VIDTORID", aclTestEntryWeb, ""},
		{"counter translation missing", "ASIC_DB", "VIDTORID", aclTestCounterWeb, ""},
		{"port translation missing", "ASIC_DB", "VIDTORID", aclTestPort, ""},
		{"target port not ready", "STATE_DB", "PORT_TABLE|Ethernet0", "state", "pending"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := dbs[tc.db].HGet(t.Context(), tc.key, tc.field).Val()
			var changeErr error
			if tc.value == "" {
				changeErr = dbs[tc.db].HDel(t.Context(), tc.key, tc.field).Err()
			} else {
				changeErr = dbs[tc.db].HSet(t.Context(), tc.key, tc.field, tc.value).Err()
			}
			if err := changeErr; err != nil {
				t.Fatal(err)
			}
			before, _, err := m.vlanChangeSnapshot(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if _, st := m.EnsureNetworkResource(t.Context(), aclRequest("ACLBinding", `{"policy":"EDGE","interfaces":["Ethernet0"]}`)); st == nil {
				t.Fatal("failed preflight accepted")
			}
			after, _, err := m.vlanChangeSnapshot(t.Context())
			if err != nil || !reflect.DeepEqual(before, after) || config.HExists(t.Context(), "ACL_TABLE|EDGE", "ports@").Val() {
				t.Fatal("preflight failure wrote configuration")
			}
			if err := dbs[tc.db].HSet(t.Context(), tc.key, tc.field, old).Err(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
