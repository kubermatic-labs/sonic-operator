//go:build integration

// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/redis/go-redis/v9"
)

func qosRedisFixture(t *testing.T) (*SonicAgent, *redis.Client, *int) {
	t.Helper()
	m, config, _, saves := networkEngineFixture(t)
	m.planNetwork = nil
	for db, id := range map[string]int{"STATE_DB": 6, "ASIC_DB": 1, "COUNTERS_DB": 2} {
		opts := *config.Options()
		opts.DB = id
		client := redis.NewClient(&opts)
		t.Cleanup(func() { _ = client.Close() })
		m.clientPool[db] = client
	}
	return m, config, saves
}

func qosSeedRedis(t *testing.T, m *SonicAgent, fixture *qosFakeRead) {
	t.Helper()
	for name, db := range fixture.db {
		client := m.clientPool[name]
		for key, row := range db {
			if err := client.HSet(t.Context(), key, row).Err(); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestNetworkQoSRedisAbsentCreateUnverifiedAndErrors(t *testing.T) {
	m, config, saves := qosRedisFixture(t)
	r := qosRequest("QoSMap", `{"name":"native","type":"DSCPToTC","entries":[{"from":63,"to":9}]}`)
	out, st := m.GetNetworkResource(t.Context(), r)
	if st != nil || out.Exists || out.ConfigurationVerified || out.RuntimeVerified || *saves != 0 {
		t.Fatalf("absent observation: %+v %v", out, st)
	}
	before, _, err := m.vlanChangeSnapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, st := m.EnsureNetworkResource(t.Context(), r); st == nil {
		t.Fatal("missing capability bypassed preflight")
	}
	after, _, err := m.vlanChangeSnapshot(t.Context())
	if err != nil || !reflect.DeepEqual(before, after) || *saves != 0 {
		t.Fatal("preflight failure wrote configuration")
	}
	caps := qosRuntimeFixture().db["STATE_DB"]["SWITCH_CAPABILITY|switch"]
	if err := m.clientPool["STATE_DB"].HSet(t.Context(), "SWITCH_CAPABILITY|switch", caps).Err(); err != nil {
		t.Fatal(err)
	}
	out, st = m.EnsureNetworkResource(t.Context(), r)
	if st != nil || !out.ConfigurationVerified || !out.PersistenceVerified || out.RuntimeVerified || *saves != 1 {
		t.Fatalf("create without fabricated runtime: %+v %v", out, st)
	}
	f := qosRuntimeFixture()
	for key, row := range f.db["ASIC_DB"] {
		if err := m.clientPool["ASIC_DB"].HSet(t.Context(), key, row).Err(); err != nil {
			t.Fatal(err)
		}
	}
	out, st = m.GetNetworkResource(t.Context(), r)
	if st != nil || out.RuntimeVerified || *saves != 1 {
		t.Fatalf("new exact ASIC content must not prove consumer identity: %+v %v", out, st)
	}
	// Identical configuration under another native name is not a name/OID proof.
	if err := config.HSet(t.Context(), "DSCP_TO_TC_MAP|ambiguous", map[string]string{"63": "9"}).Err(); err != nil {
		t.Fatal(err)
	}
	out, st = m.GetNetworkResource(t.Context(), r)
	if st != nil || out.RuntimeVerified {
		t.Fatalf("ambiguous runtime: %+v %v", out, st)
	}
	if err := config.Del(t.Context(), "DSCP_TO_TC_MAP|ambiguous").Err(); err != nil {
		t.Fatal(err)
	}
	if err := m.clientPool["ASIC_DB"].Del(t.Context(), "VIDTORID").Err(); err != nil {
		t.Fatal(err)
	}
	if err := m.clientPool["ASIC_DB"].Set(t.Context(), "VIDTORID", "wrong-type", 0).Err(); err != nil {
		t.Fatal(err)
	}
	out, st = m.GetNetworkResource(t.Context(), r)
	if st == nil || out == nil || !out.ConfigurationVerified || out.RuntimeVerified {
		t.Fatalf("probe error hidden as notexists: %+v %v", out, st)
	}
}

func TestNetworkQoSRedisBindingRejectsStaleWitness(t *testing.T) {
	m, config, saves := qosRedisFixture(t)
	f := qosRuntimeFixture()
	delete(f.db["CONFIG_DB"], "PORT_QOS_MAP|Ethernet0")
	f.db["CONFIG_DB"]["QUEUE|Ethernet0|9"] = map[string]string{"wred_profile": "untouched"}
	f.db["CONFIG_DB"]["QUEUE|Ethernet0|0-7"] = map[string]string{"wred_profile": "other-wred", "scheduler": "other-scheduler"}
	f.db["CONFIG_DB"]["BUFFER_QUEUE|Ethernet0|0-9"] = map[string]string{"profile": "buffer-profile"}
	f.db["CONFIG_DB"]["PORT_QOS_MAP|Ethernet4"] = map[string]string{"dscp_to_tc_map": "other-map", "pfc_enable": "3,4"}
	qosSeedRedis(t, m, f)
	r := qosRequest("QoSBinding", `{"interfaceName":"Ethernet0","dscpToTC":"native","queues":[{"index":9,"scheduler":"shape"}]}`)
	initial, _, err := m.vlanChangeSnapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// Real preflight must reject an untranslated referenced profile before CAS.
	asic := m.clientPool["ASIC_DB"]
	if err := asic.HDel(t.Context(), "VIDTORID", qosTestScheduler).Err(); err != nil {
		t.Fatal(err)
	}
	if _, st := m.EnsureNetworkResource(t.Context(), r); st == nil {
		t.Fatal("unapplied profile bound")
	}
	after, _, err := m.vlanChangeSnapshot(t.Context())
	if err != nil || !reflect.DeepEqual(initial, after) || *saves != 0 {
		t.Fatal("failed preflight wrote")
	}
	if err := asic.HSet(t.Context(), "VIDTORID", qosTestScheduler, "oid:0x5").Err(); err != nil {
		t.Fatal(err)
	}
	if _, st := m.EnsureNetworkResource(t.Context(), r); st == nil {
		t.Fatal("translated stale content authorized binding")
	}
	if _, st := m.RecoverNetworkResource(t.Context(), r); st != nil {
		t.Fatal(st)
	}
	after, _, err = m.vlanChangeSnapshot(t.Context())
	if err != nil || !reflect.DeepEqual(initial, after) || *saves != 0 {
		t.Fatal("blocked binding/recovery changed configuration")
	}
	if config.HExists(t.Context(), "QUEUE|Ethernet0|9", "scheduler").Val() {
		t.Fatal("scheduler was bound")
	}
}

func TestNetworkQoSRedisSchedulerCapabilityGate(t *testing.T) {
	m, config, saves := qosRedisFixture(t)
	if err := config.Set(t.Context(), "CONFIG_DB_INITIALIZED", "1", 0).Err(); err != nil {
		t.Fatal(err)
	}
	r := qosRequest("Scheduler", `{"name":"shape","algorithm":"DWRR","weight":5,"committedRate":1000,"peakRate":2000,"committedBurst":100,"peakBurst":200}`)
	out, st := m.GetNetworkResource(t.Context(), r)
	if st != nil || out.Exists || out.RuntimeVerified {
		t.Fatalf("absent scheduler: %+v %v", out, st)
	}
	ctx := context.WithValue(t.Context(), qosStageRunnerKey{}, qosStageRunner(func(*exec.Cmd) ([]byte, error) { return nil, errors.New("probe unavailable") }))
	if _, st := m.EnsureNetworkResource(ctx, r); st == nil || config.Exists(t.Context(), "SCHEDULER|shape").Val() != 0 {
		t.Fatal("unknown scheduler capability wrote")
	}
	ctx = context.WithValue(t.Context(), qosStageRunnerKey{}, qosStageRunner(func(*exec.Cmd) ([]byte, error) { return []byte(qosTestStageSupport), nil }))
	if err := config.HSet(t.Context(), "QUEUE|Ethernet0|9", "scheduler", "shape").Err(); err != nil {
		t.Fatal(err)
	}
	if _, st := m.EnsureNetworkResource(ctx, r); st == nil || config.Exists(t.Context(), "SCHEDULER|shape").Val() != 0 {
		t.Fatal("first scheduler creation activated dangling reference")
	}
	if err := config.Del(t.Context(), "QUEUE|Ethernet0|9").Err(); err != nil {
		t.Fatal(err)
	}
	// First-ever scheduler: ASIC_DB is empty. Only the native schema/consumer
	// read is stubbed; planner, preflight, CAS, journal and runtime are real.
	m.saveConfig = func(context.Context) *agent.Status { return &agent.Status{Code: 500, Message: "interrupted save"} }
	out, st = m.EnsureNetworkResource(ctx, r)
	if st == nil || out == nil || !out.ConfigurationVerified || out.RuntimeVerified {
		t.Fatalf("staged save interruption: %+v %v", out, st)
	}
	m.saveConfig = func(context.Context) *agent.Status { *saves++; return nil }
	out, st = m.RecoverNetworkResource(ctx, r)
	if st != nil || out.RuntimeVerified || !out.PersistenceVerified || *saves != 1 {
		t.Fatalf("unbound staging recovery: %+v %v", out, st)
	}
	// A later matching ASIC object still cannot make this name ready.
	for key, row := range qosRuntimeFixture().db["ASIC_DB"] {
		if err := m.clientPool["ASIC_DB"].HSet(t.Context(), key, row).Err(); err != nil {
			t.Fatal(err)
		}
	}
	out, st = m.GetNetworkResource(ctx, r)
	if st != nil || out.RuntimeVerified {
		t.Fatalf("late unrelated ASIC object accepted: %+v %v", out, st)
	}
	if got := config.HGet(t.Context(), "SCHEDULER|shape", "pir").Val(); got != "2000" {
		t.Fatalf("byte rate was scaled: %s", got)
	}
}

func TestNetworkQoSRedisAdditiveMapOwnership(t *testing.T) {
	m, config, saves := qosRedisFixture(t)
	if err := config.HSet(t.Context(), "DSCP_TO_TC_MAP|native", map[string]string{"0": "0"}).Err(); err != nil {
		t.Fatal(err)
	}
	caps := qosRuntimeFixture().db["STATE_DB"]["SWITCH_CAPABILITY|switch"]
	if err := m.clientPool["STATE_DB"].HSet(t.Context(), "SWITCH_CAPABILITY|switch", caps).Err(); err != nil {
		t.Fatal(err)
	}
	r := qosRequest("QoSMap", `{"name":"native","type":"DSCPToTC","entries":[{"from":1,"to":1}]}`)
	out, st := m.EnsureNetworkResource(t.Context(), r)
	if st != nil || !out.PersistenceVerified || *saves != 1 {
		t.Fatalf("add map entry: %+v %v", out, st)
	}
	j, err := m.lockNetworkJournal(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	state, err := loadNetworkJournal(j)
	j.close()
	if err != nil {
		t.Fatal(err)
	}
	owned := state.Records["QoSMap|DSCPToTC|native"].Owned
	if !reflect.DeepEqual(owned, vlanChangeDB{"DSCP_TO_TC_MAP|native": {"1": "1"}}) {
		t.Fatalf("claimed foreign entries: %v", owned)
	}
	for _, spec := range []string{
		`{"name":"native","type":"DSCPToTC","entries":[{"from":0,"to":2}]}`,
		`{"name":"native","type":"DSCPToTC","entries":[{"from":1,"to":2}]}`,
		`{"name":"native","type":"DSCPToTC","entries":[{"from":2,"to":2}]}`,
	} {
		r.Spec = []byte(spec)
		if _, st := m.EnsureNetworkResource(t.Context(), r); st == nil {
			t.Fatal("replacement/removal accepted")
		}
	}
	got, err := config.HGetAll(t.Context(), "DSCP_TO_TC_MAP|native").Result()
	if err != nil || !reflect.DeepEqual(got, map[string]string{"0": "0", "1": "1"}) || *saves != 1 {
		t.Fatalf("conflict modified map: %v %v", got, err)
	}
}

func TestNetworkQoSRedisTypedReferenceSnapshot(t *testing.T) {
	m, config, saves := qosRedisFixture(t)
	ctx := context.WithValue(t.Context(), qosStageRunnerKey{}, qosStageRunner(func(*exec.Cmd) ([]byte, error) { return []byte(qosTestStageSupport), nil }))
	r := qosRequest("Scheduler", `{"name":"new","algorithm":"STRICT"}`)
	p, err := planNetworkScheduler(nil, r)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		command []any
		valid   bool
	}{
		{"initialized", []any{"SET", "CONFIG_DB_INITIALIZED", "1"}, true},
		{"invalid value", []any{"SET", "CONFIG_DB_INITIALIZED", "0"}, false},
		{"noncanonical", []any{"SET", "CONFIG_DB_INITIALIZED", "01"}, false},
		{"marker hash", []any{"HSET", "CONFIG_DB_INITIALIZED", "__sonic_string__", "1"}, false},
		{"marker list", []any{"RPUSH", "CONFIG_DB_INITIALIZED", "1"}, false},
		{"expiring", []any{"SET", "CONFIG_DB_INITIALIZED", "1", "PX", "3600000"}, false},
		{"other string", []any{"SET", "OTHER", "1"}, false},
		{"other list", []any{"RPUSH", "OTHER", "1"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := config.FlushDB(ctx).Err(); err != nil {
				t.Fatal(err)
			}
			if err := config.Do(ctx, tc.command...).Err(); err != nil {
				t.Fatal(err)
			}
			key := tc.command[1].(string)
			before, err := config.Dump(ctx, key).Result()
			if err != nil {
				t.Fatal(err)
			}
			// Direct production planner closure proves the reference scan itself
			// handles types; the engine independently applies the same contract.
			if err := p.Preflight(ctx, m); (err == nil) != tc.valid {
				t.Fatalf("preflight: %v", err)
			}
			if !tc.valid {
				if _, st := m.EnsureNetworkResource(ctx, r); st == nil {
					t.Fatal("invalid type accepted by engine")
				}
				if config.Exists(ctx, "SCHEDULER|new").Val() != 0 || *saves != 0 {
					t.Fatal("invalid snapshot wrote scheduler")
				}
			}
			after, err := config.Dump(ctx, key).Result()
			if err != nil || after != before {
				t.Fatal("read/preflight mutated marker or other key")
			}
		})
	}
}

func TestNetworkQoSRedisMapReferencesBlockMutation(t *testing.T) {
	m, config, saves := qosRedisFixture(t)
	caps := qosRuntimeFixture().db["STATE_DB"]["SWITCH_CAPABILITY|switch"]
	if err := m.clientPool["STATE_DB"].HSet(t.Context(), "SWITCH_CAPABILITY|switch", caps).Err(); err != nil {
		t.Fatal(err)
	}
	for _, typ := range []string{"DSCPToTC", "Dot1pToTC", "TCToQueue"} {
		kind := qosMapKinds[typ]
		for _, existing := range []bool{false, true} {
			t.Run(typ+map[bool]string{false: "/dangling", true: "/extension"}[existing], func(t *testing.T) {
				if err := config.FlushDB(t.Context()).Err(); err != nil {
					t.Fatal(err)
				}
				if err := config.Set(t.Context(), "CONFIG_DB_INITIALIZED", "1", 0).Err(); err != nil {
					t.Fatal(err)
				}
				key := kind.table + "|NewMap"
				if existing {
					if err := config.HSet(t.Context(), key, "0", "0").Err(); err != nil {
						t.Fatal(err)
					}
				}
				if err := config.HSet(t.Context(), "PORT_QOS_MAP|Ethernet0", kind.field, "NewMap", "pfc_enable", "3").Err(); err != nil {
					t.Fatal(err)
				}
				r := qosRequest("QoSMap", `{"name":"NewMap","type":"`+typ+`","entries":[{"from":1,"to":1}]}`)
				before, _, err := m.vlanChangeSnapshot(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				priorSaves := *saves
				p, err := planNetworkQoSMap(before, r)
				if err != nil {
					t.Fatal(err)
				}
				if err := p.Preflight(t.Context(), m); err == nil {
					t.Fatal("referenced map preflight passed")
				}
				if _, st := m.GetNetworkResource(t.Context(), r); st != nil {
					t.Fatalf("read should not run mutation guard: %v", st)
				}
				if _, st := m.EnsureNetworkResource(t.Context(), r); st == nil {
					t.Fatal("referenced map mutation accepted")
				}
				after, _, err := m.vlanChangeSnapshot(t.Context())
				if err != nil || !reflect.DeepEqual(before, after) || *saves != priorSaves {
					t.Fatal("blocked map operation changed configuration")
				}
				if existing {
					r.Spec = []byte(`{"name":"NewMap","type":"` + typ + `","entries":[{"from":0,"to":0}]}`)
					p, err := planNetworkQoSMap(before, r)
					if err != nil {
						t.Fatal(err)
					}
					if err := p.Preflight(t.Context(), m); err != nil {
						t.Fatalf("no-op preflight rejected: %v", err)
					}
					if out, st := m.EnsureNetworkResource(t.Context(), r); st != nil || !out.ConfigurationVerified {
						t.Fatalf("no-op rejected: %+v %v", out, st)
					}
					after, _, err := m.vlanChangeSnapshot(t.Context())
					if err != nil || !reflect.DeepEqual(before, after) {
						t.Fatal("no-op changed configuration")
					}
				}
			})
		}
	}
}
