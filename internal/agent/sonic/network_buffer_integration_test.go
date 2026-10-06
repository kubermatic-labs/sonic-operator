//go:build integration

// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/redis/go-redis/v9"
)

func TestNetworkBufferNativeGatePreservesCapturedBinding(t *testing.T) {
	m, db, req, saves := networkEngineFixture(t)
	m.clientPool["APPL_DB"] = newVLANRedis(t)
	for key, row := range bufferTestDB() {
		if err := db.HSet(t.Context(), key, row).Err(); err != nil {
			t.Fatal(err)
		}
	}
	m.planNetwork = planNetworkResource
	req.Kind = "BufferPG"
	req.Spec = json.RawMessage(`{"interfaceName":"Ethernet11","range":"7","profile":"PORT3_INGRESS_PROFILE"}`)
	before, _, err := m.vlanChangeSnapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	got, st := m.GetNetworkResource(t.Context(), req)
	if st == nil || !got.ConfigurationVerified || got.RuntimeVerified || got.PersistenceVerified {
		t.Fatalf("read=%+v status=%v", got, st)
	}
	got, st = m.EnsureNetworkResource(t.Context(), req)
	if st == nil || !strings.Contains(st.Message, "buffer qualification") || got.RuntimeVerified || got.PersistenceVerified || *saves != 0 {
		t.Fatalf("unqualified write=%+v status=%v saves=%d", got, st, *saves)
	}
	after, _, err := m.vlanChangeSnapshot(t.Context())
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("native gate changed configuration", err)
	}
	entries, err := os.ReadDir(m.networkJournalDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("native gate created durable intent: %v %v", entries, err)
	}
}

// Native qualification is replaced ONLY in these engine tests. Runtime remains
// false: these cases prove journal/CAS mechanics, not hardware acceptance.
func TestNetworkBufferJournalSaveRecovery(t *testing.T) {
	for _, tc := range []struct{ kind, spec, key string }{
		{"BufferPool", `{"name":"newpool","type":"ingress","mode":"dynamic","size":100000}`, "BUFFER_POOL|newpool"},
		{"BufferProfile", `{"name":"newprofile","pool":"PORT3_INGRESS_POOL","size":0,"dynamicThreshold":3}`, "BUFFER_PROFILE|newprofile"},
		{"BufferPG", `{"interfaceName":"Ethernet11","range":"7","profile":"PORT3_INGRESS_PROFILE"}`, "BUFFER_PG|Ethernet11|7"},
		{"BufferQueue", `{"interfaceName":"Ethernet11","range":"0-7","profile":"out"}`, "BUFFER_QUEUE|Ethernet11|0-7"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			m, db, req, _ := networkEngineFixture(t)
			for key, row := range bufferTestDB() {
				if err := db.HSet(t.Context(), key, row).Err(); err != nil {
					t.Fatal(err)
				}
			}
			if err := db.HSet(t.Context(), "UNRELATED|config", "preserve", "yes").Err(); err != nil {
				t.Fatal(err)
			}
			m.planNetwork = func(db vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
				p, err := planNetworkResource(db, r)
				if err != nil {
					return nil, err
				}
				p.Preflight = func(context.Context, *SonicAgent) error { return nil }
				p.Runtime = func(context.Context, *SonicAgent) (bool, json.RawMessage, error) { return false, nil, nil }
				return p, nil
			}
			req.Kind = tc.kind
			req.Spec = json.RawMessage(tc.spec)
			m.saveConfig = func(context.Context) *agent.Status { return &agent.Status{Code: 500, Message: "interrupted save"} }
			got, st := m.EnsureNetworkResource(t.Context(), req)
			if st == nil || !got.ConfigurationVerified || got.PersistenceVerified {
				t.Fatalf("save interruption: %+v %v", got, st)
			}
			// Restart reuses only persisted journal/config, not the old agent's memory.
			restarted := &SonicAgent{networkJournalDir: m.networkJournalDir, clientPool: map[string]*redis.Client{"CONFIG_DB": db}, planNetwork: m.planNetwork, saveConfig: func(context.Context) *agent.Status { return nil }}
			var edited map[string]any
			if err := json.Unmarshal(req.Spec, &edited); err != nil {
				t.Fatal(err)
			}
			edited["profile"] = "invalid-after-interruption"
			req.Spec, _ = json.Marshal(edited)
			got, st = restarted.RecoverNetworkResource(t.Context(), req)
			if st != nil || !got.PersistenceVerified || got.RuntimeVerified {
				t.Fatalf("recovery: %+v %v", got, st)
			}
			req.Spec = json.RawMessage(tc.spec)
			foreign := *req
			foreign.OwnerID = "foreign-uid"
			if _, st := restarted.EnsureNetworkResource(t.Context(), &foreign); st == nil {
				t.Fatal("ownership transferred")
			}
			if db.HGet(t.Context(), "BUFFER_PG|Ethernet11|7", "profile").Val() != "PORT3_INGRESS_PROFILE" || db.HGet(t.Context(), "UNRELATED|config", "preserve").Val() != "yes" {
				t.Fatal("lost preserved values")
			}
			j, err := restarted.lockNetworkJournal(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			state, err := loadNetworkJournal(j)
			j.close()
			if err != nil {
				t.Fatal(err)
			}
			id, err := networkIdentity(req)
			if err != nil {
				t.Fatal(err)
			}
			record := state.Records[id]
			if record == nil || record.Pending != nil || record.Fields[tc.key] == nil {
				t.Fatalf("missing durable ownership: %+v", record)
			}
		})
	}
}

func TestNetworkBufferCASRejectsDependencyRace(t *testing.T) {
	m, db, req, saves := networkEngineFixture(t)
	for key, row := range bufferTestDB() {
		if err := db.HSet(t.Context(), key, row).Err(); err != nil {
			t.Fatal(err)
		}
	}
	req.Kind = "BufferPG"
	req.Spec = json.RawMessage(`{"interfaceName":"Ethernet11","range":"6","profile":"PORT3_INGRESS_PROFILE"}`)
	m.planNetwork = func(db vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
		p, err := planNetworkResource(db, r)
		if err != nil {
			return nil, err
		}
		p.Preflight = nil
		p.Runtime = nil
		return p, nil
	}
	other := redis.NewClient(db.Options())
	t.Cleanup(func() { _ = other.Close() })
	db.AddHook(&networkCASHook{before: func(ctx context.Context) {
		if err := other.HSet(ctx, "BUFFER_POOL|PORT3_INGRESS_POOL", "size", "12345").Err(); err != nil {
			t.Fatal(err)
		}
	}})
	if _, st := m.EnsureNetworkResource(t.Context(), req); st == nil || *saves != 0 {
		t.Fatal("stale buffer dependency accepted")
	}
	if db.Exists(t.Context(), "BUFFER_PG|Ethernet11|6").Val() != 0 {
		t.Fatal("CAS race wrote PG")
	}
}
