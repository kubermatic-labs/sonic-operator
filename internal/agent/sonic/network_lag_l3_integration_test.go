//go:build integration

// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/redis/go-redis/v9"
	"github.com/vishvananda/netlink"
)

func TestNetworkLAGVLANRedis(t *testing.T) {
	rdb := newVLANRedis(t)
	for _, tc := range []struct {
		name, key string
		fields    map[string]string
	}{
		{"valid", "", nil},
		{"routed LAG", "PORTCHANNEL_INTERFACE|PortChannel10|192.0.2.1/24", map[string]string{"NULL": "NULL"}},
		{"routed member", "INTERFACE|Ethernet0|192.0.2.1/24", map[string]string{"NULL": "NULL"}},
		{"VLAN member", "VLAN_MEMBER|Vlan200|Ethernet0", map[string]string{"tagging_mode": "tagged"}},
		{"other LAG", "PORTCHANNEL_MEMBER|PortChannel20|Ethernet0", map[string]string{"NULL": "NULL"}},
		{"unknown member fields", "PORTCHANNEL_MEMBER|PortChannel10|Ethernet0", map[string]string{"future": "opaque"}},
		{"legacy VLAN selector", "VLAN|Vlan200", map[string]string{"vlanid": "200", "members@": "Ethernet0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := rdb.FlushDB(t.Context()).Err(); err != nil {
				t.Fatal(err)
			}
			db := lagL3Fixture()
			db["VLAN|Vlan100"]["description"] = "preserve"
			db["PORTCHANNEL|PortChannel10"] = map[string]string{"admin_status": "up", "description": "preserve"}
			db["PORTCHANNEL_MEMBER|PortChannel10|Ethernet0"] = map[string]string{"NULL": "NULL"}
			for key, fields := range db {
				if err := rdb.HSet(t.Context(), key, fields).Err(); err != nil {
					t.Fatal(err)
				}
			}
			if tc.key != "" {
				if err := rdb.HSet(t.Context(), tc.key, tc.fields).Err(); err != nil {
					t.Fatal(err)
				}
			}
			result, err := rdb.Eval(t.Context(), vlanScript, []string{"VLAN|Vlan100"}, "100", "1", "PortChannel10", "tagged").Slice()
			if err != nil {
				t.Fatal(err)
			}
			if (result[0].(int64) == 0) != (tc.key == "") {
				t.Fatalf("unexpected result: %v", result)
			}
			if tc.key != "" && rdb.Exists(t.Context(), "VLAN_MEMBER|Vlan100|PortChannel10").Val() != 0 {
				t.Fatal("wrote before validation")
			}
			for _, key := range []string{"VLAN|Vlan100", "PORT|Ethernet0", "PORTCHANNEL|PortChannel10"} {
				got, err := rdb.HGetAll(t.Context(), key).Result()
				if err != nil || !reflect.DeepEqual(got, db[key]) {
					t.Fatalf("modified %s: %v %v", key, got, err)
				}
			}
		})
	}
	t.Run("agent acceptance", func(t *testing.T) {
		if err := rdb.FlushDB(t.Context()).Err(); err != nil {
			t.Fatal(err)
		}
		seed := vlanChangeDB{"PORT|Ethernet0": {"speed": "100000"}, "PORTCHANNEL|PortChannel10": {"admin_status": "up"}, "PORTCHANNEL_MEMBER|PortChannel10|Ethernet0": {"NULL": "NULL"}}
		for key, fields := range seed {
			if err := rdb.HSet(t.Context(), key, fields).Err(); err != nil {
				t.Fatal(err)
			}
		}
		saves := 0
		m := &SonicAgent{clientPool: map[string]*redis.Client{"CONFIG_DB": rdb}, saveConfig: func(context.Context) *agent.Status { saves++; return nil }}
		// A read-only script exercise above proves preservation; this call also
		// verifies Go name validation passes through to the atomic Lua check.
		_, status := m.GetVLAN(t.Context(), 100)
		if status == nil {
			t.Fatal("uncreated VLAN unexpectedly present")
		}
		r := &agent.VLANAuthorityRequest{OwnerID: "owner", VLAN: &agent.VLAN{ID: 100, Members: []agent.VLANMember{{InterfaceName: "PortChannel10", TaggingMode: "tagged"}}}}
		if err := validateVLANAuthority(r); err != nil {
			t.Fatal(err)
		}
		got, status := m.EnsureVLAN(t.Context(), r.VLAN)
		if status != nil || saves != 1 || !reflect.DeepEqual(got, r.VLAN) {
			t.Fatalf("LAG VLAN: %+v %+v saves=%d", got, status, saves)
		}
	})
}

func TestNetworkLAGL3AbsentGetEnsureGet(t *testing.T) {
	for _, tc := range []struct{ kind, spec, target, link string }{
		{"PortChannel", `{"name":"PortChannel10","members":["Ethernet0"]}`, "PORTCHANNEL|PortChannel10", "PortChannel10"},
		{"VRF", `{"name":"VrfNew"}`, "VRF|VrfNew", "VrfNew"},
		{"L3Interface", `{"name":"Vlan100","addresses":["192.0.2.1/24"]}`, "VLAN_INTERFACE|Vlan100", "Vlan100"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			m, db, _, saves := networkEngineFixture(t)
			// Use the real dispatch, planner and runtime closure. Only Redis,
			// netlink and persistence are fixtures; no plan/runtime replacement.
			m.planNetwork = nil
			options := *db.Options()
			options.DB = 0
			app := redis.NewClient(&options)
			t.Cleanup(func() { _ = app.Close() })
			m.clientPool["APPL_DB"] = app
			for key, fields := range lagL3Fixture() {
				if err := db.HSet(t.Context(), key, fields).Err(); err != nil {
					t.Fatal(err)
				}
			}
			var linkErr error = lagL3MissingLinkFixture{}
			lookups := 0
			m.linkByName = func(name string) (netlink.Link, error) {
				if name != tc.link {
					t.Fatalf("unexpected lookup %s", name)
				}
				lookups++
				return nil, linkErr
			}
			r := &agent.NetworkRequest{Kind: tc.kind, OwnerID: "creation-owner", Spec: json.RawMessage(tc.spec)}
			before, _, err := m.vlanChangeSnapshot(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			got, status := m.GetNetworkResource(t.Context(), r)
			if status != nil || got == nil || got.Exists || got.ConfigurationVerified || got.RuntimeVerified || *saves != 0 || lookups != 1 {
				t.Fatalf("initial Get must permit creation: %+v status=%+v saves=%d lookups=%d", got, status, *saves, lookups)
			}
			after, _, err := m.vlanChangeSnapshot(t.Context())
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("Get changed configuration")
			}
			got, status = m.EnsureNetworkResource(t.Context(), r)
			if status != nil || got == nil || !got.Exists || !got.ConfigurationVerified || !got.PersistenceVerified || got.RuntimeVerified || *saves != 1 {
				t.Fatalf("Ensure while kernel converges: %+v status=%+v saves=%d", got, status, *saves)
			}
			if db.Exists(t.Context(), tc.target).Val() != 1 {
				t.Fatal("production planner target not created")
			}
			got, status = m.GetNetworkResource(t.Context(), r)
			if status != nil || got == nil || !got.Exists || !got.ConfigurationVerified || !got.PersistenceVerified || got.RuntimeVerified || *saves != 1 || lookups < 3 {
				t.Fatalf("post-create Get: %+v status=%+v saves=%d lookups=%d", got, status, *saves, lookups)
			}
			linkErr = errors.New("netlink access denied")
			got, status = m.GetNetworkResource(t.Context(), r)
			if status == nil || got == nil || got.RuntimeVerified || !got.ConfigurationVerified || *saves != 1 {
				t.Fatalf("access error hidden: %+v %+v", got, status)
			}
		})
	}
}

func TestNetworkLAGL3CoexistRedis(t *testing.T) {
	for _, order := range []struct {
		name  string
		first bool
	}{{"routing first", true}, {"LAG first", false}} {
		t.Run(order.name, func(t *testing.T) {
			m, rdb, _, _ := networkEngineFixture(t)
			m.planNetwork = func(db vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
				p, err := planNetworkResource(db, r)
				if err == nil {
					// Exercise real planners, CAS and journal against disposable Redis.
					// Hardware/service evidence is tested separately with injected reads.
					p.Runtime = func(context.Context, *SonicAgent) (bool, json.RawMessage, error) {
						return true, json.RawMessage(`{"fixture":true}`), nil
					}
					p.Preflight = nil
					p.Activate = nil
				}
				return p, err
			}
			seed := lagL3CoexistDB()
			for key, fields := range seed {
				if err := rdb.HSet(t.Context(), key, fields).Err(); err != nil {
					t.Fatal(err)
				}
			}
			requests := lagL3CoexistRequests(order.first)
			for pass := 0; pass < 2; pass++ {
				for _, r := range requests {
					// Distinct route identities must also have distinct owner UIDs.
					r.OwnerID = r.Kind + string(r.Spec)
					got, status := m.EnsureNetworkResource(t.Context(), r)
					if status != nil || got == nil || !got.ConfigurationVerified || !got.PersistenceVerified {
						t.Fatalf("pass %d %s: %+v %+v", pass, r.Kind, got, status)
					}
				}
			}
			for key, fields := range seed {
				got, err := rdb.HGetAll(t.Context(), key).Result()
				if err != nil {
					t.Fatal(err)
				}
				for field, value := range fields {
					if got[field] != value {
						t.Fatalf("changed unmanaged %s/%s", key, field)
					}
				}
			}
		})
	}
}
