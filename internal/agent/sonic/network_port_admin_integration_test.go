//go:build integration

// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os/exec"
	"reflect"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/redis/go-redis/v9"
)

// Real Redis and the production port planner exercise the shared write lock,
// full-CONFIG_DB fingerprint, saved-input callback and durable recovery together
// with the independent admin persistence reader. Only native file/save IO
// is injected; every saved snapshot is derived from this fixture's live PORT.
func TestNetworkPortAdminPersistenceAndPendingRecovery(t *testing.T) {
	m, db, _, _ := networkEngineFixture(t)
	m.planNetwork = nil
	for name, index := range map[string]int{"APPL_DB": 0, "ASIC_DB": 1, "COUNTERS_DB": 2} {
		opts := *db.Options()
		opts.DB = index
		rdb := redis.NewClient(&opts)
		t.Cleanup(func() { _ = rdb.Close() })
		m.clientPool[name] = rdb
	}
	seed := map[string]string{"speed": "1000", "mtu": "9100", "lanes": "1", "index": "1", "admin_status": "down", "alias": "preserve"}
	for _, row := range []struct {
		db, key string
		fields  map[string]string
	}{
		{"CONFIG_DB", "PORT|Ethernet0", seed},
		{"APPL_DB", "PORT_TABLE:Ethernet0", map[string]string{"speed": "1000", "mtu": "9100", "oper_status": "down"}},
		{"COUNTERS_DB", "COUNTERS_PORT_NAME_MAP", map[string]string{"Ethernet0": "oid:0x1000000000001"}},
		{"ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_PORT:oid:0x1000000000001", map[string]string{"SAI_PORT_ATTR_SPEED": "1000", "SAI_PORT_ATTR_MTU": "9122"}},
		{"ASIC_DB", "VIDTORID", map[string]string{"oid:0x1000000000001": "oid:0xabc"}},
	} {
		if err := m.clientPool[row.db].HSet(t.Context(), row.key, row.fields).Err(); err != nil {
			t.Fatal(err)
		}
	}
	savedFields := maps.Clone(seed)
	malformedSaved := false
	readSaved := func() ([]byte, error) {
		if malformedSaved {
			return []byte(`{"PORT":null}`), nil
		}
		return json.Marshal(map[string]any{"PORT": map[string]any{"Ethernet0": savedFields}})
	}
	m.readSavedPortConfig = readSaved
	ctx := context.WithValue(t.Context(), routingCommandRunnerKey{}, routingCommandRunner(func(cmd *exec.Cmd) ([]byte, error) {
		if !reflect.DeepEqual(cmd.Args, []string{"cat", "/etc/sonic/config_db.json"}) {
			return nil, fmt.Errorf("unexpected native command %v", cmd.Args)
		}
		return readSaved()
	}))
	saves, wrongSavedSpeed := 0, false
	m.saveConfig = func(context.Context) *agent.Status {
		saves++
		var err error
		savedFields, err = db.HGetAll(ctx, "PORT|Ethernet0").Result()
		if err != nil {
			t.Fatal(err)
		}
		if wrongSavedSpeed {
			savedFields["speed"] = "10000"
		}
		return nil
	}
	r := &agent.NetworkRequest{Kind: "Port", OwnerID: "same-interface-uid", Spec: json.RawMessage(`{"nativeName":"Ethernet0","speed":1000,"mtu":9100}`)}
	if got, st := m.EnsureNetworkResource(ctx, r); st != nil || !got.PersistenceVerified || !got.RuntimeVerified || saves != 1 {
		t.Fatalf("port adoption: %+v %+v saves=%d", got, st, saves)
	}
	admin := &agent.Interface{Name: "Ethernet0", NativeName: "Ethernet0", AdminStatus: agent.StatusUp}
	if got, st := m.SetInterfaceAdminStatus(ctx, admin); st != nil || !got.AdminPersistenceVerified || saves != 2 {
		t.Fatalf("admin save after typed adoption: %+v %+v saves=%d", got, st, saves)
	}
	want := maps.Clone(seed)
	want["admin_status"] = "up"
	if live := db.HGetAll(ctx, "PORT|Ethernet0").Val(); !reflect.DeepEqual(live, want) {
		t.Fatalf("admin write changed typed fields/layout: %v", live)
	}
	if got, st := m.GetNetworkResource(ctx, r); st != nil || !got.ConfigurationVerified || !got.RuntimeVerified || got.PersistenceVerified {
		t.Fatalf("admin write must invalidate the old full-snapshot proof: %+v %+v", got, st)
	}
	if got, st := m.EnsureNetworkResource(ctx, r); st != nil || !got.PersistenceVerified || saves != 3 {
		t.Fatalf("admin-only change incorrectly invalidated port layout adoption: %+v %+v", got, st)
	}
	// Admin persistence alone cannot qualify a saved speed mismatch.
	savedFields["speed"] = "10000"
	if got, st := m.SetInterfaceAdminStatus(ctx, admin); st != nil || !got.AdminPersistenceVerified || saves != 3 {
		t.Fatalf("matching admin unnecessarily rewrote saved configuration: %+v %+v", got, st)
	}
	if got, st := m.GetNetworkResource(ctx, r); st != nil || !got.ConfigurationVerified || !got.RuntimeVerified || got.PersistenceVerified {
		t.Fatalf("admin proof hid saved typed-field drift: %+v %+v", got, st)
	}
	wrongSavedSpeed = true
	if got, st := m.EnsureNetworkResource(ctx, r); st == nil || !got.ConfigurationVerified || !got.RuntimeVerified || got.PersistenceVerified || saves != 4 {
		t.Fatalf("acknowledged wrong save must remain pending: %+v %+v", got, st)
	}
	// Both an equal admin adoption and a changed admin request are blocked by
	// the persisted network operation, including after process replacement.
	m = &SonicAgent{networkJournalDir: m.networkJournalDir, clientPool: m.clientPool, saveConfig: m.saveConfig, readSavedPortConfig: readSaved}
	for _, state := range []agent.DeviceStatus{agent.StatusUp, agent.StatusDown} {
		admin.AdminStatus = state
		if _, st := m.SetInterfaceAdminStatus(ctx, admin); st == nil || saves != 4 {
			t.Fatal("admin setter bypassed pending typed persistence")
		}
	}
	if live := db.HGetAll(ctx, "PORT|Ethernet0").Val(); !reflect.DeepEqual(live, want) {
		t.Fatal("blocked admin request changed live configuration")
	}
	wrongSavedSpeed = false
	if got, st := m.RecoverNetworkResource(ctx, r); st != nil || !got.PersistenceVerified || !got.RuntimeVerified || saves != 5 {
		t.Fatalf("saved callback recovery after restart: %+v %+v", got, st)
	}
	malformedSaved = true
	if got, st := m.GetNetworkResource(ctx, r); st == nil || got.PersistenceVerified || !got.ConfigurationVerified || !got.RuntimeVerified {
		t.Fatalf("malformed saved input did not fail independently: %+v %+v", got, st)
	}
	if _, st := m.EnsureNetworkResource(ctx, r); st == nil || saves != 5 {
		t.Fatal("invalid saved evidence bypassed no-op callback or triggered save")
	}
	malformedSaved = false
	if got, st := m.SetInterfaceAdminStatus(ctx, admin); st != nil || !got.AdminPersistenceVerified || saves != 6 {
		t.Fatalf("completed recovery did not release admin writer: %+v %+v", got, st)
	}
	if live := db.HGetAll(ctx, "PORT|Ethernet0").Val(); !reflect.DeepEqual(live, seed) {
		t.Fatalf("final admin update changed typed/unowned fields: %v", live)
	}
}
