//go:build integration

// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/redis/go-redis/v9"
	"github.com/vishvananda/netlink"
)

func TestNetworkPortEngineOwnershipRecovery(t *testing.T) {
	m, db, _, _ := networkEngineFixture(t)
	m.planNetwork = nil
	for name, index := range map[string]int{"APPL_DB": 0, "ASIC_DB": 1, "COUNTERS_DB": 2} {
		opts := *db.Options()
		opts.DB = index
		client := redis.NewClient(&opts)
		t.Cleanup(func() { _ = client.Close() })
		m.clientPool[name] = client
	}
	seed := map[string]string{"speed": "1000", "mtu": "9100", "admin_status": "down", "lanes": "1", "index": "1", "subport": "0", "autoneg": "off", "alias": "preserve"}
	if err := db.HSet(t.Context(), "PORT|Ethernet0", seed).Err(); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		db, key string
		fields  map[string]string
	}{
		{"APPL_DB", "PORT_TABLE:Ethernet0", map[string]string{"speed": "1000", "mtu": "9100", "oper_status": "down"}},
		{"COUNTERS_DB", "COUNTERS_PORT_NAME_MAP", map[string]string{"Ethernet0": "oid:0x1000000000001"}},
		{"ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_PORT:oid:0x1000000000001", map[string]string{"SAI_PORT_ATTR_SPEED": "1000", "SAI_PORT_ATTR_MTU": "9122"}},
		{"ASIC_DB", "VIDTORID", map[string]string{"oid:0x1000000000001": "oid:0xabc"}},
	} {
		if err := m.clientPool[row.db].HSet(t.Context(), row.key, row.fields).Err(); err != nil {
			t.Fatal(err)
		}
	}
	savedPort := func(fields map[string]string) string {
		data, err := json.Marshal(map[string]any{"PORT": map[string]any{"Ethernet0": fields}})
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	saved := savedPort(seed)
	ctx := context.WithValue(t.Context(), routingCommandRunnerKey{}, routingCommandRunner(func(cmd *exec.Cmd) ([]byte, error) {
		if !reflect.DeepEqual(cmd.Args, []string{"cat", "/etc/sonic/config_db.json"}) {
			return nil, fmt.Errorf("unexpected command %v", cmd.Args)
		}
		return []byte(saved), nil
	}))
	saves, failSave := 0, false
	keepWrongSaved := false
	m.saveConfig = func(context.Context) *agent.Status {
		saves++
		if failSave {
			return &agent.Status{Code: 500}
		}
		if !keepWrongSaved {
			saved = savedPort(seed)
		}
		return nil
	}
	r := &agent.NetworkRequest{Kind: "Port", OwnerID: "port-owner", Spec: json.RawMessage(`{"nativeName":"Ethernet0","speed":1000,"mtu":9100}`)}
	got, st := m.GetNetworkResource(ctx, r)
	if st != nil || !got.ConfigurationVerified || !got.RuntimeVerified || got.PersistenceVerified || saves != 0 {
		t.Fatalf("Observe: %+v %+v", got, st)
	}
	foreign := *r
	foreign.Spec = json.RawMessage(`{"nativeName":"Ethernet0","speed":10000}`)
	if _, st := m.EnsureNetworkResource(ctx, &foreign); st == nil || saves != 0 {
		t.Fatal("overwrote foreign native field")
	}
	got, st = m.EnsureNetworkResource(ctx, r)
	if st != nil || !got.ConfigurationVerified || !got.RuntimeVerified || !got.PersistenceVerified || saves != 1 {
		t.Fatalf("adoption: %+v %+v saves=%d", got, st, saves)
	}
	actual, err := db.HGetAll(ctx, "PORT|Ethernet0").Result()
	if err != nil || !reflect.DeepEqual(actual, seed) {
		t.Fatalf("adoption changed port: %v %v", actual, err)
	}
	if _, st := m.EnsureNetworkResource(ctx, r); st != nil || saves != 1 {
		t.Fatal("no-op repeated save")
	}
	for _, tc := range []struct{ field, value string }{{"lanes", "2"}, {"index", "2"}, {"subport", "1"}, {"autoneg", "on"}, {"macsec", "profile"}} {
		t.Run("saved-only "+tc.field, func(t *testing.T) {
			changed := maps.Clone(seed)
			changed[tc.field] = tc.value
			saved = savedPort(changed)
			got, st := m.GetNetworkResource(ctx, r)
			if st != nil || !got.ConfigurationVerified || !got.RuntimeVerified || got.PersistenceVerified {
				t.Fatalf("saved-only layout drift accepted: %+v %+v", got, st)
			}
			keepWrongSaved = true
			got, st = m.EnsureNetworkResource(ctx, r)
			if st == nil || !got.ConfigurationVerified || !got.RuntimeVerified || got.PersistenceVerified {
				t.Fatalf("acknowledged wrong-layout save completed: %+v %+v", got, st)
			}
			keepWrongSaved = false
			got, st = m.EnsureNetworkResource(ctx, r)
			if st != nil || !got.PersistenceVerified {
				t.Fatalf("exact saved-layout recovery: %+v %+v", got, st)
			}
			live, err := db.HGetAll(ctx, "PORT|Ethernet0").Result()
			if err != nil || !reflect.DeepEqual(live, seed) {
				t.Fatal("saved repair changed unowned live port context")
			}
			data, err := os.ReadFile(filepath.Join(m.networkJournalDir, "network.json"))
			if err != nil {
				t.Fatal(err)
			}
			var journal networkJournalState
			if err := json.Unmarshal(data, &journal); err != nil {
				t.Fatal(err)
			}
			record := journal.Records["Port|Ethernet0"]
			if record.Pending != nil || !reflect.DeepEqual(record.Fields, vlanChangeDB{"PORT|Ethernet0": {"speed": "1000", "mtu": "9100"}}) {
				t.Fatal("layout became owned or recovery stayed pending")
			}
		})
	}
	if err := db.HSet(ctx, "PORT|Ethernet0", "lanes", "2").Err(); err != nil {
		t.Fatal(err)
	}
	m.linkByName = func(string) (netlink.Link, error) { return nil, lagL3MissingLinkFixture{} }
	vrf := &agent.NetworkRequest{Kind: "VRF", OwnerID: "vrf-owner", Spec: json.RawMessage(`{"name":"VrfOther"}`)}
	if _, st := m.EnsureNetworkResource(ctx, vrf); st != nil {
		t.Fatalf("unrelated save: %+v", st)
	}
	got, st = m.GetNetworkResource(ctx, r)
	if st != nil || got.PersistenceVerified || got.RuntimeVerified || !strings.Contains(got.Message, "layout") {
		t.Fatalf("unrelated save requalified changed layout: %+v %+v", got, st)
	}
	if err := db.HSet(ctx, "PORT|Ethernet0", "lanes", "1").Err(); err != nil {
		t.Fatal(err)
	}
	foreign = *r
	foreign.OwnerID = "other-owner"
	if _, st := m.EnsureNetworkResource(ctx, &foreign); st == nil {
		t.Fatal("transferred owner")
	}
	if err := db.HSet(ctx, "PORT|Ethernet0", "speed", "10000").Err(); err != nil {
		t.Fatal(err)
	}
	failSave = true
	got, st = m.EnsureNetworkResource(ctx, r)
	if st == nil || !got.ConfigurationVerified || got.PersistenceVerified {
		t.Fatalf("repair save failure: %+v %+v", got, st)
	}
	if value := db.HGet(ctx, "PORT|Ethernet0", "speed").Val(); value != "1000" {
		t.Fatalf("did not repair owned speed: %s", value)
	}
	restarted := &SonicAgent{networkJournalDir: m.networkJournalDir, clientPool: m.clientPool, saveConfig: m.saveConfig}
	failSave = false
	got, st = restarted.EnsureNetworkResource(ctx, r)
	if st != nil || !got.PersistenceVerified || !got.RuntimeVerified {
		t.Fatalf("restart recovery: %+v %+v", got, st)
	}
	if err := db.HSet(ctx, "PORT|Ethernet0", "lanes", "2", "speed", "10000").Err(); err != nil {
		t.Fatal(err)
	}
	if _, st := restarted.EnsureNetworkResource(ctx, r); st == nil {
		t.Fatal("restored old speed after topology change")
	}
	if db.HGet(ctx, "PORT|Ethernet0", "admin_status").Val() != "down" || db.HExists(ctx, "PORT|Ethernet0", "fec").Val() {
		t.Fatal("claimed omitted/admin field")
	}
}
