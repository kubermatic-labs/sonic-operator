//go:build integration

// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/redis/go-redis/v9"
)

func traditionalFixtureJSON(db vlanChangeDB) string {
	native := map[string]map[string]map[string]string{}
	for key, fields := range db {
		table, name, _ := strings.Cut(key, "|")
		if native[table] == nil {
			native[table] = map[string]map[string]string{}
		}
		native[table][name] = map[string]string{}
		for field, value := range fields {
			if field != "NULL" {
				native[table][name][field] = value
			}
		}
	}
	data, _ := json.Marshal(native)
	return string(data)
}

func TestTraditionalBGPEngineAdoptionRepairRecovery(t *testing.T) {
	m, db, _, _ := networkEngineFixture(t)
	m.planNetwork = nil
	opts := *db.Options()
	opts.DB = 6
	state := redis.NewClient(&opts)
	t.Cleanup(func() { _ = state.Close() })
	m.clientPool["STATE_DB"] = state
	opts.DB = 0
	app := redis.NewClient(&opts)
	t.Cleanup(func() { _ = app.Close() })
	m.clientPool["APPL_DB"] = app
	seed := traditionalDB()
	for key, fields := range seed {
		if err := db.HSet(t.Context(), key, fields).Err(); err != nil {
			t.Fatal(err)
		}
	}
	stateKey := "INTERFACE_TABLE|Loopback0|10.1.0.1/32"
	if err := state.HSet(t.Context(), stateKey, "state", "ok").Err(); err != nil {
		t.Fatal(err)
	}
	saved := traditionalFixtureJSON(seed)
	running, summary, bundle := traditionalRuntimeFixture, `{"default":{}}`, traditionalBundleDigest
	saves, restarts := 0, 0
	failSave, failRestart := false, false
	m.saveConfig = func(ctx context.Context) *agent.Status {
		saves++
		if failSave {
			return &agent.Status{Code: 500}
		}
		current, _, err := m.vlanChangeSnapshot(ctx)
		if err != nil {
			return &agent.Status{Code: 500}
		}
		saved = traditionalFixtureJSON(current)
		return nil
	}
	split := strings.SplitN(strings.ReplaceAll(traditionalRuntimeFixture, "PL_LoopbackV4 seq 5 permit", "PL_LoopbackV4 permit"), "route-map RM_SET_SRC permit 10", 2)
	render, _ := json.Marshal(map[string]string{"bgpd.conf": split[0], "zebra.conf": "! generated zebra\n", "staticd.conf": "! generated staticd\n", "setsrc.conf": "route-map RM_SET_SRC permit 10" + split[1]})
	ctx := context.WithValue(t.Context(), routingCommandRunnerKey{}, routingCommandRunner(func(cmd *exec.Cmd) ([]byte, error) {
		a := cmd.Args
		switch {
		case reflect.DeepEqual(a, []string{"python3", "-c", traditionalHostScript}):
			return []byte(traditionalHostDigest), nil
		case reflect.DeepEqual(a, []string{"cat", "/etc/sonic/config_db.json"}):
			return []byte(saved), nil
		case reflect.DeepEqual(a, []string{"docker", "exec", "bgp", "python3", "-c", traditionalBundleScript}):
			return []byte(bundle), nil
		case len(a) == 8 && a[0] == "docker" && a[5] == traditionalRenderScript:
			if a[6] != "saved" && a[6] != "candidate" {
				t.Fatalf("unexpected render source: %s", a[6])
			}
			return render, nil
		case reflect.DeepEqual(a, []string{"docker", "inspect", "bgp", "--format", "{{json .Mounts}}"}):
			return []byte(`[{"Type":"bind","Source":"/etc/sonic/frr","Destination":"/etc/frr","RW":true},{"Type":"bind","Source":"/etc/sonic","Destination":"/etc/sonic","RW":false}]`), nil
		case reflect.DeepEqual(a, []string{"docker", "exec", "bgp", "supervisorctl", "status"}):
			return []byte("bgpcfgd RUNNING\nbgpd RUNNING\nzebra RUNNING\nstaticd RUNNING\nfpmsyncd RUNNING\n"), nil
		case reflect.DeepEqual(a, []string{"docker", "exec", "bgp", "vtysh", "-c", "show running-config"}):
			return []byte(running), nil
		case reflect.DeepEqual(a, []string{"docker", "exec", "bgp", "vtysh", "-c", "show bgp vrf all summary json"}):
			return []byte(summary), nil
		case reflect.DeepEqual(a, []string{"systemctl", "restart", "bgp.service"}):
			restarts++
			if failRestart {
				return nil, fmt.Errorf("injected restart failure")
			}
			running = traditionalRuntimeFixture
			return nil, nil
		default:
			return nil, fmt.Errorf("unexpected test command")
		}
	}))
	r := &agent.NetworkRequest{Kind: "BGP", OwnerID: "bgp-owner", Spec: json.RawMessage(traditionalSpec)}
	got, st := m.GetNetworkResource(ctx, r)
	if st != nil || !got.ConfigurationVerified || !got.RuntimeVerified || got.PersistenceVerified || saves != 0 || restarts != 0 {
		t.Fatalf("Observe: %+v %+v", got, st)
	}
	got, st = m.EnsureNetworkResource(ctx, r)
	if st != nil || !got.PersistenceVerified || !got.RuntimeVerified || saves != 1 || restarts != 0 {
		t.Fatalf("equal adoption: %+v %+v saves=%d restarts=%d", got, st, saves, restarts)
	}
	current, _, err := m.vlanChangeSnapshot(ctx)
	if err != nil || !reflect.DeepEqual(seed, current) {
		t.Fatal("adoption changed CONFIG_DB")
	}
	if _, st := m.EnsureNetworkResource(ctx, r); st != nil || saves != 1 || restarts != 0 {
		t.Fatal("no-op performed native mutation")
	}
	foreign := *r
	foreign.OwnerID = "foreign"
	if _, st := m.EnsureNetworkResource(ctx, &foreign); st == nil {
		t.Fatal("transferred native BGP owner")
	}
	if err := db.HSet(ctx, "DEVICE_METADATA|localhost", "bgp_asn", "65101").Err(); err != nil {
		t.Fatal(err)
	}
	running = strings.ReplaceAll(traditionalRuntimeFixture, "router bgp 65100", "router bgp 65101")
	got, st = m.EnsureNetworkResource(ctx, r)
	if st != nil || !got.RuntimeVerified || !got.PersistenceVerified || restarts != 1 {
		t.Fatalf("metadata drift repair: %+v %+v restarts=%d", got, st, restarts)
	}
	running = strings.ReplaceAll(traditionalRuntimeFixture, " set src 10.1.0.1\n", "")
	got, st = m.EnsureNetworkResource(ctx, r)
	if st != nil || !got.RuntimeVerified || restarts != 2 {
		t.Fatalf("runtime-only source-policy repair: %+v %+v restarts=%d", got, st, restarts)
	}
	failSave = true
	saved = `{}`
	got, st = m.EnsureNetworkResource(ctx, r)
	if st == nil || got.PersistenceVerified || !got.RuntimeVerified {
		t.Fatalf("save failure: %+v %+v", got, st)
	}
	m = &SonicAgent{networkJournalDir: m.networkJournalDir, clientPool: m.clientPool, saveConfig: m.saveConfig}
	failSave = false
	got, st = m.EnsureNetworkResource(ctx, r)
	if st != nil || !got.PersistenceVerified || restarts != 2 {
		t.Fatalf("save recovery restarted consumer: %+v %+v restarts=%d", got, st, restarts)
	}
	running = strings.ReplaceAll(traditionalRuntimeFixture, " set src 10.1.0.1\n", "")
	failRestart = true
	got, st = m.EnsureNetworkResource(ctx, r)
	if st == nil || got.PersistenceVerified || restarts != 3 {
		t.Fatalf("failed restart not pending: %+v %+v", got, st)
	}
	m = &SonicAgent{networkJournalDir: m.networkJournalDir, clientPool: m.clientPool, saveConfig: m.saveConfig}
	if _, st = m.EnsureNetworkResource(ctx, r); st == nil || restarts != 3 {
		t.Fatal("replayed uncertain restart")
	}
	running = traditionalRuntimeFixture
	failRestart = false
	got, st = m.EnsureNetworkResource(ctx, r)
	if st != nil || !got.PersistenceVerified || restarts != 3 {
		t.Fatalf("restart evidence recovery: %+v %+v", got, st)
	}
	running = strings.ReplaceAll(traditionalRuntimeFixture, " bgp router-id", " neighbor 10.1.0.2 remote-as 65101\n bgp router-id")
	if _, st = m.EnsureNetworkResource(ctx, r); st == nil || restarts != 3 {
		t.Fatal("foreign runtime peer was overwritten")
	}
	running = traditionalRuntimeFixture
	if err := app.HSet(ctx, "STATIC_ROUTE:10.2.0.0/24", "nexthop", "10.1.0.2").Err(); err != nil {
		t.Fatal(err)
	}
	if _, st = m.EnsureNetworkResource(ctx, r); st == nil || restarts != 3 {
		t.Fatal("pending dynamic routing input accepted")
	}
	if err := app.Del(ctx, "STATIC_ROUTE:10.2.0.0/24").Err(); err != nil {
		t.Fatal(err)
	}
	var savedNative map[string]any
	_ = json.Unmarshal([]byte(saved), &savedNative)
	savedNative["BGP_NEIGHBOR"] = map[string]any{"10.1.0.2": map[string]any{"asn": "65101"}}
	changedSaved, _ := json.Marshal(savedNative)
	saved = string(changedSaved)
	got, st = m.GetNetworkResource(ctx, r)
	if st != nil || !got.RuntimeVerified || got.PersistenceVerified {
		t.Fatalf("saved-only peer was not detected independently: %+v %+v", got, st)
	}
	got, st = m.EnsureNetworkResource(ctx, r)
	if st != nil || !got.PersistenceVerified || restarts != 3 {
		t.Fatalf("saved-source repair restarted native runtime: %+v %+v", got, st)
	}
	if err := state.Del(ctx, stateKey).Err(); err != nil {
		t.Fatal(err)
	}
	got, st = m.GetNetworkResource(ctx, r)
	if st != nil || !got.PersistenceVerified || got.RuntimeVerified {
		t.Fatalf("persistence depends on runtime: %+v %+v", got, st)
	}
	if _, st = m.EnsureNetworkResource(ctx, r); st == nil || restarts != 3 {
		t.Fatal("missing loopback state caused restart")
	}
	bundle = "unqualified"
	if _, st = m.EnsureNetworkResource(ctx, r); st == nil || restarts != 3 {
		t.Fatal("unqualified consumer permitted mutation")
	}
}
