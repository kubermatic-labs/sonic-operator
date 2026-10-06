//go:build integration

// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/redis/go-redis/v9"
)

func TestTraditionalBGPCompleteLoopbackStateSet(t *testing.T) {
	for _, tc := range []struct{ name, address, state string }{
		{"IPv4 ambiguity", "10.1.0.2/32", "ok"},
		{"IPv6 policy", "2001:db8::1/128", "ok"},
		{"malformed source", "not-a-prefix", "ok"},
		{"not-yet-ready source", "10.1.0.2/32", "pending"},
	} {
		for _, phase := range []string{"adoption", "owned repair", "dispatch"} {
			t.Run(tc.name+"/"+phase, func(t *testing.T) {
				m, db, _, _ := networkEngineFixture(t)
				m.planNetwork = nil
				for name, index := range map[string]int{"STATE_DB": 6, "APPL_DB": 0} {
					opts := *db.Options()
					opts.DB = index
					c := redis.NewClient(&opts)
					t.Cleanup(func() { _ = c.Close() })
					m.clientPool[name] = c
				}
				state := m.clientPool["STATE_DB"]
				seed := traditionalDB()
				for key, fields := range seed {
					if err := db.HSet(t.Context(), key, fields).Err(); err != nil {
						t.Fatal(err)
					}
				}
				if err := state.HSet(t.Context(), "INTERFACE_TABLE|Loopback0|10.1.0.1/32", "state", "ok").Err(); err != nil {
					t.Fatal(err)
				}
				extra := "INTERFACE_TABLE|Loopback0|" + tc.address
				addExtra := func() {
					t.Helper()
					if err := state.HSet(t.Context(), extra, "state", tc.state).Err(); err != nil {
						t.Fatal(err)
					}
				}
				journalPath := filepath.Join(m.networkJournalDir, "network.json")
				loadRecord := func() *networkRecord {
					t.Helper()
					data, err := os.ReadFile(journalPath)
					if os.IsNotExist(err) {
						return nil
					}
					if err != nil {
						t.Fatal(err)
					}
					var journal networkJournalState
					if err := json.Unmarshal(data, &journal); err != nil {
						t.Fatal(err)
					}
					return journal.Records["BGP|default"]
				}
				saved, running := traditionalFixtureJSON(seed), traditionalRuntimeFixture
				render, _ := json.Marshal(map[string]string{"bgpd.conf": strings.ReplaceAll(traditionalRuntimeFixture, "PL_LoopbackV4 seq 5 permit", "PL_LoopbackV4 permit"), "zebra.conf": "! baseline", "staticd.conf": "! baseline", "setsrc.conf": "! baseline"})
				saves, restarts := 0, 0
				injectAtDispatch := false
				m.saveConfig = func(context.Context) *agent.Status { saves++; return nil }
				ctx := context.WithValue(t.Context(), routingCommandRunnerKey{}, routingCommandRunner(func(cmd *exec.Cmd) ([]byte, error) {
					a := cmd.Args
					switch {
					case reflect.DeepEqual(a, []string{"python3", "-c", traditionalHostScript}):
						if injectAtDispatch {
							if record := loadRecord(); record != nil && record.Pending != nil && record.Pending.Activation == "Dispatched" {
								addExtra()
								injectAtDispatch = false
							}
						}
						return []byte(traditionalHostDigest), nil
					case reflect.DeepEqual(a, []string{"cat", "/etc/sonic/config_db.json"}):
						return []byte(saved), nil
					case len(a) == 6 && a[5] == traditionalBundleScript:
						return []byte(traditionalBundleDigest), nil
					case len(a) == 8 && a[5] == traditionalRenderScript:
						return render, nil
					case reflect.DeepEqual(a, []string{"docker", "inspect", "bgp", "--format", "{{json .Mounts}}"}):
						return []byte(`[{"Type":"bind","Source":"/etc/sonic/frr","Destination":"/etc/frr","RW":true},{"Type":"bind","Source":"/etc/sonic","Destination":"/etc/sonic","RW":false}]`), nil
					case reflect.DeepEqual(a, []string{"docker", "exec", "bgp", "supervisorctl", "status"}):
						return []byte("bgpcfgd RUNNING\nbgpd RUNNING\nzebra RUNNING\nstaticd RUNNING\nfpmsyncd RUNNING\n"), nil
					case reflect.DeepEqual(a, []string{"docker", "exec", "bgp", "vtysh", "-c", "show running-config"}):
						return []byte(running), nil
					case reflect.DeepEqual(a, []string{"docker", "exec", "bgp", "vtysh", "-c", "show bgp vrf all summary json"}):
						return []byte(`{"default":{}}`), nil
					case reflect.DeepEqual(a, []string{"systemctl", "restart", "bgp.service"}):
						restarts++
						return nil, nil
					default:
						return nil, fmt.Errorf("unexpected test command")
					}
				}))
				r := &agent.NetworkRequest{Kind: "BGP", OwnerID: "bgp-owner", Spec: json.RawMessage(traditionalSpec)}
				if phase != "adoption" {
					if got, st := m.EnsureNetworkResource(ctx, r); st != nil || !got.PersistenceVerified {
						t.Fatalf("initial adoption: %+v %+v", got, st)
					}
				}
				beforeSaves := saves
				if phase == "dispatch" {
					injectAtDispatch = true
				} else {
					addExtra()
					got, st := m.GetNetworkResource(ctx, r)
					if got == nil || got.RuntimeVerified || !got.ConfigurationVerified || got.PersistenceVerified != (phase != "adoption") {
						t.Errorf("extra source qualified runtime or erased saved proof: %+v %+v", got, st)
					}
				}
				if phase != "adoption" {
					running = strings.ReplaceAll(traditionalRuntimeFixture, " set src 10.1.0.1\n", "")
				}
				got, st := m.EnsureNetworkResource(ctx, r)
				if st == nil || got == nil || got.RuntimeVerified || restarts != 0 || saves != beforeSaves {
					t.Fatalf("extra source permitted adoption/repair: %+v %+v restarts=%d saves=%d", got, st, restarts, saves)
				}
				record := loadRecord()
				if phase == "adoption" && record != nil {
					t.Fatal("known extra source acquired durable ownership")
				}
				if phase == "dispatch" {
					if record == nil || record.Pending == nil || record.Pending.Activation != "Dispatched" {
						t.Fatal("late input lost durable dispatch state")
					}
				} else if record != nil && record.Pending != nil {
					t.Fatal("known extra source prepared a native operation")
				}
				running = traditionalRuntimeFixture
				plan, err := planNetworkResource(seed, r)
				if err != nil {
					t.Fatal(err)
				}
				if err := plan.Activate(ctx, m); err == nil || restarts != 0 {
					t.Fatal("activation did not recheck complete STATE_DB source set")
				}
				fields, err := state.HGetAll(ctx, extra).Result()
				if err != nil || !reflect.DeepEqual(fields, map[string]string{"state": tc.state}) {
					t.Fatal("unowned STATE_DB input was modified")
				}
				current, _, err := m.vlanChangeSnapshot(ctx)
				if err != nil || !reflect.DeepEqual(current, seed) {
					t.Fatal("source conflict changed CONFIG_DB")
				}
				if phase == "dispatch" {
					if err := state.Del(ctx, extra).Err(); err != nil {
						t.Fatal(err)
					}
					got, st := m.EnsureNetworkResource(ctx, r)
					if st != nil || !got.PersistenceVerified || restarts != 0 || loadRecord().Pending != nil {
						t.Fatalf("readback recovery replayed activation: %+v %+v", got, st)
					}
				}
			})
		}
	}
}
