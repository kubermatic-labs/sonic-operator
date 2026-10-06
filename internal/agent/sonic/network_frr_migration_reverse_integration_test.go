//go:build integration

// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"bytes"
	"context"
	"encoding/base64"
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

func frrMigrationCycleFixture(t *testing.T) (*SonicAgent, *redis.Client, *agent.NetworkRequest, *frrMigrationFixture, *int) {
	t.Helper()
	m, db, req, f, saves := frrMigrationEngine(t, true)
	f.restartHook = func() {
		f.separated = db.HGet(t.Context(), "DEVICE_METADATA|localhost", "docker_routing_config_mode").Val() == "separated"
	}
	frrMigrationApprove(t, m, req, f)
	if out, st := m.EnsureNetworkResource(f.ctx(t), req); st != nil || !out.PersistenceVerified {
		t.Fatalf("initial forward: %+v %v", out, st)
	}
	req.Spec = json.RawMessage(`{"mode":"Traditional"}`)
	return m, db, req, f, saves
}

func TestFRRMigrationReverseCycles(t *testing.T) {
	m, db, req, f, saves := frrMigrationCycleFixture(t)
	legacy := map[string][]byte{}
	for _, name := range []string{"launch.json", "backup.json"} {
		data, err := os.ReadFile(filepath.Join(m.networkJournalDir, "frr-migration", name))
		if err != nil {
			t.Fatal(err)
		}
		legacy[name] = data
	}
	digests := map[string]bool{}
	for i, mode := range []string{"Traditional", "Unified", "Traditional", "Unified"} {
		req.Spec = json.RawMessage(`{"mode":"` + mode + `"}`)
		// Earlier approvals, including a previous transition in this same
		// direction, must never authorize another cycle.
		for stale := range digests {
			req.Spec = json.RawMessage(`{"mode":"` + mode + `","approvedDigest":"` + stale + `"}`)
			if _, st := m.EnsureNetworkResource(f.ctx(t), req); st == nil || f.restarts != i+1 {
				t.Fatal("old cycle approval replayed")
			}
		}
		digest := frrMigrationApprove(t, m, req, f)
		if digests[digest] {
			t.Fatal("approval reused across cycles")
		}
		digests[digest] = true
		before, _, _ := m.vlanChangeSnapshot(t.Context())
		if out, st := m.EnsureNetworkResource(f.ctx(t), req); st != nil || !out.ConfigurationVerified || !out.RuntimeVerified || !out.PersistenceVerified {
			t.Fatalf("%s: %+v %v", mode, out, st)
		}
		after, _, _ := m.vlanChangeSnapshot(t.Context())
		if !reflect.DeepEqual(after, frrMigrationPost(before, mode)) || f.restarts != i+2 || *saves != i+2 {
			t.Fatalf("transition %s writes/restarts", mode)
		}
		receipt, err := frrMigrationReceiptFile(m.networkJournalDir, nil, digest)
		if err != nil || receipt.Mode != mode || receipt.Owner != req.OwnerID || receipt.PreHash != vlanAuthorityHash(before) || receipt.PostHash != vlanAuthorityHash(after) {
			t.Fatalf("receipt binding %+v %v", receipt, err)
		}
		// Restart the agent and clear approval: same-mode is an exact no-op.
		m = &SonicAgent{networkJournalDir: m.networkJournalDir, clientPool: map[string]*redis.Client{"CONFIG_DB": db}, saveConfig: func(context.Context) *agent.Status { (*saves)++; return nil }}
		req.Spec = json.RawMessage(`{"mode":"` + mode + `"}`)
		if out, st := m.EnsureNetworkResource(f.ctx(t), req); st != nil || !out.PersistenceVerified || !out.RuntimeVerified || f.restarts != i+2 || *saves != i+2 {
			t.Fatalf("no-op: %+v %v", out, st)
		}
		for name, want := range legacy {
			got, err := os.ReadFile(filepath.Join(m.networkJournalDir, "frr-migration", name))
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal("original artifact replaced", name, err)
			}
		}
	}
}

func TestFRRMigrationTerminalRefreshAfterOrdinaryVLANSave(t *testing.T) {
	for _, mode := range []string{"Unified", "Traditional"} {
		for _, approval := range []string{"cleared", "old"} {
			t.Run(mode+"/"+approval, func(t *testing.T) {
				m, _, req, f, saves := frrMigrationCycleFixture(t)
				forward, err := frrMigrationReceiptFile(m.networkJournalDir, nil)
				if err != nil {
					t.Fatal(err)
				}
				digest := forward.Digest
				if mode == "Traditional" {
					digest = frrMigrationApprove(t, m, req, f)
					if out, st := m.EnsureNetworkResource(f.ctx(t), req); st != nil || !out.PersistenceVerified {
						t.Fatalf("complete reverse: %+v %v", out, st)
					}
				}
				restarts, initialSaves := f.restarts, *saves
				completed, err := frrMigrationRecord(m)
				if err != nil || completed == nil || completed.Pending != nil {
					t.Fatalf("completed migration record: %+v %v", completed, err)
				}

				// Exercise the real ordinary VLAN writer and its full-DB save, not
				// a direct Redis edit or the network engine's shared-proof refresh.
				if vlan, st := m.EnsureVLAN(t.Context(), &agent.VLAN{ID: 123}); st != nil || vlan == nil || vlan.ID != 123 {
					t.Fatalf("ordinary VLAN save: %+v %v", vlan, st)
				}
				afterVLAN, _, err := m.vlanChangeSnapshot(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				hash := vlanAuthorityHash(afterVLAN)
				stale, err := frrMigrationRecord(m)
				if err != nil || stale == nil || stale.Pending != nil || stale.Fingerprint != completed.Fingerprint || stale.Fingerprint == hash || afterVLAN["VLAN|Vlan123"]["vlanid"] != "123" || *saves != initialSaves+1 || f.restarts != restarts {
					t.Fatalf("VLAN did not leave stale migration persistence proof: %+v %v saves=%d restarts=%d", stale, err, *saves, f.restarts)
				}

				req.Spec = json.RawMessage(`{"mode":"` + mode + `"}`)
				if approval == "old" {
					req.Spec = json.RawMessage(`{"mode":"` + mode + `","approvedDigest":"` + digest + `"}`)
				}
				if out, st := m.GetNetworkResource(f.ctx(t), req); st != nil || !out.ConfigurationVerified || !out.RuntimeVerified || out.PersistenceVerified {
					t.Fatalf("terminal observation after VLAN save: %+v %v", out, st)
				}
				if out, st := m.EnsureNetworkResource(f.ctx(t), req); st != nil || !out.ConfigurationVerified || !out.RuntimeVerified || !out.PersistenceVerified || f.restarts != restarts || *saves != initialSaves+2 {
					t.Fatalf("terminal persistence refresh: %+v %v saves=%d restarts=%d", out, st, *saves, f.restarts)
				}
				refreshed, err := frrMigrationRecord(m)
				if err != nil || refreshed == nil || refreshed.Pending != nil || refreshed.Fingerprint != hash || refreshed.OwnerID != req.OwnerID || !reflect.DeepEqual(refreshed.Fields, completed.Fields) || !reflect.DeepEqual(refreshed.Owned, completed.Owned) {
					t.Fatalf("refreshed durable proof: %+v %v", refreshed, err)
				}
				if out, st := m.EnsureNetworkResource(f.ctx(t), req); st != nil || !out.PersistenceVerified || f.restarts != restarts || *saves != initialSaves+2 {
					t.Fatalf("refreshed no-op: %+v %v", out, st)
				}

				// Terminal bypass is target-specific. Neither absent approval nor
				// the completed transition's digest authorizes changing direction.
				opposite := "Traditional"
				if mode == "Traditional" {
					opposite = "Unified"
				}
				for _, old := range []string{"", digest} {
					req.Spec = json.RawMessage(`{"mode":"` + opposite + `","approvedDigest":"` + old + `"}`)
					if _, st := m.EnsureNetworkResource(f.ctx(t), req); st == nil {
						t.Fatal("terminal approval bypass authorized a transition")
					}
				}
				after, _, err := m.vlanChangeSnapshot(t.Context())
				if err != nil || !reflect.DeepEqual(after, afterVLAN) || f.restarts != restarts || *saves != initialSaves+2 {
					t.Fatalf("refresh or rejected transition mutated configuration: %v saves=%d restarts=%d", err, *saves, f.restarts)
				}
			})
		}
	}
}

func TestFRRMigrationReverseRefusals(t *testing.T) {
	for _, failure := range []string{"no-approval", "forward-approval", "stale-db", "stale-runtime", "stale-template", "db-route", "db-peer", "runtime-peer", "runtime-route", "candidate", "split", "foreign-owner", "owned-drift", "storage-permissions", "receipt-conflict"} {
		t.Run(failure, func(t *testing.T) {
			m, db, req, f, saves := frrMigrationCycleFixture(t)
			legacyPath := filepath.Join(m.networkJournalDir, "frr-migration", "launch.json")
			legacy, _ := os.ReadFile(legacyPath)
			digest := frrMigrationApprove(t, m, req, f)
			switch failure {
			case "no-approval":
				req.Spec = json.RawMessage(`{"mode":"Traditional"}`)
			case "forward-approval":
				var receipt frrMigrationReceipt
				_ = json.Unmarshal(legacy, &receipt)
				req.Spec = json.RawMessage(`{"mode":"Traditional","approvedDigest":"` + receipt.Digest + `"}`)
			case "stale-db":
				db.HSet(t.Context(), "PORT|Ethernet0", "description", "new")
			case "stale-runtime":
				f.config = strings.ReplaceAll(f.config, "zebra nexthop-group keep 1\n", "")
			case "stale-template":
				f.inputs = strings.Repeat("b", 64)
			case "db-route":
				db.HSet(t.Context(), "STATIC_ROUTE|0.0.0.0/0", "nexthop", "192.0.2.1")
			case "db-peer":
				db.HSet(t.Context(), "BGP_NEIGHBOR|192.0.2.1", "asn", "65000")
			case "runtime-peer":
				f.neighbors = `{"default":{"192.0.2.1":{}}}`
			case "runtime-route":
				f.config += "ip route 0.0.0.0/0 192.0.2.1\n"
			case "candidate":
				f.separatedCandidate = f.separatedFiles()
				f.separatedCandidate["staticd.conf"] += "ip route 0.0.0.0/0 192.0.2.1\n"
			case "split":
				db.HSet(t.Context(), "DEVICE_METADATA|localhost", "docker_routing_config_mode", "split-unified")
			case "foreign-owner":
				req.OwnerID = "other-uid"
			case "owned-drift":
				db.HSet(t.Context(), "DEVICE_METADATA|localhost", frrMigrationDesired("Traditional")["DEVICE_METADATA|localhost"])
			case "storage-permissions":
				dir := filepath.Dir(legacyPath)
				if err := os.Chmod(dir, 0500); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(dir, 0700) })
			case "receipt-conflict":
				if err := os.WriteFile(filepath.Join(filepath.Dir(legacyPath), "launch-"+digest+".json"), []byte("different"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, _, _ := m.vlanChangeSnapshot(t.Context())
			if _, st := m.EnsureNetworkResource(f.ctx(t), req); st == nil {
				t.Fatal("unsafe reverse accepted")
			}
			after, _, _ := m.vlanChangeSnapshot(t.Context())
			got, _ := os.ReadFile(legacyPath)
			if !reflect.DeepEqual(before, after) || f.restarts != 1 || *saves != 1 || !bytes.Equal(legacy, got) {
				t.Fatal("rejected reverse mutated state or receipt")
			}
		})
	}
}

func TestFRRMigrationReverseRecoveryOriginalTarget(t *testing.T) {
	for _, failure := range []string{"restart-response", "save", "post-cas", "dispatch-durability"} {
		t.Run(failure, func(t *testing.T) {
			m, db, req, f, _ := frrMigrationCycleFixture(t)
			frrMigrationApprove(t, m, req, f)
			switch failure {
			case "restart-response":
				f.uncertain = true
			case "save":
				m.saveConfig = func(context.Context) *agent.Status { return &agent.Status{Code: 500} }
			case "post-cas":
				f.readHook = func(cmd *exec.Cmd) {
					if strings.Contains(strings.Join(cmd.Args, " "), "sonic-cfggen") && db.HGet(t.Context(), "DEVICE_METADATA|localhost", "docker_routing_config_mode").Val() == "separated" {
						f.inputs = strings.Repeat("b", 64)
					}
				}
			case "dispatch-durability":
				calls := 0
				m.journalSync = func(*os.File) error {
					calls++
					if calls == 3 {
						return fmt.Errorf("uncertain sync")
					}
					return nil
				}
			}
			if out, st := m.EnsureNetworkResource(f.ctx(t), req); st == nil || out == nil || out.PersistenceVerified {
				t.Fatalf("expected pending %+v %v", out, st)
			}
			f.readHook = nil
			f.inputs = strings.Repeat("a", 64)
			f.uncertain = false
			m = &SonicAgent{networkJournalDir: m.networkJournalDir, clientPool: map[string]*redis.Client{"CONFIG_DB": db}, saveConfig: func(context.Context) *agent.Status { return nil }}
			// New intent has no approval. Resume the original reverse first.
			req.Spec = json.RawMessage(`{"mode":"Unified"}`)
			out, st := m.EnsureNetworkResource(f.ctx(t), req)
			if failure == "dispatch-durability" {
				if st == nil || f.restarts != 1 {
					t.Fatalf("blind restart %+v %v", out, st)
				}
				return
			}
			if st == nil || out == nil || !out.PersistenceVerified || !out.RuntimeVerified || f.restarts != 2 {
				t.Fatalf("old target not recovered %+v %v restarts=%d", out, st, f.restarts)
			}
			if db.HGet(t.Context(), "DEVICE_METADATA|localhost", "docker_routing_config_mode").Val() != "separated" {
				t.Fatal("new target executed during recovery")
			}
			if _, st := m.EnsureNetworkResource(f.ctx(t), req); st == nil || f.restarts != 2 {
				t.Fatal("new target accepted without approval")
			}
			frrMigrationApprove(t, m, req, f)
			if out, st := m.EnsureNetworkResource(f.ctx(t), req); st != nil || !out.PersistenceVerified || f.restarts != 3 {
				t.Fatalf("next forward %+v %v", out, st)
			}
		})
	}
}

func TestFRRMigrationReverseRuntimeProof(t *testing.T) {
	for _, failure := range []string{"bgpd.conf", "zebra.conf", "staticd.conf", "vtysh.conf", "frr.conf", "daemons", "unchanged-start", "routes-drift"} {
		t.Run(failure, func(t *testing.T) {
			m, db, req, f, _ := frrMigrationCycleFixture(t)
			frrMigrationApprove(t, m, req, f)
			f.uncertain = true
			if _, st := m.EnsureNetworkResource(f.ctx(t), req); st == nil {
				t.Fatal("expected uncertain dispatch")
			}
			ctx := context.WithValue(t.Context(), routingCommandRunnerKey{}, routingCommandRunner(func(cmd *exec.Cmd) ([]byte, error) {
				data, err := f.run(cmd)
				if len(cmd.Args) == 6 && cmd.Args[5] == frrMigrationStartupScript {
					var files map[string]*string
					_ = json.Unmarshal(data, &files)
					if _, ok := files[failure]; ok {
						bad := base64.StdEncoding.EncodeToString([]byte("unexpected"))
						files[failure] = &bad
						data, _ = json.Marshal(files)
					}
				}
				if failure == "daemons" && strings.Join(cmd.Args, " ") == "docker exec bgp supervisorctl status" {
					data = []byte(strings.ReplaceAll(string(data), "bgpcfgd", "frrcfgd"))
				}
				if failure == "unchanged-start" && strings.HasPrefix(strings.Join(cmd.Args, " "), "systemctl show") {
					data = []byte("Result=success\nActiveState=active\nSubState=running\nInvocationID=" + fmt.Sprintf("%032x", 3) + "\n")
				}
				if failure == "routes-drift" && strings.Join(cmd.Args, " ") == "ip -j -4 route show table all" {
					data = []byte(`[]`)
				}
				return data, err
			}))
			m = &SonicAgent{networkJournalDir: m.networkJournalDir, clientPool: map[string]*redis.Client{"CONFIG_DB": db}, saveConfig: func(context.Context) *agent.Status { t.Fatal("saved unverified reverse"); return nil }}
			req.Spec = json.RawMessage(`{"mode":"Unified"}`)
			if out, st := m.RecoverNetworkResource(ctx, req); st == nil || out.PersistenceVerified || f.restarts != 2 {
				t.Fatalf("accepted or repeated restart %+v %v", out, st)
			}
		})
	}
}

func TestFRRMigrationLegacyReceiptReverseRecovery(t *testing.T) {
	m, db, req, f, _ := frrMigrationEngine(t, true)
	frrMigrationApprove(t, m, req, f)
	f.uncertain = true
	if _, st := m.EnsureNetworkResource(f.ctx(t), req); st == nil {
		t.Fatal("expected lost forward response")
	}
	// Simulate the old on-disk format: no mode, no scoped artifacts, original
	// backup and launch only. Pending journal still holds its original approval.
	receipt, err := frrMigrationReceiptFile(m.networkJournalDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(m.networkJournalDir, "frr-migration")
	receipt.Mode = ""
	data, _ := json.Marshal(receipt)
	if err := os.WriteFile(filepath.Join(dir, "launch.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"launch-", "backup-"} {
		if err := os.Remove(filepath.Join(dir, prefix+receipt.Digest+".json")); err != nil {
			t.Fatal(err)
		}
	}
	legacyBackup, err := os.ReadFile(filepath.Join(dir, "backup.json"))
	if err != nil {
		t.Fatal(err)
	}
	m = &SonicAgent{networkJournalDir: m.networkJournalDir, clientPool: map[string]*redis.Client{"CONFIG_DB": db}, saveConfig: func(context.Context) *agent.Status { return nil }}
	req.Spec = json.RawMessage(`{"mode":"Traditional"}`)
	if out, st := m.EnsureNetworkResource(f.ctx(t), req); st == nil || !out.PersistenceVerified || !out.RuntimeVerified || f.restarts != 1 {
		t.Fatalf("legacy forward recovery %+v %v", out, st)
	}
	f.uncertain = false
	f.restartHook = func() { f.separated = true }
	frrMigrationApprove(t, m, req, f)
	if out, st := m.EnsureNetworkResource(f.ctx(t), req); st != nil || !out.PersistenceVerified || f.restarts != 2 {
		t.Fatalf("reverse legacy receipt %+v %v", out, st)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "launch.json"))
	backup, _ := os.ReadFile(filepath.Join(dir, "backup.json"))
	if !bytes.Equal(got, data) || !bytes.Equal(backup, legacyBackup) {
		t.Fatal("legacy artifacts overwritten")
	}
}
