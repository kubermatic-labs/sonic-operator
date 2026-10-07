// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"testing/synctest"
	"time"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/redis/go-redis/v9"
)

// CONFIG_DB commands are modeled here; the integration suite runs the Lua on
// real Redis. Unexpected commands still fail closed through redisFixture.
type authorityConfigFixture struct {
	redisFixture
	cas int
}

func (f *authorityConfigFixture) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	fallback := f.redisFixture.ProcessHook(next)
	return func(ctx context.Context, cmd redis.Cmder) error {
		if cmd.Name() != "eval" {
			return fallback(ctx, cmd)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		keys := make([]string, 0, len(f.hashes))
		for key := range f.hashes {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		rows := []map[string]any{}
		for _, key := range keys {
			rows = append(rows, map[string]any{"key": key, "fields": f.hashes[key]})
		}
		raw, _ := json.Marshal(rows)
		c := cmd.(*vlanCommand)
		switch cmd.Args()[1] {
		case vlanChangeReadScript:
			c.SetVal(string(raw))
		case vlanChangeCASScript:
			f.cas++
			if cmd.Args()[3] != string(raw) {
				c.SetVal(int64(0))
				return nil
			}
			var changes []struct {
				Key    string
				Remove []string
				Set    map[string]string
			}
			if err := json.Unmarshal([]byte(cmd.Args()[4].(string)), &changes); err != nil {
				return err
			}
			for _, change := range changes {
				if f.hashes[change.Key] == nil {
					f.hashes[change.Key] = map[string]string{}
				}
				for _, field := range change.Remove {
					delete(f.hashes[change.Key], field)
				}
				maps.Copy(f.hashes[change.Key], change.Set)
				if len(f.hashes[change.Key]) == 0 {
					delete(f.hashes, change.Key)
				}
			}
			c.SetVal(int64(1))
		default:
			return fmt.Errorf("unexpected script")
		}
		return nil
	}
}

func newAuthorityRuntimeTest(t *testing.T) (*SonicAgent, *authorityConfigFixture, *agent.VLANAuthorityRequest, *int) {
	t.Helper()
	saves := new(int)
	m := &SonicAgent{clientPool: map[string]*redis.Client{}, saveConfig: func(context.Context) *agent.Status { *saves++; return nil }}
	f := &authorityConfigFixture{redisFixture: redisFixture{hashes: map[string]map[string]string{
		"PORT|Ethernet0":                {"alias": "keep"},
		"VLAN|Vlan100":                  {"vlanid": "100"},
		"VLAN_MEMBER|Vlan100|Ethernet0": {"tagging_mode": "tagged"},
	}}}
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1})
	client.AddHook(f)
	t.Cleanup(func() { _ = client.Close() })
	m.clientPool["CONFIG_DB"] = client
	m.journalDir = t.TempDir()
	if err := os.Chmod(m.journalDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.journalDir, ".lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	r := &agent.VLANAuthorityRequest{OwnerID: "owner", VLAN: &agent.VLAN{ID: 100, Members: []agent.VLANMember{{InterfaceName: "Ethernet0", TaggingMode: "untagged"}}}}
	r.AdoptionDigest = vlanAuthorityDigest(f.hashes, 100)
	return m, f, r, saves
}

func TestVLANAuthorityModeMigrationWaitAndRestart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m, f, r, saves := newAuthorityRuntimeTest(t)
		removed := false
		m.verifyVLANRuntime = func(ctx context.Context, id uint32, target vlanChangeDB) error {
			if target["VLAN_MEMBER|Vlan100|Ethernet0"] != nil {
				t.Fatal("add/verification before removal barrier")
			}
			removed = true
			if f.hashes["VLAN_MEMBER|Vlan100|Ethernet0"] != nil || *saves != 0 {
				t.Fatal("removal not staged before wait")
			}
			return fmt.Errorf("consumer still has old member")
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		got, status := m.ReconcileVLANAuthority(ctx, r)
		if status == nil || got.RuntimeVerified || got.PersistenceVerified || !removed || *saves != 0 || f.cas != 1 {
			t.Fatalf("removal timeout: %+v %v saves=%d CAS=%d", got, status, *saves, f.cas)
		}
		j, err := m.lockVLANAuthorityJournal(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		record, err := j.load(100)
		j.close()
		if err != nil || record.Pending == nil || !reflect.DeepEqual(record.Pending.Intermediate, vlanChangeTarget(f.hashes, 100)) || record.Pending.IntermediateHash != vlanAuthorityHash(f.hashes) {
			t.Fatalf("missing durable intermediate: %+v %v", record, err)
		}
		// A new agent has no in-memory progress. It must recheck removal and
		// use the journaled target, even if the caller asks for something else.
		restarted := &SonicAgent{clientPool: m.clientPool, journalDir: m.journalDir, saveConfig: m.saveConfig}
		waits := 0
		restarted.verifyVLANRuntime = func(ctx context.Context, id uint32, target vlanChangeDB) error {
			waits++
			if waits == 1 && (target["VLAN_MEMBER|Vlan100|Ethernet0"] != nil || f.cas != 1) {
				t.Fatal("removal replayed or barrier skipped")
			}
			return nil
		}
		newRequest := &agent.VLANAuthorityRequest{OwnerID: r.OwnerID, VLAN: &agent.VLAN{ID: 100}}
		got, status = restarted.ReconcileVLANAuthority(t.Context(), newRequest)
		if status == nil || !got.RuntimeVerified || !got.PersistenceVerified || !reflect.DeepEqual(got.VLAN, r.VLAN) || *saves != 1 || f.cas != 2 || waits < 2 {
			t.Fatalf("restart: %+v %v saves=%d CAS=%d waits=%d", got, status, *saves, f.cas, waits)
		}
	})
}

func TestVLANAuthorityConfirmedNoopChecksRuntime(t *testing.T) {
	m, f, r, saves := newAuthorityRuntimeTest(t)
	m.verifyVLANRuntime = func(context.Context, uint32, vlanChangeDB) error { return nil }
	if _, status := m.ReconcileVLANAuthority(t.Context(), r); status != nil {
		t.Fatal(status)
	}
	cas := f.cas
	m.verifyVLANRuntime = func(context.Context, uint32, vlanChangeDB) error { return fmt.Errorf("stale APPL_DB") }
	got, status := m.GetVLANAuthority(t.Context(), 100)
	if status != nil || got.RuntimeVerified || got.PersistenceVerified {
		t.Fatalf("stale read: %+v %v", got, status)
	}
	got, status = m.ReconcileVLANAuthority(t.Context(), r)
	if status == nil || got.RuntimeVerified || got.PersistenceVerified || f.cas != cas || *saves != 1 {
		t.Fatalf("stale noop: %+v %v", got, status)
	}
}

func TestVLANAuthorityRuntimeWaitBounded(t *testing.T) {
	for _, name := range []string{"default deadline", "caller deadline", "canceled", "eventual convergence"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				calls := 0
				m := &SonicAgent{verifyVLANRuntime: func(context.Context, uint32, vlanChangeDB) error {
					calls++
					if name == "eventual convergence" && calls == 3 {
						return nil
					}
					return fmt.Errorf("stale membership")
				}}
				ctx := t.Context()
				want := vlanAuthorityRuntimeTimeout
				switch name {
				case "caller deadline":
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, 250*time.Millisecond)
					defer cancel()
					want = 250 * time.Millisecond
				case "canceled":
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					cancel()
					want = 0
				case "eventual convergence":
					want = 200 * time.Millisecond
				}
				start := time.Now()
				err := m.waitVLANAuthorityRuntime(ctx, 100, vlanChangeDB{})
				if (err == nil) != (name == "eventual convergence") || time.Since(start) != want {
					t.Fatalf("err=%v elapsed=%s want=%s", err, time.Since(start), want)
				}
				if name == "canceled" && calls != 0 {
					t.Fatal("called verifier after cancellation")
				}
			})
		})
	}
}

func TestVLANAuthorityStagedAddRejectsFullSnapshotDrift(t *testing.T) {
	m, f, r, saves := newAuthorityRuntimeTest(t)
	m.verifyVLANRuntime = func(context.Context, uint32, vlanChangeDB) error {
		f.hashes["UNRELATED|new"] = map[string]string{"value": "concurrent writer"}
		return nil
	}
	got, status := m.ReconcileVLANAuthority(t.Context(), r)
	if status == nil || got.RuntimeVerified || got.PersistenceVerified || *saves != 0 || f.hashes["VLAN_MEMBER|Vlan100|Ethernet0"] != nil || f.cas != 2 {
		t.Fatalf("staged add did not reject drift: %+v %v", got, status)
	}
	j, err := m.lockVLANAuthorityJournal(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	record, err := j.load(100)
	j.close()
	if err != nil || record.Pending == nil {
		t.Fatalf("discarded partial operation: %+v %v", record, err)
	}
	if _, status := m.ReconcileVLANAuthority(t.Context(), r); status == nil || f.cas != 2 {
		t.Fatal("replayed conflicted intermediate")
	}
}

func TestVLANAuthorityAllChangesWaitBeforePersistence(t *testing.T) {
	for _, name := range []string{"create", "prune", "delete", "adopt noop", "post-save stale", "drift during wait"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				m, f, r, saves := newAuthorityRuntimeTest(t)
				r.VLAN.Members[0].TaggingMode = "tagged"
				switch name {
				case "delete":
					m.verifyVLANRuntime = func(context.Context, uint32, vlanChangeDB) error { return nil }
					if _, s := m.ReconcileVLANAuthority(t.Context(), r); s != nil {
						t.Fatal(s)
					}
					*saves = 0
					r.Delete = true
				case "create":
					delete(f.hashes, "VLAN|Vlan100")
					delete(f.hashes, "VLAN_MEMBER|Vlan100|Ethernet0")
				case "prune":
					r.VLAN.Members = nil
				}
				calls := 0
				m.verifyVLANRuntime = func(context.Context, uint32, vlanChangeDB) error {
					calls++
					if name == "post-save stale" && *saves == 0 {
						return nil
					}
					if name == "drift during wait" {
						f.hashes["OTHER|config"] = map[string]string{"value": "changed"}
						return nil
					}
					return fmt.Errorf("consumer stalled")
				}
				got, s := m.ReconcileVLANAuthority(t.Context(), r)
				wantSaves := 0
				if name == "post-save stale" {
					wantSaves = 1
				}
				if s == nil || got.PersistenceVerified || *saves != wantSaves || calls == 0 {
					t.Fatalf("unverified completion: %+v %v saves=%d", got, s, *saves)
				}
				if name != "drift during wait" && got.RuntimeVerified {
					t.Fatal("stale APPL_DB marked verified")
				}
				j, err := m.lockVLANAuthorityJournal(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				record, err := j.load(100)
				j.close()
				if err != nil || record.Pending == nil {
					t.Fatalf("lost pending operation: %+v %v", record, err)
				}
			})
		})
	}
}

func TestVLANAuthorityIntermediateSelection(t *testing.T) {
	for _, name := range []string{"tagged to untagged", "untagged to tagged", "unchanged", "delete"} {
		t.Run(name, func(t *testing.T) {
			before := vlanChangeDB{"VLAN|Vlan100": {"vlanid": "100"}, "VLAN_MEMBER|Vlan100|Ethernet0": {"tagging_mode": "tagged"}, "VLAN_MEMBER|Vlan100|Ethernet4": {"tagging_mode": "tagged"}, "VLAN_MEMBER|Vlan100|Ethernet8": {"tagging_mode": "tagged"}}
			after := vlanChangeDB{"VLAN|Vlan100": {"vlanid": "100"}, "VLAN_MEMBER|Vlan100|Ethernet0": {"tagging_mode": "untagged"}, "VLAN_MEMBER|Vlan100|Ethernet4": {"tagging_mode": "tagged"}, "VLAN_MEMBER|Vlan100|Ethernet12": {"tagging_mode": "tagged"}}
			switch name {
			case "untagged to tagged":
				before["VLAN_MEMBER|Vlan100|Ethernet0"]["tagging_mode"] = "untagged"
				after["VLAN_MEMBER|Vlan100|Ethernet0"]["tagging_mode"] = "tagged"
			case "unchanged":
				after = before
			case "delete":
				after = vlanChangeDB{}
			}
			got := vlanAuthorityIntermediate(before, after)
			if name == "delete" || name == "unchanged" {
				if got != nil {
					t.Fatal("unnecessary stage")
				}
				return
			}
			want := vlanChangeDB{"VLAN|Vlan100": {"vlanid": "100"}, "VLAN_MEMBER|Vlan100|Ethernet4": {"tagging_mode": "tagged"}}
			if !reflect.DeepEqual(got, want) || len(before) != 4 {
				t.Fatalf("intermediate=%v", got)
			}
		})
	}
}

func TestVLANAuthorityLegacyPendingModeMigration(t *testing.T) {
	for _, name := range []string{"pre", "post"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				m, f, r, saves := newAuthorityRuntimeTest(t)
				before, after := vlanChangeTarget(f.hashes, 100), vlanAuthorityDesired(r)
				post := vlanAuthorityReplaceTarget(f.hashes, before, after)
				record := &vlanAuthorityRecord{Version: 1, VLANID: 100, OwnerID: r.OwnerID, Pending: &vlanAuthorityPending{
					Request: *r, Before: before, After: after, PreHash: vlanAuthorityHash(f.hashes), PostHash: vlanAuthorityHash(post),
				}}
				j, err := m.lockVLANAuthorityJournal(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				if err := j.store(record); err != nil {
					t.Fatal(err)
				}
				j.close()
				if name == "post" {
					f.hashes = post
				}
				waits := 0
				m.verifyVLANRuntime = func(context.Context, uint32, vlanChangeDB) error {
					waits++
					if name == "post" {
						return fmt.Errorf("old in-place update never converged")
					}
					if waits == 1 && f.hashes["VLAN_MEMBER|Vlan100|Ethernet0"] != nil {
						t.Fatal("legacy pre skipped staging")
					}
					return nil
				}
				got, status := m.ReconcileVLANAuthority(t.Context(), r)
				if name == "pre" {
					if status != nil || !got.PersistenceVerified || f.cas != 2 || *saves != 1 {
						t.Fatalf("legacy pre: %+v %v", got, status)
					}
				} else if status == nil || got.RuntimeVerified || got.PersistenceVerified || f.cas != 0 || *saves != 0 {
					t.Fatalf("blind legacy replay: %+v %v", got, status)
				}
			})
		})
	}
}
