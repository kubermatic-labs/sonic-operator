//go:build integration

// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/redis/go-redis/v9"
)

// Each test starts its own real Redis. Only the startup root gate is bypassed;
// private files, fsync, flock, CAS and recovery run unchanged under the test UID.
func authorityAgent(t *testing.T, db *redis.Client, dir string) (*SonicAgent, *atomic.Int32) {
	t.Helper()
	if dir == "" {
		dir = t.TempDir()
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	saves := &atomic.Int32{}
	options := *db.Options()
	options.DB = 0
	app := redis.NewClient(&options)
	t.Cleanup(func() { _ = app.Close() })
	// Emulate vlanmgr on APPL reads, not by bypassing the production verifier.
	// Existing member mode updates are deliberately ignored, matching SONiC:
	// only an observed deletion allows the next add to set a new mode.
	consumer := &authorityAPPLConsumer{config: db, app: redis.NewClient(&options)}
	t.Cleanup(func() { _ = consumer.app.Close() })
	if err := consumer.consume(t.Context()); err != nil {
		t.Fatal(err)
	}
	app.AddHook(consumer)
	return &SonicAgent{journalDir: dir, clientPool: map[string]*redis.Client{"CONFIG_DB": db, "APPL_DB": app}, saveConfig: func(context.Context) *agent.Status { saves.Add(1); return nil }}, saves
}

type authorityAPPLConsumer struct {
	config, app *redis.Client
}

func (h *authorityAPPLConsumer) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h *authorityAPPLConsumer) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}
func (h *authorityAPPLConsumer) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if cmd.Name() == "eval" && cmd.Args()[1] == vlanAuthorityRuntimeScript {
			if err := h.consume(ctx); err != nil {
				return err
			}
		}
		return next(ctx, cmd)
	}
}

func (h *authorityAPPLConsumer) consume(ctx context.Context) error {
	for _, table := range []struct{ config, app string }{{"VLAN|", "VLAN_TABLE:"}, {"VLAN_MEMBER|", "VLAN_MEMBER_TABLE:"}} {
		keys, err := h.config.Keys(ctx, table.config+"*").Result()
		if err != nil {
			return err
		}
		desired := map[string]bool{}
		for _, key := range keys {
			appKey := table.app + strings.ReplaceAll(strings.TrimPrefix(key, table.config), "|", ":")
			desired[appKey] = true
			fields, err := h.config.HGetAll(ctx, key).Result()
			if err != nil {
				return err
			}
			for field, value := range fields {
				if err := h.app.HSetNX(ctx, appKey, field, value).Err(); err != nil {
					return err
				}
			}
		}
		keys, err = h.app.Keys(ctx, table.app+"*").Result()
		if err != nil {
			return err
		}
		for _, key := range keys {
			if !desired[key] {
				if err := h.app.Del(ctx, key).Err(); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func authoritySeed(t *testing.T, db *redis.Client) {
	t.Helper()
	for key, fields := range map[string]map[string]string{
		"VLAN|Vlan100":                  {"vlanid": "100"},
		"VLAN_MEMBER|Vlan100|Ethernet0": {"tagging_mode": "untagged"},
		"VLAN_MEMBER|Vlan100|Ethernet4": {"tagging_mode": "tagged"},
		"PORT|Ethernet0":                {"alias": "keep"}, "PORT|Ethernet4": {"alias": "keep"}, "PORT|Ethernet8": {"alias": "keep"},
		"SECRET|unrelated": {"password": "never-journal-this-secret"},
	} {
		if err := db.HSet(t.Context(), key, fields).Err(); err != nil {
			t.Fatal(err)
		}
	}
}

func authorityRequest() *agent.VLANAuthorityRequest {
	return &agent.VLANAuthorityRequest{OwnerID: "cr-uid-1", VLAN: &agent.VLAN{ID: 100, Members: []agent.VLANMember{{InterfaceName: "Ethernet4", TaggingMode: "untagged"}, {InterfaceName: "Ethernet8", TaggingMode: "tagged"}}}}
}

func authorityApprove(t *testing.T, m *SonicAgent, r *agent.VLANAuthorityRequest) {
	t.Helper()
	got, s := m.GetVLANAuthority(t.Context(), r.VLAN.ID)
	if s != nil || got == nil || len(got.Digest) != 64 {
		t.Fatalf("snapshot=%+v status=%v", got, s)
	}
	r.AdoptionDigest = got.Digest
}

func authorityOK(t *testing.T, m *SonicAgent, r *agent.VLANAuthorityRequest) *agent.VLANAuthorityResult {
	t.Helper()
	got, s := m.ReconcileVLANAuthority(t.Context(), r)
	if s != nil || got == nil || !got.RuntimeVerified || !got.PersistenceVerified || got.OwnerID != r.OwnerID {
		t.Fatalf("reconcile=%+v status=%v", got, s)
	}
	return got
}

func TestVLANAuthorityTakeoverAndAutomaticMembership(t *testing.T) {
	db := newVLANRedis(t)
	authoritySeed(t, db)
	m, saves := authorityAgent(t, db, "")
	r := authorityRequest()
	if _, s := m.ReconcileVLANAuthority(t.Context(), r); s == nil {
		t.Fatal("unapproved takeover")
	}
	authorityApprove(t, m, r)
	approved := r.AdoptionDigest
	if err := db.HSet(t.Context(), "PORT|Ethernet0", "alias", "changed").Err(); err != nil {
		t.Fatal(err)
	}
	if _, s := m.ReconcileVLANAuthority(t.Context(), r); s == nil {
		t.Fatal("stale digest accepted")
	}
	authorityApprove(t, m, r)
	if r.AdoptionDigest == approved {
		t.Fatal("digest omitted dependencies")
	}
	got := authorityOK(t, m, r)
	if !reflect.DeepEqual(got.VLAN, r.VLAN) || db.Exists(t.Context(), "VLAN_MEMBER|Vlan100|Ethernet0").Val() != 0 {
		t.Fatalf("not full membership: %+v", got.VLAN)
	}
	m, restartedSaves := authorityAgent(t, db, m.journalDir)
	authorityOK(t, m, r)
	if saves.Load() != 1 || restartedSaves.Load() != 0 {
		t.Fatal("unchanged confirmed state saved again")
	}
	r.AdoptionDigest = ""
	r.VLAN.Members = []agent.VLANMember{{InterfaceName: "Ethernet4", TaggingMode: "tagged"}}
	got = authorityOK(t, m, r)
	if !reflect.DeepEqual(got.VLAN, r.VLAN) {
		t.Fatalf("mode migration/prune: %+v", got.VLAN)
	}
	r.OwnerID = "duplicate-cr"
	if _, s := m.ReconcileVLANAuthority(t.Context(), r); s == nil {
		t.Fatal("owner transferred")
	}
	files, err := os.ReadDir(m.journalDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(m.journalDir, f.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "never-journal-this-secret") || strings.Contains(string(data), "SECRET|unrelated") {
			t.Fatal("unrelated credentials journaled")
		}
	}
}

func TestVLANAuthorityReadAndCreate(t *testing.T) {
	db := newVLANRedis(t)
	m := &SonicAgent{clientPool: map[string]*redis.Client{"CONFIG_DB": db}}
	r := &agent.VLANAuthorityRequest{OwnerID: "new", VLAN: &agent.VLAN{ID: 100}}
	got, s := m.GetVLANAuthority(t.Context(), 100)
	if s != nil || got == nil || got.VLAN != nil || got.Digest == "" || got.OwnerID != "" || got.PersistenceVerified {
		t.Fatalf("absent: %+v %v", got, s)
	}
	if _, s := m.ReconcileVLANAuthority(t.Context(), r); s == nil {
		t.Fatal("write without journal")
	}
	if db.DBSize(t.Context()).Val() != 0 {
		t.Fatal("read or refused write mutated DB")
	}
	m, saves := authorityAgent(t, db, "")
	before, _ := os.ReadDir(m.journalDir)
	if _, s := m.GetVLANAuthority(t.Context(), 100); s != nil {
		t.Fatal(s)
	}
	after, _ := os.ReadDir(m.journalDir)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("snapshot created files")
	}
	authorityOK(t, m, r)
	if saves.Load() != 1 {
		t.Fatal("create not saved")
	}
}

func TestVLANAuthoritySaveRecoveryBeforeNewDesired(t *testing.T) {
	db := newVLANRedis(t)
	authoritySeed(t, db)
	m, _ := authorityAgent(t, db, "")
	r := authorityRequest()
	authorityApprove(t, m, r)
	m.saveConfig = func(context.Context) *agent.Status { return agent.NewErrorStatus(500, "lost reply") }
	got, s := m.ReconcileVLANAuthority(t.Context(), r)
	if s == nil || got == nil || !got.RuntimeVerified || got.PersistenceVerified {
		t.Fatalf("save failure: %+v %v", got, s)
	}
	if s := m.ReleaseVLANAuthority(t.Context(), 100, r.OwnerID); s == nil {
		t.Fatal("released pending save")
	}
	m, saves := authorityAgent(t, db, m.journalDir)
	newDesired := &agent.VLANAuthorityRequest{OwnerID: r.OwnerID, VLAN: &agent.VLAN{ID: 100}}
	got, s = m.ReconcileVLANAuthority(t.Context(), newDesired)
	if s == nil || got == nil || !reflect.DeepEqual(got.VLAN, r.VLAN) || saves.Load() != 1 {
		t.Fatalf("new desired did not recover old first: %+v %v saves=%d", got, s, saves.Load())
	}
	if got = authorityOK(t, m, newDesired); len(got.VLAN.Members) != 0 || saves.Load() != 2 {
		t.Fatal("new revision stuck after recovery")
	}
}

func TestVLANAuthorityDeletionAndRelease(t *testing.T) {
	db := newVLANRedis(t)
	authoritySeed(t, db)
	m, saves := authorityAgent(t, db, "")
	r := authorityRequest()
	r.Delete = true
	authorityApprove(t, m, r)
	if _, s := m.ReconcileVLANAuthority(t.Context(), r); s == nil {
		t.Fatal("delete claimed unowned VLAN")
	}
	r.Delete = false
	authorityOK(t, m, r)
	if s := m.ReleaseVLANAuthority(t.Context(), 100, "wrong"); s == nil {
		t.Fatal("wrong owner released")
	}
	if s := m.ReleaseVLANAuthority(t.Context(), 100, r.OwnerID); s != nil {
		t.Fatal(s)
	}
	if saves.Load() != 1 || db.Exists(t.Context(), "VLAN|Vlan100").Val() != 1 {
		t.Fatal("orphan release wrote config")
	}
	got, s := m.GetVLANAuthority(t.Context(), 100)
	if s != nil || got.OwnerID != "" {
		t.Fatalf("release: %+v %v", got, s)
	}
	authorityApprove(t, m, r)
	authorityOK(t, m, r)
	r.Delete = true
	r.VLAN.Members = nil
	m.saveConfig = func(context.Context) *agent.Status { return agent.NewErrorStatus(500, "save lost") }
	got, s = m.ReconcileVLANAuthority(t.Context(), r)
	if s == nil || got == nil || got.VLAN != nil || got.PersistenceVerified {
		t.Fatalf("delete pending: %+v %v", got, s)
	}
	if db.Exists(t.Context(), "VLAN|Vlan100", "VLAN_MEMBER|Vlan100|Ethernet4", "VLAN_MEMBER|Vlan100|Ethernet8").Val() != 0 {
		t.Fatal("delete did not remove all members")
	}
	m, saves = authorityAgent(t, db, m.journalDir)
	authorityOK(t, m, r)
	authorityOK(t, m, r)
	if saves.Load() != 1 {
		t.Fatal("delete retry was not saved exactly once")
	}
	if s := m.ReleaseVLANAuthority(t.Context(), 100, r.OwnerID); s != nil {
		t.Fatal(s)
	}
}

func TestVLANAuthorityRejectUnsafe(t *testing.T) {
	for _, tc := range []struct{ name, key, field, value string }{
		{"legacy list", "VLAN|Vlan100", "members@", "Ethernet0,Ethernet4"},
		{"unknown VLAN field", "VLAN|Vlan100", "mystery", "secret"},
		{"unknown member field", "VLAN_MEMBER|Vlan100|Ethernet0", "mystery", "secret"},
		{"LAG member", "VLAN_MEMBER|Vlan100|PortChannel1", "tagging_mode", "tagged"},
		{"LAG port", "PORTCHANNEL_MEMBER|PortChannel1|Ethernet4", "NULL", "NULL"},
		{"routed port", "INTERFACE|Ethernet0|192.0.2.1/24", "NULL", "NULL"},
		{"SVI", "VLAN_INTERFACE|Vlan100|192.0.2.1/24", "NULL", "NULL"},
		{"unknown key reference", "MYSTERY|Vlan100", "NULL", "NULL"},
		{"unknown value reference", "MYSTERY|thing", "interfaces@", "Vlan100,Vlan200"},
		{"numeric reference", "MYSTERY|thing", "vlan_id", "100"},
		{"second untagged", "VLAN_MEMBER|Vlan200|Ethernet4", "tagging_mode", "untagged"},
		{"bad competing mode", "VLAN_MEMBER|Vlan200|Ethernet4", "tagging_mode", "mystery"},
		{"unknown port reference", "MYSTERY|thing", "ports@", "Ethernet4"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newVLANRedis(t)
			authoritySeed(t, db)
			m, saves := authorityAgent(t, db, "")
			if err := db.HSet(t.Context(), tc.key, tc.field, tc.value).Err(); err != nil {
				t.Fatal(err)
			}
			r := authorityRequest()
			authorityApprove(t, m, r)
			if _, s := m.ReconcileVLANAuthority(t.Context(), r); s == nil {
				t.Fatal("unsafe write accepted")
			}
			if saves.Load() != 0 || db.Exists(t.Context(), "VLAN_MEMBER|Vlan100|Ethernet0").Val() != 1 {
				t.Fatal("unsafe operation partially wrote")
			}
		})
	}
}

type authorityRedisHook struct {
	before func(context.Context)
	after  func() error
}

func (h *authorityRedisHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h *authorityRedisHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}
func (h *authorityRedisHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		cas := cmd.Name() == "eval" && len(cmd.Args()) == 5
		if cas && h.before != nil {
			h.before(ctx)
		}
		err := next(ctx, cmd)
		if cas && err == nil && h.after != nil {
			return h.after()
		}
		return err
	}
}

func TestVLANAuthorityCASAndInterruptedApply(t *testing.T) {
	for _, tc := range []string{"phantom", "lost apply reply", "before apply", "pending drift"} {
		t.Run(tc, func(t *testing.T) {
			db := newVLANRedis(t)
			authoritySeed(t, db)
			m, saves := authorityAgent(t, db, "")
			r := authorityRequest()
			authorityApprove(t, m, r)
			client := redis.NewClient(db.Options())
			t.Cleanup(func() { _ = client.Close() })
			hook := &authorityRedisHook{}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch tc {
			case "phantom":
				hook.before = func(ctx context.Context) {
					if err := db.HSet(ctx, "OTHER|thing", "value", "changed").Err(); err != nil {
						t.Error(err)
					}
				}
			case "before apply":
				hook.before = func(context.Context) { cancel() }
			default:
				hook.after = func() error { return errors.New("lost apply reply") }
			}
			client.AddHook(hook)
			m.clientPool["CONFIG_DB"] = client
			if _, s := m.ReconcileVLANAuthority(ctx, r); s == nil {
				t.Fatal("interruption not reported")
			}
			if saves.Load() != 0 {
				t.Fatal("saved uncertain apply")
			}
			m, saves = authorityAgent(t, db, m.journalDir)
			if tc == "pending drift" {
				if err := db.HSet(t.Context(), "VLAN_MEMBER|Vlan100|Ethernet4", "tagging_mode", "tagged").Err(); err != nil {
					t.Fatal(err)
				}
				if _, s := m.ReconcileVLANAuthority(t.Context(), r); s == nil {
					t.Fatal("pending drift replayed")
				}
				if saves.Load() != 0 {
					t.Fatal("saved conflicted pending state")
				}
				return
			}
			if tc == "phantom" {
				authorityApprove(t, m, r)
			}
			authorityOK(t, m, r)
			if saves.Load() != 1 {
				t.Fatal("recovery did not save")
			}
		})
	}
}

func TestVLANAuthorityCrossAgentSerialization(t *testing.T) {
	db := newVLANRedis(t)
	authoritySeed(t, db)
	m, _ := authorityAgent(t, db, "")
	other, _ := authorityAgent(t, db, m.journalDir)
	r := authorityRequest()
	authorityApprove(t, m, r)
	entered, unblock := make(chan struct{}), make(chan struct{})
	m.saveConfig = func(context.Context) *agent.Status { close(entered); <-unblock; return nil }
	done := make(chan *agent.Status, 1)
	go func() { _, s := m.ReconcileVLANAuthority(context.Background(), r); done <- s }()
	<-entered
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	_, s := other.ReconcileVLANAuthority(ctx, r)
	close(unblock)
	if first := <-done; first != nil {
		t.Fatal(first)
	}
	if s == nil {
		t.Fatal("second agent bypassed cross-process lock during save")
	}
}

func TestVLANAuthorityParentOrdering(t *testing.T) {
	db := newVLANRedis(t)
	if err := db.HSet(t.Context(), "PORT|Ethernet0", "alias", "keep").Err(); err != nil {
		t.Fatal(err)
	}
	m, _ := authorityAgent(t, db, "")
	r := &agent.VLANAuthorityRequest{OwnerID: "owner", VLAN: &agent.VLAN{ID: 100, Members: []agent.VLANMember{{InterfaceName: "Ethernet0", TaggingMode: "tagged"}}}}
	client := redis.NewClient(db.Options())
	t.Cleanup(func() { _ = client.Close() })
	client.AddHook(authorityOrderHook{t: t, deleting: &r.Delete})
	m.clientPool["CONFIG_DB"] = client
	authorityOK(t, m, r)
	r.Delete = true
	authorityOK(t, m, r)
}

type authorityOrderHook struct {
	t        *testing.T
	deleting *bool
}

func (h authorityOrderHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h authorityOrderHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}
func (h authorityOrderHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if cmd.Name() == "eval" && len(cmd.Args()) == 5 {
			var changes []struct {
				Key string `json:"key"`
			}
			if err := json.Unmarshal([]byte(cmd.Args()[4].(string)), &changes); err != nil {
				h.t.Fatal(err)
			}
			if len(changes) != 2 {
				h.t.Fatalf("unexpected delta: %+v", changes)
			}
			want := "VLAN|Vlan100"
			if *h.deleting {
				want = "VLAN_MEMBER|Vlan100|Ethernet0"
			}
			if changes[0].Key != want {
				h.t.Errorf("first delta=%s, want %s", changes[0].Key, want)
			}
		}
		return next(ctx, cmd)
	}
}

func TestVLANAuthorityDeletionRejectsDependencies(t *testing.T) {
	for _, tc := range []struct{ name, key, field, value string }{
		{"SVI", "VLAN_INTERFACE|Vlan100", "NULL", "NULL"},
		{"unknown target", "VLAN|Vlan100", "secret", "do-not-drop"},
		{"numeric key", "MYSTERY_VLAN|100", "NULL", "NULL"},
		{"unknown range", "MYSTERY|thing", "vlan_range", "99-101"},
		{"unknown malformed", "MYSTERY|thing", "vlan_selector", "all"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newVLANRedis(t)
			authoritySeed(t, db)
			m, saves := authorityAgent(t, db, "")
			r := authorityRequest()
			authorityApprove(t, m, r)
			authorityOK(t, m, r)
			if err := db.HSet(t.Context(), tc.key, tc.field, tc.value).Err(); err != nil {
				t.Fatal(err)
			}
			r.Delete = true
			if _, s := m.ReconcileVLANAuthority(t.Context(), r); s == nil {
				t.Fatal("unsafe delete accepted")
			}
			if saves.Load() != 1 || db.Exists(t.Context(), "VLAN|Vlan100", "VLAN_MEMBER|Vlan100|Ethernet4").Val() != 2 {
				t.Fatal("unsafe deletion partially wrote")
			}
		})
	}
}

func TestVLANAuthorityJournalAndSaveFailures(t *testing.T) {
	for _, name := range []string{"prepare failure", "completion failure", "save drift", "other VLAN pending", "unknown desired port", "wrong type", "expiring key"} {
		t.Run(name, func(t *testing.T) {
			db := newVLANRedis(t)
			authoritySeed(t, db)
			m, saves := authorityAgent(t, db, "")
			r := authorityRequest()
			authorityApprove(t, m, r)
			block := func() {
				path := filepath.Join(m.journalDir, "vlan-100.json.tmp")
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(path, "block"), []byte("x"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch name {
			case "prepare failure":
				block()
			case "completion failure":
				m.saveConfig = func(context.Context) *agent.Status { block(); return nil }
			case "save drift":
				m.saveConfig = func(ctx context.Context) *agent.Status {
					if err := db.HSet(ctx, "OTHER|config", "value", "changed during save").Err(); err != nil {
						t.Error(err)
					}
					return nil
				}
			case "other VLAN pending":
				m.saveConfig = func(context.Context) *agent.Status { return agent.NewErrorStatus(500, "save lost") }
			case "unknown desired port":
				r.VLAN.Members[0].InterfaceName = "Ethernet999"
			case "wrong type":
				if err := db.Set(t.Context(), "OTHER|value", "uninspectable", 0).Err(); err != nil {
					t.Fatal(err)
				}
			case "expiring key":
				if err := db.Expire(t.Context(), "PORT|Ethernet0", time.Hour).Err(); err != nil {
					t.Fatal(err)
				}
			}
			got, s := m.ReconcileVLANAuthority(t.Context(), r)
			if s == nil || (got != nil && got.PersistenceVerified) {
				t.Fatalf("failure falsely succeeded: %+v %v", got, s)
			}
			if name == "completion failure" {
				path := filepath.Join(m.journalDir, "vlan-100.json.tmp")
				if err := os.Remove(filepath.Join(path, "block")); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				m, saves = authorityAgent(t, db, m.journalDir)
				authorityOK(t, m, r)
				if saves.Load() != 1 {
					t.Fatal("completion uncertainty not re-saved")
				}
			} else if name == "other VLAN pending" {
				m, saves = authorityAgent(t, db, m.journalDir)
				other := &agent.VLANAuthorityRequest{OwnerID: "other", VLAN: &agent.VLAN{ID: 200}}
				if _, s := m.ReconcileVLANAuthority(t.Context(), other); s == nil {
					t.Fatal("new VLAN bypassed pending save")
				}
				if saves.Load() != 0 || db.Exists(t.Context(), "VLAN|Vlan200").Val() != 0 {
					t.Fatal("other VLAN wrote around pending")
				}
			} else if name != "save drift" && saves.Load() != 0 {
				t.Fatal("saved rejected config")
			}
		})
	}
}

func TestVLANAuthorityAutomaticDriftAndPreRecovery(t *testing.T) {
	for _, pendingPre := range []bool{false, true} {
		name := "confirmed drift"
		if pendingPre {
			name = "new desired after interrupted pre-state"
		}
		t.Run(name, func(t *testing.T) {
			db := newVLANRedis(t)
			authoritySeed(t, db)
			m, _ := authorityAgent(t, db, "")
			r := authorityRequest()
			authorityApprove(t, m, r)
			if pendingPre {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				client := redis.NewClient(db.Options())
				t.Cleanup(func() { _ = client.Close() })
				client.AddHook(&authorityRedisHook{before: func(context.Context) { cancel() }})
				m.clientPool["CONFIG_DB"] = client
				if _, s := m.ReconcileVLANAuthority(ctx, r); s == nil {
					t.Fatal("expected interruption")
				}
				m, _ = authorityAgent(t, db, m.journalDir)
				newDesired := &agent.VLANAuthorityRequest{OwnerID: r.OwnerID, VLAN: &agent.VLAN{ID: 100}}
				got, s := m.ReconcileVLANAuthority(t.Context(), newDesired)
				if s == nil || got == nil || !reflect.DeepEqual(got.VLAN, r.VLAN) {
					t.Fatalf("did not recover old pre-state: %+v %v", got, s)
				}
				authorityOK(t, m, newDesired)
			} else {
				authorityOK(t, m, r)
				if err := db.HSet(t.Context(), "VLAN_MEMBER|Vlan100|Ethernet0", "tagging_mode", "tagged").Err(); err != nil {
					t.Fatal(err)
				}
				if err := db.HSet(t.Context(), "VLAN_MEMBER|Vlan100|Ethernet4", "tagging_mode", "tagged").Err(); err != nil {
					t.Fatal(err)
				}
				got, s := m.GetVLANAuthority(t.Context(), 100)
				if s != nil || got.RuntimeVerified || got.PersistenceVerified {
					t.Fatalf("stale confirmed flags: %+v %v", got, s)
				}
				r.AdoptionDigest = ""
				got = authorityOK(t, m, r)
				if !reflect.DeepEqual(got.VLAN, r.VLAN) {
					t.Fatal("ordinary drift required new approval or was not pruned")
				}
			}
		})
	}
}

func TestVLANAuthoritySharesAdditiveMutex(t *testing.T) {
	db := newVLANRedis(t)
	authoritySeed(t, db)
	m, _ := authorityAgent(t, db, "")
	r := authorityRequest()
	authorityApprove(t, m, r)
	entered, unblock := make(chan struct{}), make(chan struct{})
	var saves atomic.Int32
	m.saveConfig = func(context.Context) *agent.Status {
		if saves.Add(1) == 1 {
			close(entered)
			<-unblock
		}
		return nil
	}
	done := make(chan *agent.Status, 1)
	go func() { _, s := m.ReconcileVLANAuthority(context.Background(), r); done <- s }()
	<-entered
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	additiveDone := make(chan *agent.Status, 1)
	go func() { _, s := m.EnsureVLAN(ctx, &agent.VLAN{ID: 200}); additiveDone <- s }()
	<-ctx.Done()
	if db.Exists(t.Context(), "VLAN|Vlan200").Val() != 0 {
		t.Error("additive writer ran during authority save")
	}
	close(unblock)
	if s := <-done; s != nil {
		t.Fatal(s)
	}
	if s := <-additiveDone; s == nil {
		t.Fatal("canceled additive request mutated")
	}
	if saves.Load() != 1 {
		t.Fatal("overlapping save")
	}
}

func TestVLANAuthorityOwnershipKnown(t *testing.T) {
	db := newVLANRedis(t)
	m := &SonicAgent{clientPool: map[string]*redis.Client{"CONFIG_DB": db}}
	got, s := m.GetVLANAuthority(t.Context(), 100)
	if s != nil || got == nil || got.OwnershipKnown || got.Digest == "" {
		t.Fatalf("unconfigured preview: %+v %v", got, s)
	}
	m, _ = authorityAgent(t, db, "")
	got, s = m.GetVLANAuthority(t.Context(), 100)
	if s != nil || got == nil || !got.OwnershipKnown || got.OwnerID != "" {
		t.Fatalf("configured absence: %+v %v", got, s)
	}
}

func TestVLANAuthorityDirectorySyncRetry(t *testing.T) {
	for _, operation := range []string{"prepare", "complete", "remove"} {
		t.Run(operation, func(t *testing.T) {
			db := newVLANRedis(t)
			authoritySeed(t, db)
			m, saves := authorityAgent(t, db, "")
			r := authorityRequest()
			authorityApprove(t, m, r)
			if operation == "remove" {
				authorityOK(t, m, r)
			}
			calls := 0
			failAt := 2 // acquire sync succeeds; rename/unlink directory sync fails.
			if operation == "complete" {
				failAt = 3
			}
			m.journalSync = func(f *os.File) error {
				calls++
				if calls >= failAt {
					return errors.New("injected directory fsync failure")
				}
				return f.Sync()
			}
			if operation == "remove" {
				if s := m.ReleaseVLANAuthority(t.Context(), 100, r.OwnerID); s == nil {
					t.Fatal("unlink durability failure hidden")
				}
			} else if _, s := m.ReconcileVLANAuthority(t.Context(), r); s == nil {
				t.Fatal("rename durability failure hidden")
			}
			if calls != failAt {
				t.Fatalf("sync checkpoint calls=%d want=%d", calls, failAt)
			}
			beforeSaves := saves.Load()
			if got, s := m.GetVLANAuthority(t.Context(), 100); s == nil || (got != nil && got.OwnershipKnown) {
				t.Fatalf("trusted unsynced directory: %+v %v", got, s)
			}
			if _, s := m.ReconcileVLANAuthority(t.Context(), r); s == nil {
				t.Fatal("resumed before establishing durability")
			}
			if s := m.ReleaseVLANAuthority(t.Context(), 100, r.OwnerID); s == nil {
				t.Fatal("released before establishing durability")
			}
			if saves.Load() != beforeSaves {
				t.Fatal("save ran despite sync failure")
			}
			// A restarted process must also sync before trusting the visible record
			// or absence. No in-memory uncertain flag is needed to recover safely.
			m, saves = authorityAgent(t, db, m.journalDir)
			var synced bool
			m.journalSync = func(f *os.File) error { synced = true; return f.Sync() }
			got, s := m.GetVLANAuthority(t.Context(), 100)
			if s != nil || got == nil || !got.OwnershipKnown || !synced {
				t.Fatalf("retry did not establish durability: %+v %v", got, s)
			}
			if operation == "remove" {
				if got.OwnerID != "" || saves.Load() != 0 {
					t.Fatal("durable removal not observed")
				}
			} else {
				authorityOK(t, m, r)
				wantSaves := int32(1)
				if operation == "complete" {
					wantSaves = 0
				}
				if saves.Load() != wantSaves {
					t.Fatalf("retry saves=%d want=%d", saves.Load(), wantSaves)
				}
			}
		})
	}
}

func TestVLANAuthorityGuardsOrdinaryWriters(t *testing.T) {
	for _, writer := range []string{"other VLAN", "same VLAN", "alias", "admin", "save", "noop alias dirty"} {
		t.Run(writer, func(t *testing.T) {
			db := newVLANRedis(t)
			authoritySeed(t, db)
			m, _ := authorityAgent(t, db, "")
			r := authorityRequest()
			authorityApprove(t, m, r)
			m.saveConfig = func(context.Context) *agent.Status { return agent.NewErrorStatus(500, "lost save") }
			if _, s := m.ReconcileVLANAuthority(t.Context(), r); s == nil {
				t.Fatal("expected pending save")
			}
			ordinary, saves := authorityAgent(t, db, m.journalDir)
			ordinary.clientPool["APPL_DB"] = db
			ordinary.configDirty = true
			if writer == "admin" {
				// An unblocked admin ensure now requires independent saved evidence,
				// not just the save stub's successful return.
				var saved []byte
				ordinary.readSavedPortConfig = func() ([]byte, error) { return saved, nil }
				ordinary.saveConfig = func(ctx context.Context) *agent.Status {
					saves.Add(1)
					fields, err := db.HGetAll(ctx, "PORT|Ethernet0").Result()
					if err != nil {
						t.Fatal(err)
					}
					saved = portConfigJSON(t, vlanChangeDB{"PORT|Ethernet0": fields})
					return nil
				}
			}
			write := func() *agent.Status {
				switch writer {
				case "other VLAN":
					_, s := ordinary.EnsureVLAN(t.Context(), &agent.VLAN{ID: 200})
					return s
				case "same VLAN":
					_, s := ordinary.EnsureVLAN(t.Context(), &agent.VLAN{ID: 100})
					return s
				case "alias":
					_, s := ordinary.SetInterfaceAliasName(t.Context(), &agent.Interface{Name: "Ethernet0", AliasName: "new"})
					return s
				case "noop alias dirty":
					_, s := ordinary.SetInterfaceAliasName(t.Context(), &agent.Interface{Name: "Ethernet0", AliasName: "keep"})
					return s
				case "admin":
					_, s := ordinary.SetInterfaceAdminStatus(t.Context(), &agent.Interface{Name: "Ethernet0", AdminStatus: "up"})
					return s
				default:
					return ordinary.SaveConfig(t.Context())
				}
			}
			_, before, err := m.vlanChangeSnapshot(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if s := write(); s == nil {
				t.Fatal("writer bypassed pending authority")
			}
			_, after, err := m.vlanChangeSnapshot(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if before != after || saves.Load() != 0 {
				t.Fatal("blocked writer mutated or saved")
			}
			m, _ = authorityAgent(t, db, m.journalDir)
			authorityOK(t, m, r)
			if writer == "same VLAN" {
				if s := write(); s == nil {
					t.Fatal("additive touched confirmed owned VLAN")
				}
				if saves.Load() != 0 {
					t.Fatal("owned VLAN was saved by additive")
				}
				if s := m.ReleaseVLANAuthority(t.Context(), 100, r.OwnerID); s != nil {
					t.Fatal(s)
				}
			}
			if s := write(); s != nil {
				t.Fatalf("writer blocked after recovery/release: %v", s)
			}
			if saves.Load() != 1 {
				t.Fatalf("writer saves=%d", saves.Load())
			}
		})
	}
}

func TestVLANAuthorityOrdinaryPathDoesNotSnapshotFullDB(t *testing.T) {
	db := newVLANRedis(t)
	authoritySeed(t, db)
	m, _ := authorityAgent(t, db, "")
	m.clientPool["APPL_DB"] = db
	if err := db.Set(t.Context(), "UNRELATED|opaque", "not a hash", 0).Err(); err != nil {
		t.Fatal(err)
	}
	if _, s := m.EnsureVLAN(t.Context(), &agent.VLAN{ID: 200}); s != nil {
		t.Fatal(s)
	}
	if _, s := m.SetInterfaceAliasName(t.Context(), &agent.Interface{Name: "Ethernet0", AliasName: "new"}); s != nil {
		t.Fatal(s)
	}
	if s := m.SaveConfig(t.Context()); s != nil {
		t.Fatal(s)
	}
}

func TestVLANAuthorityOrdinaryWriterLockFailures(t *testing.T) {
	for _, failure := range []string{"locked by other agent", "directory sync", "missing journal", "corrupt record"} {
		t.Run(failure, func(t *testing.T) {
			db := newVLANRedis(t)
			authoritySeed(t, db)
			m, saves := authorityAgent(t, db, "")
			m.clientPool["APPL_DB"] = db
			switch failure {
			case "locked by other agent":
				other, _ := authorityAgent(t, db, m.journalDir)
				j, err := other.lockVLANAuthorityJournal(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer j.close()
			case "directory sync":
				m.journalSync = func(*os.File) error { return errors.New("injected directory sync failure") }
			case "missing journal":
				if err := os.Rename(m.journalDir, m.journalDir+"-moved"); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := os.Rename(m.journalDir+"-moved", m.journalDir); err != nil {
						t.Error(err)
					}
				})
			case "corrupt record":
				if err := os.WriteFile(filepath.Join(m.journalDir, "vlan-100.json"), []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			_, before, err := m.vlanChangeSnapshot(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			for _, writer := range []string{"ensure", "setter", "save"} {
				ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
				var s *agent.Status
				switch writer {
				case "ensure":
					_, s = m.EnsureVLAN(ctx, &agent.VLAN{ID: 200})
				case "setter":
					_, s = m.SetInterfaceAliasName(ctx, &agent.Interface{Name: "Ethernet0", AliasName: "new"})
				case "save":
					s = m.SaveConfig(ctx)
				}
				cancel()
				if s == nil {
					t.Fatalf("%s bypassed %s", writer, failure)
				}
			}
			_, after, err := m.vlanChangeSnapshot(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if before != after || saves.Load() != 0 {
				t.Fatal("lock failure mutated or saved configuration")
			}
		})
	}
}
