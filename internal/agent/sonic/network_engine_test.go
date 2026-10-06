//go:build integration

// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/redis/go-redis/v9"
)

func networkEngineFixture(t *testing.T) (*SonicAgent, *redis.Client, *agent.NetworkRequest, *int) {
	t.Helper()
	db := newVLANRedis(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	saves := 0
	m := &SonicAgent{networkJournalDir: dir, clientPool: map[string]*redis.Client{"CONFIG_DB": db}, saveConfig: func(context.Context) *agent.Status { saves++; return nil }}
	m.planNetwork = func(_ vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
		return &networkPlan{Identity: "VRF|VrfTest", Desired: vlanChangeDB{"VRF|VrfTest": {"NULL": "NULL"}}}, nil
	}
	return m, db, &agent.NetworkRequest{Kind: "VRF", OwnerID: "uid-1", Spec: json.RawMessage(`{"name":"VrfTest"}`)}, &saves
}

func TestNetworkEngineReadAndPreservation(t *testing.T) {
	m, db, req, saves := networkEngineFixture(t)
	if err := db.HSet(t.Context(), "VRF|VrfTest", "unmanaged_secret", "never-journal-this").Err(); err != nil {
		t.Fatal(err)
	}
	before, _, err := m.vlanChangeSnapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	got, st := m.GetNetworkResource(t.Context(), req)
	if st != nil || got.ConfigurationVerified || got.PersistenceVerified || *saves != 0 {
		t.Fatalf("read: %+v %+v", got, st)
	}
	entries, err := os.ReadDir(m.networkJournalDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("Get created journal: %v %v", entries, err)
	}
	got, st = m.EnsureNetworkResource(t.Context(), req)
	if st != nil || !got.ConfigurationVerified || !got.PersistenceVerified || got.RuntimeVerified || *saves != 1 {
		t.Fatalf("ensure: %+v %+v saves=%d", got, st, *saves)
	}
	if value := db.HGet(t.Context(), "VRF|VrfTest", "unmanaged_secret").Val(); value != before["VRF|VrfTest"]["unmanaged_secret"] {
		t.Fatal("unknown field changed")
	}
	data, err := os.ReadFile(filepath.Join(m.networkJournalDir, "network.json"))
	if err != nil || strings.Contains(string(data), "never-journal-this") || strings.Contains(string(data), "unmanaged_secret") {
		t.Fatalf("secret persisted: %v", err)
	}
	got, st = m.EnsureNetworkResource(t.Context(), req)
	if st != nil || !got.PersistenceVerified || *saves != 1 {
		t.Fatalf("no-op: %+v %+v saves=%d", got, st, *saves)
	}
	other := *req
	other.OwnerID = "uid-2"
	if _, st := m.EnsureNetworkResource(t.Context(), &other); st == nil {
		t.Fatal("ownership transferred")
	}
}

func TestNetworkEnginePendingRestartAndGuards(t *testing.T) {
	m, db, req, _ := networkEngineFixture(t)
	m.saveConfig = func(context.Context) *agent.Status { return &agent.Status{Code: 500, Message: "save failed"} }
	got, st := m.EnsureNetworkResource(t.Context(), req)
	if st == nil || !got.ConfigurationVerified || got.PersistenceVerified {
		t.Fatalf("save failure: %+v %+v", got, st)
	}
	if st := m.SaveConfig(t.Context()); st == nil {
		t.Fatal("ordinary save bypassed pending network")
	}
	if _, st := m.SetInterfaceAliasName(t.Context(), &agent.Interface{Name: "Ethernet0", AliasName: "x"}); st == nil {
		t.Fatal("setter bypassed pending network")
	}
	restarted := &SonicAgent{networkJournalDir: m.networkJournalDir, clientPool: map[string]*redis.Client{"CONFIG_DB": db}, planNetwork: m.planNetwork, saveConfig: func(context.Context) *agent.Status { return nil }}
	got, st = restarted.GetNetworkResource(t.Context(), req)
	if st != nil || got.PersistenceVerified || !got.ConfigurationVerified {
		t.Fatalf("pending read: %+v %+v", got, st)
	}
	got, st = restarted.EnsureNetworkResource(t.Context(), req)
	if st != nil || !got.PersistenceVerified {
		t.Fatalf("recovery: %+v %+v", got, st)
	}
}

func TestNetworkEngineConflictAndRuntimeSeparation(t *testing.T) {
	m, db, req, saves := networkEngineFixture(t)
	if err := db.HSet(t.Context(), "VRF|VrfTest", "NULL", "foreign").Err(); err != nil {
		t.Fatal(err)
	}
	if _, st := m.EnsureNetworkResource(t.Context(), req); st == nil || *saves != 0 {
		t.Fatal("conflicting field replaced")
	}
	if err := db.Del(t.Context(), "VRF|VrfTest").Err(); err != nil {
		t.Fatal(err)
	}
	planner := m.planNetwork
	m.planNetwork = func(db vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
		p, err := planner(db, r)
		p.Runtime = func(context.Context, *SonicAgent) (bool, json.RawMessage, error) {
			return false, json.RawMessage(`{"state":"down"}`), nil
		}
		return p, err
	}
	got, st := m.EnsureNetworkResource(t.Context(), req)
	if st != nil || !got.ConfigurationVerified || !got.PersistenceVerified || got.RuntimeVerified {
		t.Fatalf("independent evidence: %+v %+v", got, st)
	}
}

func TestNetworkEnginePendingForeignChange(t *testing.T) {
	m, db, req, _ := networkEngineFixture(t)
	m.saveConfig = func(context.Context) *agent.Status { return &agent.Status{Code: 500} }
	if _, st := m.EnsureNetworkResource(t.Context(), req); st == nil {
		t.Fatal("save should fail")
	}
	if err := db.HSet(t.Context(), "UNRELATED|settings", "secret", "not-in-journal").Err(); err != nil {
		t.Fatal(err)
	}
	m.saveConfig = func(context.Context) *agent.Status { t.Fatal("foreign snapshot saved"); return nil }
	if _, st := m.EnsureNetworkResource(t.Context(), req); st == nil {
		t.Fatal("foreign change recovered")
	}
	other := *req
	other.Spec = json.RawMessage(`{"name":"VrfOther"}`)
	if _, st := m.EnsureNetworkResource(t.Context(), &other); st == nil {
		t.Fatal("pending identity overwritten")
	}
}

func TestNetworkEngineCASRejection(t *testing.T) {
	m, db, req, saves := networkEngineFixture(t)
	other := redis.NewClient(db.Options())
	t.Cleanup(func() { _ = other.Close() })
	db.AddHook(&networkCASHook{before: func(ctx context.Context) {
		if err := other.HSet(ctx, "OTHER|x", "value", "foreign").Err(); err != nil {
			t.Fatal(err)
		}
	}})
	if _, st := m.EnsureNetworkResource(t.Context(), req); st == nil || *saves != 0 {
		t.Fatal("stale snapshot saved")
	}
	if db.Exists(t.Context(), "VRF|VrfTest").Val() != 0 {
		t.Fatal("CAS applied despite unrelated write")
	}
	unlock, err := m.guardNetworkWrites(t.Context())
	if err != nil {
		t.Fatalf("definite CAS rejection wedged journal: %v", err)
	}
	unlock()
}

func TestNetworkEngineForeignReadAndProbeError(t *testing.T) {
	m, _, req, _ := networkEngineFixture(t)
	if _, st := m.EnsureNetworkResource(t.Context(), req); st != nil {
		t.Fatal(st)
	}
	probeCalls := 0
	planner := m.planNetwork
	m.planNetwork = func(db vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
		p, err := planner(db, r)
		p.Runtime = func(context.Context, *SonicAgent) (bool, json.RawMessage, error) {
			probeCalls++
			return false, nil, errors.New("probe failed")
		}
		return p, err
	}
	foreign := *req
	foreign.OwnerID = "foreign"
	if out, st := m.GetNetworkResource(t.Context(), &foreign); st == nil || (out != nil && out.PersistenceVerified) || probeCalls != 0 {
		t.Fatalf("foreign read: %+v %v probes=%d", out, st, probeCalls)
	}
	if out, st := m.GetNetworkResource(t.Context(), req); st == nil || out == nil || !out.ConfigurationVerified || !out.PersistenceVerified {
		t.Fatalf("probe failure lost evidence/error: %+v %v", out, st)
	}
}

type networkCASHook struct{ before func(context.Context) }

func (h *networkCASHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h *networkCASHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}
func (h *networkCASHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if cmd.Name() == "eval" && cmd.Args()[1] == vlanChangeCASScript {
			h.before(ctx)
		}
		return next(ctx, cmd)
	}
}

func TestNetworkEngineJournalFailure(t *testing.T) {
	m, db, req, saves := networkEngineFixture(t)
	syncs := 0
	m.journalSync = func(*os.File) error {
		syncs++
		if syncs == 2 {
			return errors.New("injected fsync failure")
		}
		return nil
	}
	if _, st := m.EnsureNetworkResource(t.Context(), req); st == nil || *saves != 0 {
		t.Fatal("uncertain journal allowed save")
	}
	if db.Exists(t.Context(), "VRF|VrfTest").Val() != 0 {
		t.Fatal("write before durable pending")
	}
	m.journalSync = nil
	if out, st := m.EnsureNetworkResource(t.Context(), req); st != nil || !out.PersistenceVerified {
		t.Fatalf("pre-state recovery: %+v %v", out, st)
	}
}

func TestNetworkEngineOwnedPeerScalar(t *testing.T) {
	m, db, req, _ := networkEngineFixture(t)
	req.Kind = "BGPPeer"
	req.Spec = json.RawMessage(`{"address":"192.0.2.2","adminState":"Down"}`)
	runtimeVerified := true
	m.planNetwork = func(_ vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
		var s struct {
			AdminState string `json:"adminState"`
		}
		if err := json.Unmarshal(r.Spec, &s); err != nil {
			return nil, err
		}
		return &networkPlan{Identity: "BGPPeer|default|192.0.2.2", Desired: vlanChangeDB{"BGP_NEIGHBOR|default|192.0.2.2": {"asn": "65001", "admin_status": strings.ToLower(s.AdminState)}}, Runtime: func(context.Context, *SonicAgent) (bool, json.RawMessage, error) { return runtimeVerified, nil, nil }, Preflight: func(context.Context, *SonicAgent) error {
			if s.AdminState == "Up" && !runtimeVerified {
				return errors.New("staged policy not verified")
			}
			return nil
		}}, nil
	}
	if out, st := m.EnsureNetworkResource(t.Context(), req); st != nil || !out.PersistenceVerified {
		t.Fatalf("create: %+v %v", out, st)
	}
	req.Spec = json.RawMessage(`{"address":"192.0.2.2","adminState":"Up"}`)
	runtimeVerified = false
	if _, st := m.EnsureNetworkResource(t.Context(), req); st == nil {
		t.Fatal("peer activated without staged runtime proof")
	}
	if db.HGet(t.Context(), "BGP_NEIGHBOR|default|192.0.2.2", "admin_status").Val() != "down" {
		t.Fatal("peer lifted shutdown before policy verification")
	}
	runtimeVerified = true
	if out, st := m.EnsureNetworkResource(t.Context(), req); st != nil || !out.PersistenceVerified {
		t.Fatalf("owned update: %+v %v", out, st)
	}
	if err := db.HSet(t.Context(), "BGP_NEIGHBOR|default|192.0.2.2", "admin_status", "foreign").Err(); err != nil {
		t.Fatal(err)
	}
	req.Spec = json.RawMessage(`{"address":"192.0.2.2","adminState":"Down"}`)
	if _, st := m.EnsureNetworkResource(t.Context(), req); st == nil {
		t.Fatal("overwrote drift in owned scalar")
	}
}

func TestNetworkEngineOtherJournalGuards(t *testing.T) {
	m, db, req, saves := networkEngineFixture(t)
	a, _ := authorityAgent(t, db, "")
	j, err := a.lockVLANAuthorityJournal(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	before := vlanChangeDB{}
	after := vlanChangeDB{"VLAN|Vlan100": {"vlanid": "100"}}
	err = j.store(&vlanAuthorityRecord{Version: 1, VLANID: 100, OwnerID: "vlan-owner", Pending: &vlanAuthorityPending{Request: agent.VLANAuthorityRequest{OwnerID: "vlan-owner", VLAN: &agent.VLAN{ID: 100}}, Before: before, After: after, PreHash: vlanAuthorityHash(before), PostHash: vlanAuthorityHash(after)}})
	j.close()
	if err != nil {
		t.Fatal(err)
	}
	m.journalDir = a.journalDir
	if _, st := m.EnsureNetworkResource(t.Context(), req); st == nil || *saves != 0 {
		t.Fatal("pending VLAN did not block network")
	}
	m.journalDir = ""
	b, _, _, _ := breakoutFixture(t)
	b.saveConfig = func(context.Context) *agent.Status { return &agent.Status{Code: 500} }
	if _, st := b.ReconcilePortBreakout(t.Context(), splitRequest()); st == nil {
		t.Fatal("breakout save should fail")
	}
	m.breakoutJournalDir = b.breakoutJournalDir
	if _, st := m.EnsureNetworkResource(t.Context(), req); st == nil || *saves != 0 {
		t.Fatal("pending breakout did not block network")
	}
	m.breakoutJournalDir = ""
	m.saveConfig = func(context.Context) *agent.Status { return &agent.Status{Code: 500} }
	if _, st := m.EnsureNetworkResource(t.Context(), req); st == nil {
		t.Fatal("network save should fail")
	}
	b.networkJournalDir = m.networkJournalDir
	if _, st := b.ReconcilePortBreakout(t.Context(), splitRequest()); st == nil || !strings.Contains(st.Message, "network") {
		t.Fatalf("breakout bypassed network: %v", st)
	}
	a.networkJournalDir = m.networkJournalDir
	if _, st := a.ReconcileVLANAuthority(t.Context(), &agent.VLANAuthorityRequest{OwnerID: "vlan-owner", VLAN: &agent.VLAN{ID: 100}}); st == nil || !strings.Contains(st.Message, "network") {
		t.Fatalf("authority bypassed network: %v", st)
	}
}

func TestNetworkEnginePlannerAllowlist(t *testing.T) {
	t.Parallel()
	db := lagL3Fixture()
	db["DEVICE_METADATA|localhost"] = map[string]string{"frr_mgmt_framework_config": "true", "has_sonic_dhcpv4_relay": "True"}
	db["VLAN_INTERFACE|Vlan100"] = map[string]string{"NULL": "NULL"}
	db["VLAN_INTERFACE|Vlan100|192.0.2.1/24"] = map[string]string{"NULL": "NULL"}
	for _, tc := range []struct{ name, kind, spec string }{
		{"lag", "PortChannel", `{"name":"PortChannel10","members":["Ethernet0"]}`},
		{"vrf", "VRF", `{"name":"VrfRed"}`},
		{"l3", "L3Interface", `{"name":"Ethernet4","addresses":["198.51.100.1/24"]}`},
		{"bgp", "BGP", `{"localASN":65000,"routerID":"192.0.2.1","prefixes":["198.51.100.0/24"]}`},
		{"peer", "BGPPeer", `{"address":"192.0.2.2","remoteASN":65001,"addressFamilies":["ipv4Unicast"]}`},
		{"relay", "DHCPRelay", `{"vlanID":100,"ipv4Servers":["192.0.2.3"]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.kind == "BGPPeer" {
				global, err := planNetworkBGP(db, &agent.NetworkRequest{Kind: "BGP", Spec: json.RawMessage(`{"localASN":65000,"routerID":"192.0.2.1","prefixes":["198.51.100.0/24"]}`)})
				if err != nil {
					t.Fatal(err)
				}
				for key, fields := range global.Desired {
					db[key] = fields
				}
			}
			p, err := planNetworkResource(db, &agent.NetworkRequest{Kind: tc.kind, Spec: json.RawMessage(tc.spec)})
			if err != nil {
				t.Fatal(err)
			}
			if err := validateNetworkFields(tc.kind, p.Desired); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNetworkEngineMultiIdentityPersistence(t *testing.T) {
	m, _, req, saves := networkEngineFixture(t)
	m.planNetwork = func(_ vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
		var s struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(r.Spec, &s); err != nil {
			return nil, err
		}
		return &networkPlan{Identity: "VRF|" + s.Name, Desired: vlanChangeDB{"VRF|" + s.Name: {"NULL": "NULL"}}}, nil
	}
	if _, st := m.EnsureNetworkResource(t.Context(), req); st != nil {
		t.Fatal(st)
	}
	other := *req
	other.OwnerID = "uid-2"
	other.Spec = json.RawMessage(`{"name":"VrfOther"}`)
	if _, st := m.EnsureNetworkResource(t.Context(), &other); st != nil {
		t.Fatal(st)
	}
	for _, r := range []*agent.NetworkRequest{req, &other} {
		if out, st := m.EnsureNetworkResource(t.Context(), r); st != nil || !out.PersistenceVerified {
			t.Fatalf("proof stale: %+v %v", out, st)
		}
	}
	if *saves != 2 {
		t.Fatalf("controllers repeatedly saved each other's stale fingerprints: saves=%d", *saves)
	}
}

func TestNetworkEngineCompletionFailureAndLock(t *testing.T) {
	m, db, req, _ := networkEngineFixture(t)
	syncs := 0
	m.journalSync = func(*os.File) error {
		syncs++
		if syncs == 3 {
			return errors.New("completion fsync failed")
		}
		return nil
	}
	if out, st := m.EnsureNetworkResource(t.Context(), req); st == nil || out.PersistenceVerified {
		t.Fatalf("uncertain completion: %+v %v", out, st)
	}
	restarted := &SonicAgent{networkJournalDir: m.networkJournalDir, clientPool: map[string]*redis.Client{"CONFIG_DB": db}, planNetwork: m.planNetwork, saveConfig: func(context.Context) *agent.Status { return nil }}
	if out, st := restarted.EnsureNetworkResource(t.Context(), req); st != nil || !out.PersistenceVerified {
		t.Fatalf("completion recovery: %+v %v", out, st)
	}
	j, err := m.lockNetworkJournal(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
	defer cancel()
	if _, st := restarted.EnsureNetworkResource(ctx, req); st == nil {
		t.Fatal("second process bypassed journal lock")
	}
}

func TestNetworkEngineNoJournalGet(t *testing.T) {
	m, db, req, saves := networkEngineFixture(t)
	m.networkJournalDir = ""
	if out, st := m.GetNetworkResource(t.Context(), req); st != nil || out.PersistenceVerified || out.Exists {
		t.Fatalf("unconfigured read: %+v %v", out, st)
	}
	if _, st := m.EnsureNetworkResource(t.Context(), req); st == nil {
		t.Fatal("unconfigured write allowed")
	}
	if *saves != 0 || db.DBSize(t.Context()).Val() != 0 {
		t.Fatal("unconfigured access wrote database")
	}
}
