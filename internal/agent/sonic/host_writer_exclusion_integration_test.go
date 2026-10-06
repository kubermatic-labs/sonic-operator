//go:build integration

// SPDX-License-Identifier: Apache-2.0
package sonic

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/redis/go-redis/v9"
)

func hostNetworkFixture(t *testing.T) (*hostDeviceFixture, *redis.Client, *agent.NetworkRequest) {
	rdb := newVLANRedis(t)
	f := seedHostDeviceFixture(t, rdb)
	_ = os.Remove(filepath.Join(f.dir, "journal/host.json"))
	old := host.Snapshot{Management: hostBefore(), ActiveMAC: hostBefore().MAC}
	if err := f.native.RestoreManagement(t.Context(), host.RecoveryScope{Before: old, Candidate: hostCandidate()}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(f.dir, "network")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	f.agent.networkJournalDir = dir
	f.agent.hostRecoverySnapshot = f.native.Snapshot
	f.agent.planNetwork = func(_ vlanChangeDB, _ *agent.NetworkRequest) (*networkPlan, error) {
		return &networkPlan{Identity: "VRF|VrfRecovery", Desired: vlanChangeDB{"VRF|VrfRecovery": {"NULL": "NULL"}}}, nil
	}
	return f, rdb, &agent.NetworkRequest{Kind: "VRF", OwnerID: "network-owner", Spec: json.RawMessage(`{"name":"VrfRecovery"}`)}
}
func hostRepairRequest() host.Request {
	m := hostBefore()
	return host.Request{Kind: "Management", Owner: "host-owner", Target: "switch", Revision: "1", Management: &m, RollbackSeconds: 60}
}
func seedLegacyHostPending(t *testing.T, f *hostDeviceFixture) {
	q := hostRepairRequest()
	data, _ := json.Marshal(map[string]any{"pending": map[string]any{"id": "legacy", "claim": map[string]string{"owner": q.Owner, "target": q.Target, "revision": q.Revision}, "before": host.Snapshot{Management: *q.Management, ActiveMAC: q.Management.MAC}, "candidate": q.Management, "created": time.Now().Add(-time.Minute), "deadline": time.Now().Add(-time.Second), "connection": "old", "rollbackRequired": true}})
	if err := os.WriteFile(filepath.Join(f.dir, "journal/host.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}
func TestHostNetworkPendingDoesNotPublishIntent(t *testing.T) {
	for _, drift := range []string{"runtime", "persistence"} {
		t.Run(drift, func(t *testing.T) {
			f, _, req := hostNetworkFixture(t)
			save := f.agent.saveConfig
			f.agent.saveConfig = func(context.Context) *agent.Status { return &agent.Status{Code: 500} }
			if _, st := f.agent.EnsureNetworkResource(t.Context(), req); st == nil {
				t.Fatal("network pending fixture not established")
			}
			f.agent.saveConfig = save
			if drift == "runtime" {
				k := f.kernel()
				delete(k.Routes, hostRoute("10.0.0.0/24", ""))
				f.putKernel(k)
			} else {
				_ = f.write("/etc/network/interfaces", []byte("stale generation"))
			}
			e, err := host.NewEngine(filepath.Join(f.dir, "journal"), f.native)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = e.Ensure(t.Context(), hostRepairRequest(), "connection"); !errors.Is(err, host.ErrConflict) {
				t.Fatal("preexisting network recovery was not given priority")
			}
			if _, err = os.Stat(filepath.Join(f.dir, "journal/host.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("host intent created before pending writer was checked")
			}
			if _, st := f.agent.RecoverNetworkResource(t.Context(), req); st != nil {
				t.Fatal("network recovery was stranded")
			}
		})
	}
}
func TestHostWatchdogResolvesLegacyDualPendingWithoutCluster(t *testing.T) {
	f, _, req := hostNetworkFixture(t)
	save := f.agent.saveConfig
	f.agent.saveConfig = func(context.Context) *agent.Status { return &agent.Status{Code: 500} }
	if _, st := f.agent.EnsureNetworkResource(t.Context(), req); st == nil {
		t.Fatal("network save failure not retained")
	}
	f.agent.saveConfig = save
	k := f.kernel()
	delete(k.Routes, hostRoute("10.0.0.0/24", ""))
	f.putKernel(k)
	seedLegacyHostPending(t, f)
	if _, st := f.agent.EnsureNetworkResource(t.Context(), req); st == nil {
		t.Fatal("new network writes must remain blocked during dual-pending recovery")
	}
	// New watchdog engine completes only the recorded dependency, then restores
	// management. No controller, RPC or cluster connection drives these calls.
	e, err := host.NewEngine(filepath.Join(f.dir, "journal"), f.native)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err = e.RecoverExpired(ctx); err != nil {
		t.Fatalf("legacy recovery deadlocked: %v", err)
	}
	if err = host.CheckPending(filepath.Join(f.dir, "journal")); err != nil {
		t.Fatal(err)
	}
	if !f.kernel().Routes[hostRoute("10.0.0.0/24", "")] {
		t.Fatal("management runtime was not restored")
	}
	if _, st := f.agent.RecoverNetworkResource(ctx, req); st != nil {
		t.Fatal("network pending state remains")
	}
}

func TestHostWatchdogResolvesLegacyVLANPendingWithoutCluster(t *testing.T) {
	f, _, _ := hostNetworkFixture(t)
	dir := filepath.Join(f.dir, "vlan")
	_ = os.Mkdir(dir, 0700)
	_ = os.WriteFile(filepath.Join(dir, ".lock"), nil, 0600)
	f.agent.journalDir = dir
	f.agent.verifyVLANRuntime = func(context.Context, uint32, vlanChangeDB) error { return nil }
	current, st := f.agent.GetVLANAuthority(t.Context(), 100)
	if st != nil {
		t.Fatal(st.Message)
	}
	save := f.agent.saveConfig
	f.agent.saveConfig = func(context.Context) *agent.Status { return &agent.Status{Code: 500} }
	if _, st = f.agent.ReconcileVLANAuthority(t.Context(), &agent.VLANAuthorityRequest{OwnerID: "vlan-owner", VLAN: &agent.VLAN{ID: 100}, AdoptionDigest: current.Digest}); st == nil {
		t.Fatal("VLAN save failure not retained")
	}
	f.agent.saveConfig = save
	k := f.kernel()
	delete(k.Routes, hostRoute("10.0.0.0/24", ""))
	f.putKernel(k)
	seedLegacyHostPending(t, f)
	e, err := host.NewEngine(filepath.Join(f.dir, "journal"), f.native)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err = e.RecoverExpired(ctx); err != nil {
		t.Fatal("legacy VLAN dependency did not recover", err)
	}
	if err = host.CheckPending(filepath.Join(f.dir, "journal")); err != nil {
		t.Fatal(err)
	}
}

type hostPreflightBarrier struct {
	*host.Native
	once   sync.Once
	arrive func()
}

func (b *hostPreflightBarrier) Validate(ctx context.Context, q host.Request) error {
	if e := b.Native.Validate(ctx, q); e != nil {
		return e
	}
	b.once.Do(b.arrive)
	return nil
}

func TestHostWriterArrivingBetweenPreflightAndDispatchIsFenced(t *testing.T) {
	f, rdb, req := hostNetworkFixture(t)
	other := &SonicAgent{clientPool: map[string]*redis.Client{"CONFIG_DB": rdb}, networkJournalDir: f.agent.networkJournalDir, hostJournalDir: f.agent.hostJournalDir, planNetwork: f.agent.planNetwork, saveConfig: f.agent.saveConfig}
	started := make(chan struct{})
	done := make(chan *agent.Status, 1)
	barrier := &hostPreflightBarrier{Native: f.native, arrive: func() {
		go func() { close(started); _, st := other.EnsureNetworkResource(t.Context(), req); done <- st }()
		<-started
	}}
	e, err := host.NewEngine(filepath.Join(f.dir, "journal"), barrier)
	if err != nil {
		t.Fatal(err)
	}
	q := hostRepairRequest()
	q.Management.Addresses[0].Prefix = "10.0.0.99/24"
	if _, err = e.Ensure(t.Context(), q, "initial"); err != nil {
		t.Fatal(err)
	}
	select {
	case st := <-done:
		if st == nil {
			t.Fatal("arriving writer escaped pending host fence")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("writer did not release its blocked request")
	}
	if rdb.Exists(t.Context(), "VRF|VrfRecovery").Val() != 0 {
		t.Fatal("network operation overlapped management dispatch")
	}
}
