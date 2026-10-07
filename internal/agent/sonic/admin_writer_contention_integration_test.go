//go:build integration

// SPDX-License-Identifier: Apache-2.0
package sonic

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/ironcore-dev/sonic-operator/internal/artifact"
)

type pausedHostProof struct {
	host.Backend
	entered, release chan struct{}
}

func (b *pausedHostProof) Observe(ctx context.Context, q host.Request) (host.Result, error) {
	got, err := b.Backend.Observe(ctx, q)
	close(b.entered)
	select {
	case <-b.release:
		return got, err
	case <-ctx.Done():
		return host.Result{}, ctx.Err()
	}
}

func TestHealthyHostEnsureAllowsAdminDuringNativeProof(t *testing.T) {
	f, rdb, _ := hostNetworkFixture(t)
	f.agent.clientPool["APPL_DB"] = rdb
	he, err := host.NewEngine(f.agent.hostJournalDir, f.native)
	if err != nil {
		t.Fatal(err)
	}
	q := hostRepairRequest()
	if got, err := he.Ensure(t.Context(), q, "first"); err != nil || !got.Ready() {
		t.Fatalf("adoption: %+v %v", got, err)
	}
	path := filepath.Join(f.agent.hostJournalDir, "host.json")
	before, _ := os.Stat(path)
	body, _ := os.ReadFile(path)
	barrier := &pausedHostProof{Backend: f.native, entered: make(chan struct{}), release: make(chan struct{})}
	he, err = host.NewEngine(f.agent.hostJournalDir, barrier)
	if err != nil {
		t.Fatal(err)
	}
	if err := rdb.HSet(t.Context(), "PORT|Ethernet0", "admin_status", "up").Err(); err != nil {
		t.Fatal(err)
	}
	f.agent.readSavedPortConfig = func() ([]byte, error) { return []byte(`{"PORT":{"Ethernet0":{"admin_status":"up"}}}`), nil }
	done := make(chan error, 1)
	go func() {
		got, err := he.Ensure(t.Context(), q, "repeat")
		if err == nil && !got.Ready() {
			err = host.ErrNative
		}
		done <- err
	}()
	<-barrier.entered
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	got, st := f.agent.SetInterfaceAdminStatus(ctx, &agent.Interface{Name: "Ethernet0", AdminStatus: agent.StatusUp})
	close(barrier.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if st != nil || got == nil || !got.AdminPersistenceVerified || ctx.Err() != nil {
		t.Fatalf("healthy Ensure blocked admin during native proof: %+v %+v", got, st)
	}
	after, _ := os.Stat(path)
	latest, _ := os.ReadFile(path)
	if !os.SameFile(before, after) || !bytes.Equal(body, latest) {
		t.Fatal("healthy native proof rewrote host ownership")
	}
}

type slowHostReader struct {
	host.Backend
	entered, release chan struct{}
}

func TestHealthyHostEnsureRetainsForeignPendingAdmission(t *testing.T) {
	f, _, request := hostNetworkFixture(t)
	he, err := host.NewEngine(f.agent.hostJournalDir, f.native)
	if err != nil {
		t.Fatal(err)
	}
	q := hostRepairRequest()
	if got, err := he.Ensure(t.Context(), q, "first"); err != nil || !got.Ready() {
		t.Fatalf("adoption: %+v %v", got, err)
	}
	save := f.agent.saveConfig
	f.agent.saveConfig = func(context.Context) *agent.Status { return &agent.Status{Code: 500} }
	if _, st := f.agent.EnsureNetworkResource(t.Context(), request); st == nil {
		t.Fatal("network Pending not established")
	}
	f.agent.saveConfig = save
	if _, err := he.Ensure(t.Context(), q, "repeat"); !errors.Is(err, host.ErrConflict) {
		t.Fatalf("healthy host ignored foreign Pending: %v", err)
	}
}

func (b *slowHostReader) Observe(ctx context.Context, _ host.Request) (host.Result, error) {
	close(b.entered)
	select {
	case <-b.release:
		return host.Result{ConfigurationVerified: true, RuntimeVerified: true, PersistenceVerified: true, GatewayVerified: true}, nil
	case <-ctx.Done():
		return host.Result{}, ctx.Err()
	}
}

type signaledWriterFence struct {
	*ArtifactWriterFence
	once    sync.Once
	entered chan struct{}
}

func (f *signaledWriterFence) WithMutation(ctx context.Context, fn func() error) error {
	return f.ArtifactWriterFence.WithMutation(ctx, func() error {
		f.once.Do(func() { close(f.entered) })
		return fn()
	})
}

func TestSlowHostGetSupervisorAllowsAdmin(t *testing.T) {
	for _, operation := range []string{"tick", "boot"} {
		t.Run(operation, func(t *testing.T) {
			f, rdb, _ := hostNetworkFixture(t)
			f.agent.clientPool["APPL_DB"] = rdb
			cfg := combinedFixture(t, f)
			reader := &slowHostReader{Backend: f.native, entered: make(chan struct{}), release: make(chan struct{})}
			he, err := host.NewEngine(cfg.JournalDir, reader)
			if err != nil {
				t.Fatal(err)
			}
			getDone := make(chan error, 1)
			go func() {
				_, err := he.Get(t.Context(), host.Request{Kind: "System", Owner: "host-owner", Target: "switch", Revision: "1", System: &host.System{NTP: &host.NTP{Servers: []string{"192.0.2.1"}}}}, "read")
				getDone <- err
			}()
			<-reader.entered
			defer func() {
				close(reader.release)
				if err := <-getDone; err != nil {
					t.Error(err)
				}
			}()
			fence := &signaledWriterFence{ArtifactWriterFence: &ArtifactWriterFence{agent: f.agent}, entered: make(chan struct{})}
			e, _, err := artifact.NewNativeEngine(f.dir, "/host/sonic-operator-artifacts", artifact.Policy{Baseline: "test"}, fence)
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			supervisorDone := make(chan error, 1)
			go func() {
				if operation == "boot" {
					supervisorDone <- e.RestoreBoot()
				} else {
					supervisorDone <- e.Tick(time.Now())
				}
			}()
			defer func() { <-supervisorDone }()
			<-fence.entered
			if err := rdb.HSet(t.Context(), "PORT|Ethernet0", "admin_status", "up").Err(); err != nil {
				t.Fatal(err)
			}
			f.agent.readSavedPortConfig = func() ([]byte, error) { return []byte(`{"PORT":{"Ethernet0":{"admin_status":"up"}}}`), nil }
			ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
			defer cancel()
			got, st := f.agent.SetInterfaceAdminStatus(ctx, &agent.Interface{Name: "Ethernet0", AdminStatus: agent.StatusUp})
			if st != nil || got == nil || !got.AdminPersistenceVerified || ctx.Err() != nil {
				t.Fatalf("supervisor waiting on host Get blocked admin: %+v %+v %v", got, st, ctx.Err())
			}
			if _, err := os.Stat(filepath.Join(cfg.JournalDir, "host.json")); !os.IsNotExist(err) {
				t.Fatal("read-only probe published host state")
			}
		})
	}
}
