// SPDX-License-Identifier: Apache-2.0
package host

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type writerProbeBackend struct {
	*fakeBackend
	inWriter bool
	t        *testing.T
}

func (b *writerProbeBackend) Observe(ctx context.Context, q Request) (Result, error) {
	if b.inWriter {
		b.t.Error("healthy native proof ran under writer locks")
	}
	return b.fakeBackend.Observe(ctx, q)
}

func (b *writerProbeBackend) CheckPublication(ctx context.Context) error {
	if b.inWriter {
		b.t.Error("healthy watchdog proof repeated under writer locks")
	}
	return b.fakeBackend.CheckPublication(ctx)
}

func TestExactHostEnsureDoesNotProbeUnderWritersOrRewriteClaim(t *testing.T) {
	for _, kind := range []string{"Management", "System"} {
		t.Run(kind, func(t *testing.T) {
			e, f, _ := newTestEngine(t)
			q := managementRequest()
			if kind == "System" {
				q.Kind, q.Management, q.RollbackSeconds = kind, nil, 0
				q.System = &System{NTP: &NTP{Servers: []string{"192.0.2.1"}}}
			}
			if got, err := e.Get(t.Context(), q, "read"); err != nil || got.Owner != "" {
				t.Fatalf("unowned observation adopted: %+v %v", got, err)
			}
			if _, err := os.Stat(filepath.Join(e.dir, "host.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("Get published a claim")
			}
			if _, err := e.Ensure(t.Context(), q, "first"); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(e.dir, "host.json")
			before, _ := os.Stat(path)
			body, _ := os.ReadFile(path)
			b := &writerProbeBackend{fakeBackend: f, t: t}
			e.backend = b
			f.exclusive = func(ctx context.Context, fn func(context.Context) error) error {
				b.inWriter = true
				defer func() { b.inWriter = false }()
				return fn(ctx)
			}
			got, err := e.Ensure(t.Context(), q, "repeat")
			if err != nil || !got.Ready() || got.Owner != q.Owner || got.Recovery != "Idle" {
				t.Fatalf("healthy repeat: %+v %v", got, err)
			}
			after, _ := os.Stat(path)
			latest, _ := os.ReadFile(path)
			if !os.SameFile(before, after) || !bytes.Equal(body, latest) {
				t.Fatal("repeat rewrote the claim")
			}
		})
	}
}

func TestExactHostEnsureRetainsWriterAdmission(t *testing.T) {
	e, f, _ := newTestEngine(t)
	q := managementRequest()
	if _, err := e.Ensure(t.Context(), q, "first"); err != nil {
		t.Fatal(err)
	}
	// Foreign Pending/reservation may not affect any host native proof. Even
	// a read-only Ensure must preserve the writer-side admission decision.
	f.exclusive = func(context.Context, func(context.Context) error) error { return ErrConflict }
	if _, err := e.Ensure(t.Context(), q, "repeat"); !errors.Is(err, ErrConflict) {
		t.Fatalf("exact healthy claim bypassed admission: %v", err)
	}
}

func TestHostClaimChangedAfterReadCannotUseEarlierProof(t *testing.T) {
	e, f, _ := newTestEngine(t)
	q := managementRequest()
	if _, err := e.Ensure(t.Context(), q, "first"); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	f.exclusive = func(ctx context.Context, fn func(context.Context) error) error {
		once.Do(func() {
			if err := e.withRecord(ctx, func(r *record) error { r.Management.Owner = "foreign"; return e.save(r) }); err != nil {
				t.Error(err)
			}
		})
		return fn(ctx)
	}
	if _, err := e.Ensure(t.Context(), q, "repeat"); !errors.Is(err, ErrConflict) {
		t.Fatalf("claim changed after proof was accepted: %v", err)
	}
}

func TestHostWriterRecordContentionUnwindsBeforeRetry(t *testing.T) {
	for _, name := range []string{"mutex", "flock"} {
		t.Run(name, func(t *testing.T) {
			e, _, _ := newTestEngine(t)
			var release func()
			if name == "mutex" {
				e.mu.Lock()
				release = e.mu.Unlock
			} else {
				_, unlock, err := lockRecord(t.Context(), e.dir, nil)
				if err != nil {
					t.Fatal(err)
				}
				release = unlock
			}
			defer release()
			var writer sync.Mutex
			unwound := make(chan struct{}, 1)
			exclusive := func(ctx context.Context, fn func(context.Context) error) error {
				writer.Lock()
				defer func() {
					writer.Unlock()
					select {
					case unwound <- struct{}{}:
					default:
					}
				}()
				return fn(ctx)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- e.withExclusiveRecord(ctx, exclusive, func(context.Context, *record) error { t.Error("action entered while host busy"); return nil })
			}()
			select {
			case <-unwound:
				if ctx.Err() != nil {
					t.Error("host contention held writer to deadline")
				}
			case <-time.After(250 * time.Millisecond):
				t.Error("host contention did not unwind writer promptly")
			}
			cancel()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Errorf("canceled retry: %v", err)
			}
			if !writer.TryLock() {
				t.Fatal("writer lock leaked")
			}
			writer.Unlock()
		})
	}
}

func TestSystemHealthyClaimCannotBypassManagementPending(t *testing.T) {
	e, f, _ := newTestEngine(t)
	q := Request{Kind: "System", Owner: "system", Target: "switch", Revision: "1-secret-rv-1", System: &System{NTP: &NTP{Servers: []string{"192.0.2.1"}}}}
	if _, err := e.Ensure(t.Context(), q, "system"); err != nil {
		t.Fatal(err)
	}
	management := managementRequest()
	management.Management.Addresses[0].Prefix = "10.0.0.99/24"
	if _, err := e.Ensure(t.Context(), management, "first"); err != nil {
		t.Fatal(err)
	}
	if got, err := e.Get(t.Context(), q, "read"); err != nil || !got.Ready() {
		t.Fatalf("legacy System Get is insufficient: %+v %v", got, err)
	}
	f.exclusive = nil
	if _, err := e.Ensure(t.Context(), q, "repeat"); !errors.Is(err, ErrConflict) {
		t.Fatalf("System ignored global Pending: %v", err)
	}
}

func TestHostEnsureAmbiguityRetainsGuardedPath(t *testing.T) {
	for _, name := range []string{"missing", "owner", "target", "revision", "settings", "runtime", "persistence", "gateway", "pending", "rolled back"} {
		t.Run(name, func(t *testing.T) {
			e, f, _ := newTestEngine(t)
			q := managementRequest()
			if name != "missing" {
				if _, err := e.Ensure(t.Context(), q, "first"); err != nil {
					t.Fatal(err)
				}
			}
			switch name {
			case "owner":
				q.Owner = "foreign"
			case "target":
				q.Target = "different-switch"
			case "revision":
				q.Revision = "2-secret-rv-8"
			case "settings":
				q.Management.Addresses[0].Prefix = "10.0.0.99/24"
			case "runtime":
				f.native = false
			case "persistence":
				f.persist = false
			case "gateway":
				f.gateway = false
			case "pending":
				q.Management.Addresses[0].Prefix = "10.0.0.99/24"
				if _, err := e.Ensure(t.Context(), q, "first"); err != nil {
					t.Fatal(err)
				}
			case "rolled back":
				if err := e.withRecord(t.Context(), func(r *record) error { r.RolledBack = requestClaim(q); return e.save(r) }); err != nil {
					t.Fatal(err)
				}
			}
			guard := errors.New("guarded path")
			f.exclusive = func(context.Context, func(context.Context) error) error { return guard }
			if _, err := e.Ensure(t.Context(), q, "repeat"); !errors.Is(err, guard) {
				t.Fatalf("%s bypassed writer guard: %v", name, err)
			}
		})
	}
}
