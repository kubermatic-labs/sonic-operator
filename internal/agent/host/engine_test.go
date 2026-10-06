// SPDX-License-Identifier: Apache-2.0
package host

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeBackend struct {
	exclusive                       func(context.Context, func(context.Context) error) error
	state                           Management
	activeMAC                       string
	apply, restore, system          int
	native, persist, gateway        bool
	invalid, failApply, failRestore bool
	beforeApply                     func()
}

func (f *fakeBackend) Exclusive(ctx context.Context, fn func(context.Context) error) error {
	if f.exclusive != nil {
		return f.exclusive(ctx, fn)
	}
	return fn(ctx)
}
func (f *fakeBackend) RecoverDependencies(context.Context) error { return nil }
func (f *fakeBackend) CheckPublication(context.Context) error    { return nil }
func (f *fakeBackend) VerifySaved(context.Context, Request) error {
	if !f.persist {
		return ErrNative
	}
	return nil
}
func (f *fakeBackend) ExclusiveRecovery(ctx context.Context, fn func(context.Context) error) error {
	return f.Exclusive(ctx, fn)
}

func (f *fakeBackend) Observe(_ context.Context, r Request) (Result, error) {
	match := r.Management == nil || managementEqual(f.state, *r.Management)
	return Result{ConfigurationVerified: match, RuntimeVerified: match && f.native, PersistenceVerified: match && f.persist, GatewayVerified: f.gateway}, nil
}
func (f *fakeBackend) Snapshot(context.Context) (Snapshot, error) {
	return Snapshot{Management: f.state, ActiveMAC: f.activeMAC}, nil
}
func (f *fakeBackend) Validate(context.Context, Request) error {
	if f.invalid {
		return errors.New("credential-looking backend output")
	}
	return nil
}
func (f *fakeBackend) WatchdogReady(context.Context) error { return nil }
func (f *fakeBackend) ApplyManagement(_ context.Context, _ Snapshot, m Management) error {
	f.apply++
	if f.beforeApply != nil {
		f.beforeApply()
	}
	f.state = m
	if f.failApply {
		return errors.New("apply failed")
	}
	return nil
}
func (f *fakeBackend) RestoreManagement(_ context.Context, scope RecoveryScope) error {
	s := scope.Before
	f.restore++
	if f.failRestore {
		return errors.New("restore failed")
	}
	f.state = s.Management
	return nil
}
func (f *fakeBackend) ApplySystem(context.Context, Request) error { f.system++; return nil }
func managementRequest() Request {
	m := validManagement()
	return Request{Kind: "Management", Owner: "uid", Target: "switch-uid", Revision: "1", Management: &m, RollbackSeconds: 60}
}
func newTestEngine(t *testing.T) (*Engine, *fakeBackend, *time.Time) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	f := &fakeBackend{state: validManagement(), activeMAC: validManagement().MAC, native: true, persist: true, gateway: true}
	now := time.Now()
	e, err := NewEngine(dir, f)
	if err != nil {
		t.Fatal(err)
	}
	e.now = func() time.Time { return now }
	e.bootNow = func() (bootClock, error) { return bootClock{}, nil }
	return e, f, &now
}

func TestManagementEqualAdoptionNeverActivates(t *testing.T) {
	e, f, _ := newTestEngine(t)
	r, err := e.Ensure(context.Background(), managementRequest(), "old-connection")
	if err != nil || !r.Ready() || f.apply != 0 || f.restore != 0 {
		t.Fatalf("adoption: %+v %v apply=%d", r, err, f.apply)
	}
	q := managementRequest()
	q.Owner = "other"
	if _, err = e.Ensure(context.Background(), q, "other"); err == nil {
		t.Fatal("ownership stolen")
	}
}
func TestManagementDurableRollbackBeforeActivation(t *testing.T) {
	e, f, now := newTestEngine(t)
	q := managementRequest()
	q.Management.Addresses[0].Prefix = "10.0.0.99/24"
	f.beforeApply = func() {
		b, err := os.ReadFile(filepath.Join(e.dir, "host.json"))
		if err != nil || !strings.Contains(string(b), "10.0.0.11/24") {
			t.Fatal("no durable prior state")
		}
	}
	r, err := e.Ensure(context.Background(), q, "first")
	if err != nil || r.Recovery != "Pending" || r.Ready() {
		t.Fatalf("%+v %v", r, err)
	}
	*now = now.Add(61 * time.Second)
	restarted, err := NewEngine(e.dir, f)
	if err != nil {
		t.Fatal(err)
	}
	restarted.now = e.now
	if err = restarted.RecoverExpired(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.restore != 1 || !managementEqual(f.state, validManagement()) {
		t.Fatal("lost connection/restart did not restore")
	}
	if _, err = e.Confirm(context.Background(), Confirmation{Owner: q.Owner, Target: q.Target, Transaction: r.Transaction, Challenge: "stale"}, "fresh"); err == nil {
		t.Fatal("stale confirmation accepted")
	}
}
func TestManagementConfirmationRequiresFreshVerifiedConnection(t *testing.T) {
	e, f, _ := newTestEngine(t)
	q := managementRequest()
	q.Management.Addresses[0].Prefix = "10.0.0.99/24"
	r, err := e.Ensure(context.Background(), q, "first")
	if err != nil {
		t.Fatal(err)
	}
	same, err := e.Get(context.Background(), q, "first")
	if err != nil || same.Challenge != "" {
		t.Fatal("same connection challenge")
	}
	f.gateway = false
	bad, _ := e.Get(context.Background(), q, "fresh")
	if bad.Challenge != "" {
		t.Fatal("unreachable gateway issued challenge")
	}
	f.gateway = true
	fresh, err := e.Get(context.Background(), q, "fresh")
	if err != nil || fresh.Challenge == "" {
		t.Fatal("fresh proof absent")
	}
	confirm := Confirmation{Owner: q.Owner, Target: q.Target, Transaction: r.Transaction, Challenge: fresh.Challenge}
	if _, err = e.Confirm(context.Background(), confirm, "other"); err == nil {
		t.Fatal("connection binding bypassed")
	}
	confirmed, err := e.Confirm(context.Background(), confirm, "fresh")
	if err != nil || !confirmed.Ready() {
		t.Fatalf("confirm: %+v %v", confirmed, err)
	}
}
func TestManagementCandidateFailureAndFailedRecovery(t *testing.T) {
	e, f, now := newTestEngine(t)
	q := managementRequest()
	q.Management.MAC = "02:00:00:00:00:99"
	f.invalid = true
	if _, err := e.Ensure(context.Background(), q, "c"); err == nil || strings.Contains(err.Error(), "credential-looking") {
		t.Fatal("candidate failure was not sanitized")
	}
	if f.apply != 0 {
		t.Fatal("invalid candidate applied")
	}
	f.invalid = false
	f.failApply = true
	f.failRestore = true
	if _, err := e.Ensure(context.Background(), q, "c"); err == nil {
		t.Fatal("failed activation accepted")
	}
	*now = now.Add(time.Minute)
	if err := e.RecoverExpired(context.Background()); err == nil {
		t.Fatal("failed rollback disappeared")
	}
	f.failRestore = false
	if err := e.RecoverExpired(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func TestSystemCredentialsNeverJournaled(t *testing.T) {
	e, f, _ := newTestEngine(t)
	f.native = false
	q := Request{Kind: "System", Owner: "uid", Target: "switch", Revision: "generation-1-secret-rv-7", System: &System{SNMP: &SNMP{Community: Credential("super-secret-marker")}}}
	_, _ = e.Ensure(context.Background(), q, "conn")
	b, err := os.ReadFile(filepath.Join(e.dir, "host.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "super-secret-marker") {
		t.Fatal("credential journaled")
	}
}
func TestStoreRejectsSymlink(t *testing.T) {
	e, _, _ := newTestEngine(t)
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(e.dir, "host.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Ensure(context.Background(), managementRequest(), "c"); err == nil {
		t.Fatal("symlink store accepted")
	}
}

func TestManagementRepairsNativeDriftInsteadOfAdoptingRedisOnly(t *testing.T) {
	e, f, _ := newTestEngine(t)
	f.native = false
	f.beforeApply = func() { f.native = true }
	q := managementRequest()
	out, err := e.Ensure(context.Background(), q, "original")
	if err != nil || f.apply != 1 || out.Recovery != "Pending" || out.Ready() {
		t.Fatalf("runtime drift was not repaired under rollback: %+v %v", out, err)
	}
}
