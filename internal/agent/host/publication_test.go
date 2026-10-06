// SPDX-License-Identifier: Apache-2.0
package host

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestHostIntentCannotPublishOutsideWriterExclusion(t *testing.T) {
	e, f, _ := newTestEngine(t)
	q := managementRequest()
	q.Management.Addresses[0].Prefix = "10.0.0.99/24"
	f.exclusive = func(context.Context, func(context.Context) error) error { return ErrConflict }
	if _, err := e.Ensure(context.Background(), q, "conn"); !errors.Is(err, ErrConflict) {
		t.Fatal("pending writer was not rejected")
	}
	if _, err := os.Stat(filepath.Join(e.dir, "host.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("host intent published before cooperating-writer check")
	}
	if f.apply != 0 {
		t.Fatal("native dispatch escaped writer fence")
	}
}

func TestGuardBindsDurabilityToConcurrentConfirmationRecord(t *testing.T) {
	for _, failPostSync := range []bool{true, false} {
		t.Run(map[bool]string{true: "post-read-sync-fails", false: "post-read-sync-establishes-durability"}[failPostSync], func(t *testing.T) {
			e, backend, _ := newTestEngine(t)
			var writer sync.Mutex
			backend.exclusive = func(ctx context.Context, fn func(context.Context) error) error {
				if err := lockMutex(ctx, &writer); err != nil {
					return err
				}
				defer writer.Unlock()
				return fn(ctx)
			}
			q := managementRequest()
			q.Management.Addresses[0].Prefix = "10.0.0.99/24"
			if _, err := e.Ensure(t.Context(), q, "old"); err != nil {
				t.Fatal(err)
			}
			proof, err := e.Get(t.Context(), q, "fresh")
			if err != nil {
				t.Fatal(err)
			}
			guardSynced, allowRead := make(chan struct{}), make(chan struct{})
			published, allowConfirmSync := make(chan struct{}), make(chan struct{})
			guardDone, confirmDone := make(chan error, 1), make(chan error, 1)
			guardSyncs, confirmationSyncs := 0, 0
			e.syncDir = func(f *os.File) error {
				confirmationSyncs++
				if confirmationSyncs == 1 {
					return f.Sync()
				}
				close(published)
				<-allowConfirmSync
				return ErrStorage
			}
			go func() {
				guardDone <- backend.Exclusive(t.Context(), func(context.Context) error {
					return checkPending(e.dir, func(f *os.File) error {
						guardSyncs++
						if guardSyncs == 1 {
							if err := f.Sync(); err != nil {
								return err
							}
							close(guardSynced)
							<-allowRead
							return nil
						}
						if failPostSync {
							return ErrStorage
						}
						return f.Sync()
					})
				})
			}()
			select {
			case <-guardSynced:
			case <-time.After(2 * time.Second):
				t.Fatal("guard did not reach initial sync")
			}
			go func() {
				_, err := e.Confirm(t.Context(), Confirmation{Owner: q.Owner, Target: q.Target, Transaction: proof.Transaction, Challenge: proof.Challenge}, "fresh")
				confirmDone <- err
			}()
			select {
			case <-published:
			case <-time.After(2 * time.Second):
				t.Fatal("confirmation did not publish between guard sync and read")
			}
			close(allowRead)
			var guardErr error
			select {
			case guardErr = <-guardDone:
			case <-time.After(2 * time.Second):
				t.Fatal("guard blocked on reverse host lock")
			}
			close(allowConfirmSync)
			if err = <-confirmDone; !errors.Is(err, ErrStorage) {
				t.Fatal("confirmation's after-rename failure was not injected")
			}
			if guardSyncs != 2 {
				t.Fatal("guard accepted a newer completion without syncing the actual read record")
			}
			if failPostSync && !errors.Is(guardErr, ErrStorage) {
				t.Fatal("unsynced completion released writer fence")
			}
			if !failPostSync && guardErr != nil {
				t.Fatal("post-read sync failed to establish actual completion durability", guardErr)
			}
			if err = CheckPending(e.dir); err != nil {
				t.Fatal("durable completion did not release fence", err)
			}
		})
	}
}

func TestGuardRejectsPublicationAfterPostReadSync(t *testing.T) {
	for _, absent := range []bool{false, true} {
		t.Run(map[bool]string{false: "replaced-record", true: "replaced-absence"}[absent], func(t *testing.T) {
			e, _, _ := newTestEngine(t)
			if !absent {
				if _, err := e.Ensure(t.Context(), managementRequest(), "connection"); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			err := checkPending(e.dir, func(f *os.File) error {
				calls++
				if err := f.Sync(); err != nil {
					return err
				}
				if calls == 2 {
					return e.save(&record{Pending: &transaction{ID: "newly-published"}})
				}
				return nil
			})
			if calls != 2 || !errors.Is(err, ErrConflict) {
				t.Fatal("guard accepted an identity that changed after its final sync")
			}
		})
	}
}

func TestConfirmationRenameNeedsDirectoryDurabilityBeforeFenceRelease(t *testing.T) {
	e, _, _ := newTestEngine(t)
	q := managementRequest()
	q.Management.Addresses[0].Prefix = "10.0.0.99/24"
	if _, err := e.Ensure(context.Background(), q, "old"); err != nil {
		t.Fatal(err)
	}
	proof, err := e.Get(context.Background(), q, "new")
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	e.syncDir = func(f *os.File) error {
		calls++
		if calls == 1 {
			return f.Sync()
		}
		return ErrStorage
	}
	if _, err = e.Confirm(context.Background(), Confirmation{Owner: q.Owner, Target: q.Target, Transaction: proof.Transaction, Challenge: proof.Challenge}, "new"); !errors.Is(err, ErrStorage) {
		t.Fatal("completion rename durability failure not reported")
	}
	if err = checkPending(e.dir, func(*os.File) error { return ErrStorage }); !errors.Is(err, ErrStorage) {
		t.Fatal("visible completion released fence without durable directory")
	}
	restarted, err := NewEngine(e.dir, e.backend)
	if err != nil {
		t.Fatal(err)
	}
	restarted.syncDir = func(*os.File) error { return ErrStorage }
	if _, err = restarted.Get(context.Background(), q, "third"); !errors.Is(err, ErrStorage) {
		t.Fatal("new process trusted unestablished completion durability")
	}
	if err = CheckPending(e.dir); err != nil {
		t.Fatal("successful directory sync did not resolve visible completion")
	}
}
