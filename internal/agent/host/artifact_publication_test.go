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

	"github.com/ironcore-dev/sonic-operator/internal/agent/artifactstate"
)

type publicationBackend struct {
	*fakeBackend
	dir       string
	checks    int
	reserveAt int
}

func (b *publicationBackend) CheckPublication(context.Context) error {
	b.checks++
	if b.checks == b.reserveAt {
		if err := artifactstate.Store(b.dir, artifactstate.Reservation{Version: 1, Owner: "artifact", Token: strings.Repeat("a", 32), Manifest: strings.Repeat("b", 64), Phase: "Active"}); err != nil {
			return err
		}
	}
	return artifactstate.CheckPending(b.dir)
}
func (b *publicationBackend) ExclusiveRecovery(ctx context.Context, fn func(context.Context) error) error {
	if err := artifactstate.CheckRecovery(b.dir); err != nil {
		return err
	}
	return fn(ctx)
}

func TestArtifactReservationBlocksEveryHostPublication(t *testing.T) {
	for _, scenario := range []string{"adopt-management", "adopt-system", "apply-system", "management-pending", "last-pending-boundary"} {
		t.Run(scenario, func(t *testing.T) {
			e, f, _ := newTestEngine(t)
			b := &publicationBackend{fakeBackend: f, dir: t.TempDir(), reserveAt: 1}
			if err := os.Chmod(b.dir, 0700); err != nil {
				t.Fatal(err)
			}
			e.backend = b
			q := managementRequest()
			switch scenario {
			case "adopt-system", "apply-system":
				q.RollbackSeconds = 0
				q.Kind, q.Management, q.System = "System", nil, &System{NTP: &NTP{Servers: []string{"10.0.0.1"}}}
				if scenario == "apply-system" {
					f.native = false
				}
			case "management-pending", "last-pending-boundary":
				q.Management.Addresses[0].Prefix = "10.0.0.99/24"
				if scenario == "last-pending-boundary" {
					b.reserveAt = 2
				}
			}
			if _, err := e.Ensure(t.Context(), q, "transport"); !errors.Is(err, artifactstate.ErrReserved) {
				t.Fatalf("publication escaped reservation: %v (checks=%d)", err, b.checks)
			}
			if f.apply != 0 || f.system != 0 {
				t.Fatal("native dispatch before admission")
			}
			if _, err := os.Stat(filepath.Join(e.dir, "host.json")); !os.IsNotExist(err) {
				t.Fatalf("new claim or Pending was published: %v", err)
			}
		})
	}
}

func TestRecordedHostRecoveryDoesNotBorrowNewPublication(t *testing.T) {
	e, f, now := newTestEngine(t)
	b := &publicationBackend{fakeBackend: f, dir: t.TempDir()}
	_ = os.Chmod(b.dir, 0700)
	e.backend = b
	q := managementRequest()
	q.Management.Addresses[0].Prefix = "10.0.0.99/24"
	if _, err := e.Ensure(t.Context(), q, "old"); err != nil {
		t.Fatal(err)
	}
	b.reserveAt = b.checks + 1
	if err := b.CheckPublication(t.Context()); !errors.Is(err, artifactstate.ErrReserved) {
		t.Fatal(err)
	}
	f.exclusive = func(ctx context.Context, fn func(context.Context) error) error {
		if err := artifactstate.CheckPending(b.dir); err != nil {
			return err
		}
		return fn(ctx)
	}
	*now = now.Add(61 * time.Second)
	reopened, err := NewEngine(e.dir, b)
	if err != nil {
		t.Fatal(err)
	}
	reopened.now = e.now
	if err := reopened.RecoverExpired(t.Context()); err != nil {
		t.Fatalf("dual pending deadlock: %v", err)
	}
	if f.restore != 1 || !managementEqual(f.state, validManagement()) {
		t.Fatal("recorded recovery did not restore Before")
	}
	if _, err := reopened.Ensure(t.Context(), managementRequest(), "new"); !errors.Is(err, artifactstate.ErrReserved) {
		t.Fatalf("new publication borrowed recovery: %v", err)
	}
}
