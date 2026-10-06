// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ironcore-dev/sonic-operator/internal/agent/artifactstate"
	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
)

type retryEntryFence struct {
	t              *testing.T
	writer         sync.Mutex
	attempts, busy int
	deadline       time.Time
}

func (f *retryEntryFence) WithMutation(ctx context.Context, action func() error) error {
	if !f.writer.TryLock() {
		f.t.Fatal("retry retained writer lock")
	}
	defer f.writer.Unlock()
	f.attempts++
	deadline, ok := ctx.Deadline()
	if !ok {
		f.t.Fatal("unbounded retry")
	}
	if f.attempts == 1 {
		f.deadline = deadline
	} else if !deadline.Equal(f.deadline) {
		f.t.Error("retry reset original deadline")
	}
	if f.busy < 0 || f.attempts <= f.busy {
		return fmt.Errorf("host acquisition: %w", host.ErrBusy)
	}
	return action()
}
func (f *retryEntryFence) WithAgentRecovery(ctx context.Context, _, _, _ string, action func() error) error {
	return f.WithMutation(ctx, action)
}

func TestArtifactAssemblyRetryStopsAtInnermostActionEntry(t *testing.T) {
	for _, guard := range []string{"mutation", "agent-recovery"} {
		for _, scenario := range []string{"entered-busy", "preentry-busy", "preentry-deadline"} {
			t.Run(guard+"/"+scenario, func(t *testing.T) {
				old, root := testEngine(t)
				old.Close()
				f := &retryEntryFence{t: t}
				if scenario == "preentry-busy" {
					f.busy = 2
				}
				if scenario == "preentry-deadline" {
					f.busy = -1
				}
				e, _, err := NewNativeEngine(root, "/host/artifacts", old.Policy, f)
				if err != nil {
					t.Fatal(err)
				}
				defer e.Close()
				token, manifest := strings.Repeat("a", 32), strings.Repeat("b", 64)
				if err := artifactstate.Store(e.reservationDir(), artifactstate.Reservation{Version: 1, Owner: "owner", Token: token, Manifest: manifest, Phase: "Active"}); err != nil {
					t.Fatal(err)
				}
				budget := time.Second
				if scenario == "preentry-deadline" {
					budget = 40 * time.Millisecond
				}
				ctx, cancel := context.WithTimeout(t.Context(), budget)
				defer cancel()
				calls := 0
				enteredErr := fmt.Errorf("action returned busy after entry: %w", host.ErrBusy)
				action := func() error {
					calls++
					if f.writer.TryLock() {
						f.writer.Unlock()
						t.Error("action ran without writer exclusion")
					}
					if scenario == "entered-busy" {
						return enteredErr
					}
					return nil
				}
				if guard == "mutation" {
					err = e.MutationGuard(ctx, action)
				} else {
					err = e.AgentRecoveryGuard(ctx, "owner", token, manifest, action)
				}
				switch scenario {
				case "entered-busy":
					if err != enteredErr || calls != 1 || f.attempts != 1 {
						t.Errorf("entered action replayed: calls=%d attempts=%d err=%v", calls, f.attempts, err)
					}
				case "preentry-busy":
					if err != nil || calls != 1 || f.attempts != 3 {
						t.Errorf("preentry retry: calls=%d attempts=%d err=%v", calls, f.attempts, err)
					}
				case "preentry-deadline":
					if !errors.Is(err, context.DeadlineExceeded) || calls != 0 {
						t.Errorf("busy deadline entered action: calls=%d err=%v", calls, err)
					}
				}
				if !f.writer.TryLock() {
					t.Fatal("guard leaked writer")
				}
				f.writer.Unlock()
			})
		}
	}
}
