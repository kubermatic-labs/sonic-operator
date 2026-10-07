// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSupervisorCallbacksBoundEngineMutexWait(t *testing.T) {
	for _, name := range []string{"tick", "boot"} {
		t.Run(name, func(t *testing.T) {
			e, root := testEngine(t)
			e.Close()
			e, _, err := NewNativeEngine(root, "/host/artifacts", e.Policy, assemblyFence{})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			e.mu.Lock()
			done := make(chan error, 1)
			go func() {
				if name == "boot" {
					done <- e.RestoreBoot()
				} else {
					done <- e.Tick(time.Now())
				}
			}()
			select {
			case err := <-done:
				e.mu.Unlock()
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal(err)
				}
			case <-time.After(2500 * time.Millisecond):
				e.mu.Unlock()
				<-done
				t.Fatal("supervisor callback retained writer guard past its 2s mutex deadline")
			}
			if err := e.mu.LockContext(t.Context()); err != nil {
				t.Fatal(err)
			}
			e.mu.Unlock()
		})
	}
}
