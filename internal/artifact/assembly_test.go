// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"context"
	"errors"
	"testing"
	"time"
)

type assemblyFence struct{ entered chan context.Context }

func (f assemblyFence) WithMutation(ctx context.Context, action func() error) error {
	if f.entered != nil {
		f.entered <- ctx
		<-ctx.Done()
		return ctx.Err()
	}
	return action()
}
func (f assemblyFence) WithAgentRecovery(ctx context.Context, _, _, _ string, action func() error) error {
	return f.WithMutation(ctx, action)
}

func TestNativeAssemblyBindsConfirmationCancellation(t *testing.T) {
	old, root := testEngine(t)
	old.Close()
	f := assemblyFence{entered: make(chan context.Context, 1)}
	e, n, err := NewNativeEngine(root, "/host/artifacts", old.Policy, f)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if n.Engine != e || e.BootID == nil || e.Preflight == nil || e.ProcessID == nil || e.Uptime == nil || e.PlanTLS == nil || e.RecoveryInput == nil || e.RestorePackages == nil || e.BootRuntimeRestore == nil || e.ValidatePlatformBoot == nil || e.Finalize == nil || e.RetirementCheck == nil || e.AgentRecoveryGuard == nil || e.ActivateAgentRecovery == nil || e.AgentRecoveryHealth == nil || !e.DeferActivation || !e.PauseRuntime {
		t.Fatal("incomplete production assembly")
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { _, err := e.ConfirmContext(ctx, testBundle(), "token", time.Now()); done <- err }()
	<-f.entered
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("command assembly detached canceled request")
	}
}
