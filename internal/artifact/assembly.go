// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
)

type WriterFence interface {
	WithMutation(context.Context, func() error) error
	WithAgentRecovery(context.Context, string, string, string, func() error) error
}

// NewNativeEngine is shared by the supervisor command and recovery tests.
// Guards run before the engine mutex; request contexts must be passed explicitly
// rather than read from the mutable request binding protected by that mutex.
func NewNativeEngine(root, state string, policy Policy, fence WriterFence) (*Engine, *Native, error) {
	if fence == nil {
		return nil, nil, fmt.Errorf("cooperating writer fence required")
	}
	n := &Native{}
	e, err := Open(root, state, policy, n.Health, n.Activate)
	if err != nil {
		return nil, nil, err
	}
	n.Engine = e
	e.BootID, e.Preflight, e.ProcessID, e.Uptime = n.BootID, n.Preflight, n.PID, n.Uptime
	e.DeferActivation, e.PauseRuntime = true, true
	e.Finalize, e.RetirementCheck = n.Finalize, n.RetirementCheck
	e.PlanPlatform, e.PlanTLS, e.RecoveryInput = n.PlanPlatform, n.PlanTLS, n.LoadedRecoveryInput
	e.MutationGuard = func(ctx context.Context, action func() error) error {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		return retryHostBusy(ctx, func(guarded func() error) error {
			return fence.WithMutation(ctx, func() error { return n.WithHostFence(ctx, guarded) })
		}, action)
	}
	e.AgentRecoveryGuard = func(ctx context.Context, owner, token, manifest string, action func() error) error {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		return retryHostBusy(ctx, func(guarded func() error) error {
			return fence.WithAgentRecovery(ctx, owner, token, manifest, func() error { return n.WithAgentRecoveryFence(ctx, owner, token, manifest, guarded) })
		}, action)
	}
	e.ActivateAgentRecovery, e.AgentRecoveryHealth = n.ActivateAgentRecovery, n.AgentRecoveryHealth
	e.RestorePackages, e.BootRuntimeRestore, e.ValidatePlatformBoot = n.RestorePackages, n.RestoreBootRuntime, n.ColdPlatformBoot
	return e, n, nil
}

// attempt must unwind every writer lock before returning ErrBusy. The deadline
// belongs to the whole guard, not each attempt, including reserved recovery.
// Only acquisition can retry: an entered action may already have mutated state,
// even if it returns a wrapped ErrBusy. Mark entry inside the innermost fence.
func retryHostBusy(ctx context.Context, attempt func(func() error) error, action func() error) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		entered := false
		err := attempt(func() error {
			entered = true
			return action()
		})
		if entered || !errors.Is(err, host.ErrBusy) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}
