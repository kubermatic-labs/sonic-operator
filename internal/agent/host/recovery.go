// SPDX-License-Identifier: Apache-2.0
package host

import (
	"context"
	"errors"
)

func (e *Engine) restore(ctx context.Context, r *record) error {
	p := r.Pending
	if p == nil {
		return nil
	}
	q := Request{Kind: "Management", Owner: p.Claim.Owner, Target: p.Claim.Target, Revision: p.Claim.Revision, Management: &p.Before.Management, RollbackSeconds: 60}
	if p.MACOwned != nil && !*p.MACOwned {
		before := p.Before.Management
		before.MAC = ""
		q.Management = &before
	}
	if e.backend.RestoreManagement(ctx, RecoveryScope{MACOwned: p.MACOwned, Before: p.Before, Candidate: p.Candidate, ObservedActiveMAC: p.ObservedActiveMAC}) != nil {
		return ErrNative
	}
	v, err := e.backend.Observe(ctx, q)
	if err != nil || !v.ConfigurationVerified || !v.RuntimeVerified || !v.PersistenceVerified {
		return ErrNative
	}
	r.RolledBack = &p.Claim
	r.Pending = nil
	e.proof = proof{}
	return e.save(r)
}

// RecoverExpired runs locally, under the same interprocess lock as Ensure and
// Confirm. It requires neither Kubernetes credentials nor an active RPC client.
func (e *Engine) RecoverExpired(ctx context.Context) error {
	if err := CheckPending(e.dir); err == nil {
		return nil
	} else if !errors.Is(err, ErrConflict) {
		return err
	}
	if err := e.backend.RecoverDependencies(ctx); err != nil {
		return err
	}
	return e.backend.ExclusiveRecovery(ctx, func(locked context.Context) error {
		return e.withRecord(locked, func(r *record) error {
			if r.Pending == nil || !e.expired(r.Pending) {
				return nil
			}
			return e.restore(locked, r)
		})
	})
}
