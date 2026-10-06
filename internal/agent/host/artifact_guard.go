// SPDX-License-Identifier: Apache-2.0
package host

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/ironcore-dev/sonic-operator/internal/agent/artifactstate"
)

// WithArtifactExclusion holds the real host lock across artifact publication.
// Unlike CheckPending it is only called after the complete writer lock set.
func WithArtifactExclusion(ctx context.Context, dir string, action func() error) error {
	return withArtifactExclusion(ctx, dir, false, action)
}

// The caller must already hold and validate its artifact reservation. This
// permits only old-Agent dependency repair, never host replay or a new claim.
func WithArtifactAgentRecoveryExclusion(ctx context.Context, dir string, action func() error) error {
	return withArtifactExclusion(ctx, dir, true, action)
}

func withArtifactExclusion(ctx context.Context, dir string, recovery bool, action func() error) error {
	r, unlock, err := lockRecord(ctx, dir, nil)
	if err != nil {
		return err
	}
	defer unlock()
	if err := validateArtifactRecord(r); err != nil {
		return err
	}
	if r.Pending != nil && !recovery {
		return fmt.Errorf("%w: management", artifactstate.ErrForeignPending)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return action()
}

// A syntactically decodable fragment is not evidence of recorded recovery.
// Keep semantic validation here read-only; never normalize/rewrite host state.
func validateArtifactRecord(r *record) error {
	for _, c := range []*claim{r.Management, r.System, r.RolledBack} {
		if c != nil && (!safeID.MatchString(c.Owner) || !safeID.MatchString(c.Target) || !safeID.MatchString(c.Revision)) {
			return ErrStorage
		}
	}
	p := r.Pending
	if p == nil {
		return nil
	}
	id, err := hex.DecodeString(p.ID)
	if err != nil || len(id) != 32 || r.Management == nil || *r.Management != p.Claim || p.Connection == "" || p.Created.IsZero() || !p.Deadline.After(p.Created) || (p.BootID != "" && p.DeadlineUptime <= 0) {
		return ErrStorage
	}
	if validateRecoveryScope(RecoveryScope{MACOwned: p.MACOwned, Before: p.Before, Candidate: p.Candidate, ObservedActiveMAC: p.ObservedActiveMAC}) != nil {
		return ErrStorage
	}
	return nil
}
