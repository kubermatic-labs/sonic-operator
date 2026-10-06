// SPDX-License-Identifier: Apache-2.0
package host

import "context"

// DeferForRecordedRecovery is only for a cooperating writer completing an
// already-journaled operation. Caller holds config/VLAN/breakout/network locks,
// validates its exact pending owner/request and full database fingerprint, and
// retains this last (host) lock until completion. It never clears the host fence.
func DeferForRecordedRecovery(ctx context.Context, dir string, current Snapshot) (func(), error) {
	r, unlock, err := lockRecord(ctx, dir, nil)
	if err != nil {
		return nil, err
	}
	if r.Pending == nil {
		unlock()
		return nil, ErrConflict
	}
	candidate := r.Pending.Candidate
	if candidate.MAC == "" {
		candidate.MAC = r.Pending.Before.Management.MAC
	}
	if !managementEqual(current.Management, r.Pending.Before.Management) && !managementEqual(current.Management, candidate) {
		unlock()
		return nil, ErrConflict
	}
	return unlock, nil
}
