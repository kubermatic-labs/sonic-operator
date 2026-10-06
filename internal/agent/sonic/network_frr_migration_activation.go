// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"fmt"
	"strings"
	"time"
)

func frrMigrationActivated(ctx context.Context, db vlanChangeDB, receipt frrMigrationReceipt, owner string) (bool, error) {
	if receipt.Owner != owner || vlanAuthorityHash(db) != receipt.PostHash || !networkSubset(db, frrMigrationDesired(receipt.Mode)) {
		return false, fmt.Errorf("migration launch binding mismatch")
	}
	service, err := runFRRMigration(ctx, frrMigrationService)
	if err != nil {
		return false, err
	}
	start, err := frrMigrationStart(service)
	if err != nil {
		return false, err
	}
	if start == receipt.StartHash {
		return false, nil
	}
	evidence, err := inspectFRRMigration(ctx, db, frrMigrationMode(receipt.Mode))
	if err != nil {
		return false, err
	}
	return evidence.StartHash == start && evidence.ContainerHash != receipt.ContainerHash && evidence.CandidateHash == receipt.CandidateHash && evidence.InputsHash == receipt.InputsHash && evidence.RoutesHash == receipt.RoutesHash, nil
}

func activateFRRMigration(ctx context.Context, m *SonicAgent, owner string, modes ...string) error {
	mode := frrMigrationMode(modes...)
	receipt, err := frrMigrationPendingReceipt(m, owner, mode)
	if err != nil || receipt.Owner != owner {
		return fmt.Errorf("migration preparation unavailable")
	}
	db, _, err := m.vlanChangeSnapshot(ctx)
	if err != nil || vlanAuthorityHash(db) != receipt.PostHash || !networkSubset(db, frrMigrationDesired(mode)) {
		return fmt.Errorf("migration post snapshot mismatch")
	}
	// Validate all raw runtime and target-generation inputs immediately before
	// dispatch too: the metadata CAS must not authorize a changed FRR baseline.
	pre := frrMigrationRestoreMode(db, receipt.Before)
	evidence, err := inspectFRRMigration(ctx, pre, mode)
	if err != nil {
		return err
	}
	if evidence.StartHash != receipt.StartHash || evidence.ConfigHash != receipt.ConfigHash || evidence.CandidateHash != receipt.CandidateHash || evidence.InputsHash != receipt.InputsHash || frrMigrationDigest(pre, evidence, mode) != receipt.Digest {
		return fmt.Errorf("runtime or template inputs changed before migration restart")
	}
	if _, err = runFRRMigration(ctx, frrMigrationRestart); err != nil {
		return err
	}
	for attempt := 0; attempt < 30; attempt++ {
		current, _, err := m.vlanChangeSnapshot(ctx)
		if err != nil || vlanAuthorityHash(current) != receipt.PostHash {
			return fmt.Errorf("configuration changed during migration activation")
		}
		ready, err := frrMigrationActivated(ctx, current, receipt, owner)
		if err == nil && ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("migration runtime verification timed out")
		case <-time.After(time.Second):
		}
	}
	return fmt.Errorf("migration restart not verified; manual inspection required, restart will not be repeated")
}

func frrMigrationRestoreMode(db, before vlanChangeDB) vlanChangeDB {
	pre := frrMigrationPost(db)
	for field := range frrMigrationDesired()["DEVICE_METADATA|localhost"] {
		delete(pre["DEVICE_METADATA|localhost"], field)
		if value, ok := before["DEVICE_METADATA|localhost"][field]; ok {
			pre["DEVICE_METADATA|localhost"][field] = value
		}
	}
	return pre
}

func frrMigrationCheckTarget(ctx context.Context, receipt frrMigrationReceipt) error {
	candidate, err := frrMigrationRender(ctx, frrMigrationMode(receipt.Mode))
	if err != nil || vlanChangeHash(candidate) != receipt.CandidateHash {
		return fmt.Errorf("migration target candidate changed")
	}
	inputs, err := runFRRMigration(ctx, frrMigrationInputs)
	if err != nil || strings.TrimSpace(string(inputs)) != receipt.InputsHash {
		return fmt.Errorf("migration startup inputs changed")
	}
	return nil
}
