// SPDX-License-Identifier: Apache-2.0
package sonic

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/ironcore-dev/sonic-operator/internal/agent/artifactstate"
	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

// Legacy dual-pending states are serialized by the complete writer lock set.
// Only one already-recorded dependency may finish, with its existing fingerprint,
// safety and activation checks. New desired work never receives this permit.
func (m *SonicAgent) recoverHostDependencies(ctx context.Context) error {
	if e := host.CheckPending(m.hostJournalDir); e == nil {
		return nil
	} else if !errors.Is(e, host.ErrConflict) {
		return e
	}
	return m.withHostWriterLocks(ctx, func(locks hostWriterLocks) error {
		if err := artifactstate.CheckRecovery(m.artifactStateDir); err != nil {
			return err
		}
		type recovery func(context.Context, vlanChangeDB, string) *agent.Status
		var work []recovery
		var networkState *networkJournalState
		if locks.vlan != nil {
			d, e := locks.vlan.root.Open(".")
			if e != nil {
				return host.ErrStorage
			}
			files, e := d.ReadDir(-1)
			d.Close()
			if e != nil {
				return host.ErrStorage
			}
			for _, file := range files {
				if !strings.HasSuffix(file.Name(), ".json") {
					continue
				}
				id, e := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(file.Name(), "vlan-"), ".json"), 10, 32)
				if e != nil || vlanAuthorityFile(uint32(id)) != file.Name() {
					return host.ErrStorage
				}
				r, e := locks.vlan.load(uint32(id))
				if e != nil || r == nil {
					return host.ErrStorage
				}
				if r.Pending != nil {
					work = append(work, func(ctx context.Context, db vlanChangeDB, raw string) *agent.Status {
						_, st := m.recoverVLANAuthority(ctx, locks.vlan, r, db, raw)
						return st
					})
				}
			}
		}
		if locks.breakout != nil {
			r, e := loadBreakoutRecord(locks.breakout)
			if e != nil {
				return host.ErrStorage
			}
			if r != nil && r.Pending {
				work = append(work, func(ctx context.Context, db vlanChangeDB, raw string) *agent.Status {
					_, st := m.finishBreakout(ctx, locks.breakout, r, networkState, db, raw)
					return st
				})
			}
		}
		if locks.network != nil {
			state, e := loadNetworkJournal(locks.network)
			if e != nil {
				return host.ErrStorage
			}
			networkState = state
			for identity, r := range state.Records {
				if r.Pending != nil {
					work = append(work, func(ctx context.Context, db vlanChangeDB, raw string) *agent.Status {
						_, st := m.finishRecordedNetwork(ctx, locks.network, state, identity, r, db, raw)
						return st
					})
				}
			}
		}
		if len(work) == 0 {
			return nil
		}
		if len(work) != 1 {
			return host.ErrConflict
		}
		snapshot := m.hostRecoverySnapshot
		if snapshot == nil {
			snapshot = m.NewHostNative().Snapshot
		}
		current, e := snapshot(ctx)
		if e != nil {
			return host.ErrNative
		}
		unlock, e := host.DeferForRecordedRecovery(ctx, m.hostJournalDir, current)
		if e != nil {
			return e
		}
		defer unlock()
		db, raw, e := m.vlanChangeSnapshot(ctx)
		if e != nil {
			return host.ErrNative
		}
		recoveryCtx := context.WithValue(context.WithValue(ctx, hostCASKey{}, true), artifactRecoveryKey{}, true)
		if st := work[0](recoveryCtx, db, raw); st != nil && st.Code != 0 {
			return host.ErrConflict
		}
		return nil
	})
}
