// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/ironcore-dev/sonic-operator/internal/agent/artifactstate"
)

func (e *Engine) reservationDir() string { return filepath.Join(e.root.Name(), e.state) }
func (e *Engine) reservation(j *journal, phase string) error {
	return artifactstate.Store(e.reservationDir(), artifactstate.Reservation{Version: 1, Owner: j.Owner, Token: j.Token, Manifest: j.Identity, Phase: phase})
}
func (e *Engine) reserve(j *journal) error {
	if err := e.reservation(j, "Active"); err != nil {
		return err
	}
	j.Reserved = true
	return nil
}
func (e *Engine) release(j *journal) error {
	if !j.Reserved {
		return nil
	}
	if err := e.reservation(j, "Idle"); err != nil {
		return err
	}
	j.Reserved = false
	return e.save(j)
}

// Dependency restoration never changes a platform input, CONFIG_DB or a foreign
// journal. Its authority is the already-published reservation and validated old
// Agent* content. The restored agent may then finish existing foreign recovery.
//
//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func (e *Engine) restoreAgentDependency(now time.Time) error {
	e.mu.Lock()
	j, err := e.load()
	e.mu.Unlock()
	if err != nil || j == nil {
		return err
	}
	if j.Reserved && (j.Phase == "Confirmed" || j.Phase == "RolledBack") && e.AgentRecoveryGuard != nil {
		return e.AgentRecoveryGuard(context.Background(), j.Owner, j.Token, j.Identity, func() error { e.mu.Lock(); defer e.mu.Unlock(); return e.release(j) })
	}
	if !j.Reserved || (!e.expired(j, now) && j.Phase != "WaitingForeign" && j.Phase != "RestoringAgent") {
		return fmt.Errorf("foreign recovery blocks artifact continuation")
	}
	r, err := artifactstate.Read(e.reservationDir())
	if err != nil || r == nil || r.Owner != j.Owner || r.Token != j.Token || r.Manifest != j.Identity || r.Phase == "Idle" {
		return fmt.Errorf("agent restoration has no valid reservation")
	}
	if e.AgentRecoveryGuard == nil || e.ActivateAgentRecovery == nil || e.AgentRecoveryHealth == nil {
		return fmt.Errorf("agent dependency recovery unavailable")
	}
	return e.AgentRecoveryGuard(context.Background(), j.Owner, j.Token, j.Identity, func() error {
		e.mu.Lock()
		defer e.mu.Unlock()
		current, err := e.load()
		if err != nil || current == nil || current.Token != j.Token {
			return fmt.Errorf("agent recovery identity changed")
		}
		j = current
		if j.Phase == "WaitingForeign" {
			return nil
		}
		if j.Phase != "RestoringAgent" {
			j.RollbackPID = ""
			if e.ProcessID != nil {
				j.RollbackPID = e.ProcessID()
			}
			j.Phase = "RestoringAgent"
			j.Reason = "ForeignRecoveryDependency"
			if err := e.save(j); err != nil {
				return err
			}
		}
		found := false
		replay := j.Files
		source := *j
		which := "old"
		if j.BootPriorPhase != "" && j.Active != nil {
			replay = append([]savedFile(nil), j.Active.Files...)
			source.Token = j.Active.Token
			which = "new"
			for i := range replay {
				replay[i].Existed = true
				replay[i].PreviousHash = replay[i].Hash
				replay[i].PreviousMode = replay[i].Mode
			}
		}
		// Validate the complete restricted replay before touching any destination.
		if err := e.validateProtectedAgent(&source, which, replay); err != nil {
			return err
		}
		for i, f := range replay {
			if !agentRecoverySlot(f.Slot) {
				continue
			}
			if !f.Existed {
				return fmt.Errorf("no previous working agent input")
			}
			data, _, err := e.read(e.storage(&source, which, i))
			if err != nil || Digest(data) != f.PreviousHash {
				return fmt.Errorf("agent recovery content invalid")
			}
			if f.Slot == "AgentBinary" {
				if err := ValidateAgentRelease(e.Policy, Digest(data)); err != nil {
					return err
				}
				found = true
			}
		}
		if !found {
			return fmt.Errorf("agent binary must be declared for dependency recovery")
		}
		if !j.DependencyActivated {
			for i, f := range replay {
				if !agentRecoverySlot(f.Slot) {
					continue
				}
				data, _, _ := e.read(e.storage(&source, which, i))
				if err := e.atomic(f.Path, data, f.PreviousMode); err != nil {
					return err
				}
			}
			if err := e.ActivateAgentRecovery(); err != nil {
				return err
			}
			j.DependencyActivated = true
			if err := e.save(j); err != nil {
				return err
			}
		}
		if err := e.AgentRecoveryHealth(); err != nil {
			return err
		}
		j.Phase = "WaitingForeign"
		if err := e.save(j); err != nil {
			return err
		}
		return e.reservation(j, "ForeignRecovery")
	})
}
