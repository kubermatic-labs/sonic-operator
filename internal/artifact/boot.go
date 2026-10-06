// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"context"
	"fmt"
	"time"
)

// RestoreBoot restores confirmed generating inputs before native platform
// services. It only runs across boot identities, never as blind drift repair.
func (e *Engine) RestoreBoot() error {
	if e.MutationGuard != nil {
		return e.MutationGuard(context.Background(), e.restoreBoot)
	}
	return e.restoreBoot()
}
func (e *Engine) restoreBoot() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.restoreBootLocked()
}
func (e *Engine) restoreBootLocked() error {
	j, err := e.load()
	if err != nil || j == nil {
		return err
	}
	changedBoot := e.BootID != nil && j.BootID != e.BootID()
	if (j.Phase == "ActivatingBoot" || j.Phase == "RecoveringBoot") && !changedBoot {
		return nil
	}
	if (j.Phase != "Confirmed" && j.Phase != "RolledBack" && j.BootPriorPhase == "") || j.Active == nil || e.BootID == nil || j.Active.BootID == e.BootID() {
		return nil
	}
	active := *j
	active.Token = j.Active.Token
	if err := e.validateProtectedAgent(&active, "new", j.Active.Files); err != nil {
		return err
	}
	if err := e.reserve(j); err != nil {
		return err
	}
	if j.BootPriorPhase == "" || changedBoot {
		j.BootRuntimeApplied = false
		j.BootRuntimeIdentity = ""
		j.BootID = e.BootID()
		if err := e.armDeadline(j, time.Now()); err != nil {
			return err
		}
	}
	if j.BootPriorPhase == "" {
		j.BootPriorPhase = j.Phase
	}
	j.Phase = "RestoringBoot"
	if err := e.save(j); err != nil {
		return err
	}
	for i, f := range j.Active.Files {
		if packageGeneratedSlot(&active, f.Slot) {
			continue
		}
		data, _, err := e.read(e.storage(&active, "new", i))
		if err != nil || Digest(data) != f.Hash {
			return fmt.Errorf("confirmed boot content unavailable")
		}
		if err := e.atomic(f.Path, data, f.Mode); err != nil {
			return err
		}
	}
	j.BootID = e.BootID()
	if e.BootRuntimeRestore != nil {
		j.Phase = "ActivatingBoot"
		return e.save(j)
	}
	j.Active.BootID = e.BootID()
	j.Changed = false
	j.PreviousPID = ""
	j.Phase = j.BootPriorPhase
	j.BootPriorPhase = ""
	if err := e.save(j); err != nil {
		return err
	}
	return e.release(j)
}
