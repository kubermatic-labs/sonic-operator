// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"context"
	"fmt"
	"strings"
	"time"
)

func (n *Native) ColdPlatformBoot() error {
	raw, _, err := n.Engine.read("proc/cmdline")
	if err != nil {
		return fmt.Errorf("platform boot type unavailable")
	}
	for _, arg := range strings.Fields(string(raw)) {
		if strings.HasPrefix(arg, "SONIC_BOOT_TYPE=") && arg != "SONIC_BOOT_TYPE=cold" {
			return fmt.Errorf("changed platform inputs require a qualified cold boot")
		}
	}
	return nil
}

func fileChanged(f savedFile) bool {
	return !f.ObservedExisted || f.ObservedHash != f.Hash || f.ObservedMode != f.Mode
}

// rollbackFileChanged reports whether rollback writes something other than
// the pre-stage observation. Rollback restores the last confirmed bytes, which
// can differ from the observation even when the candidate matched it (for
// example a hand-installed agent), so it cannot reuse fileChanged.
func rollbackFileChanged(f savedFile) bool {
	if !f.Existed {
		return f.ObservedExisted
	}
	return !f.ObservedExisted || f.ObservedHash != f.PreviousHash || f.ObservedMode != f.PreviousMode
}
func platformMutation(j *journal) bool {
	if j.RuntimePlatformDrift {
		return true
	}
	for _, f := range j.Files {
		p, _, err := Destination(f.Slot)
		if err == nil && p == "" && fileChanged(f) {
			return true
		}
	}
	return false
}
func asicMutation(j *journal) bool {
	if j.RuntimePlatformDrift {
		return true
	}
	for _, f := range j.Files {
		switch f.Slot {
		case "PlatformJSON", "HWSKUJSON", "PortConfig", "SAIProfile", "BroadcomConfig":
			if fileChanged(f) {
				return true
			}
		}
	}
	return false
}
func agentMutation(j *journal) bool {
	if j.RuntimeAgentDrift {
		return true
	}
	for _, f := range j.Files {
		if agentRecoverySlot(f.Slot) && (fileChanged(f) || (j.Phase == "RollingBack" && rollbackFileChanged(f))) {
			return true
		}
	}
	return false
}

// rollbackChanged reports whether rollback writes any file differing from the
// pre-stage observation, which then requires activation like a change.
func rollbackChanged(j *journal) bool {
	for _, f := range j.Files {
		if !packageGeneratedSlot(j, f.Slot) && rollbackFileChanged(f) {
			return true
		}
	}
	return false
}
func (n *Native) PlanPlatform(b Bundle) (bool, error) {
	current, err := n.Engine.load()
	if err != nil {
		return false, err
	}
	if current == nil || current.Active == nil {
		for _, f := range b.Files {
			if f.Slot == "PlatformWheel" {
				if b.Activation != "PlatformNextBoot" {
					return false, fmt.Errorf("initial import provenance requires guarded platform activation")
				}
				return true, nil
			}
		}
		return false, nil
	}
	probe := *current
	probe.Files = current.Active.Files
	probe.Packages = current.Active.Packages
	probe.LauncherManifest = current.Active.LauncherManifest
	probe.Phase = "Confirmed"
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if n.platformHealth(ctx, &probe) == nil {
		return false, nil
	}
	if b.Activation != "PlatformNextBoot" {
		return false, fmt.Errorf("native platform drift requires explicit PlatformNextBoot repair")
	}
	return true, nil
}
