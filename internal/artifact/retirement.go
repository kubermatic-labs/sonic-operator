// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"fmt"
	"io/fs"
)

const legacyHookPath = "etc/systemd/system/rc-local.service.d/dc-core001-site.conf"
const legacyScriptPath = "usr/local/sbin/dc-core001-site-restore.py"
const legacyRetiredMarker = "# Owned by SwitchArtifact: legacy site restoration is retired.\n# The durable artifact supervisor restores confirmed inputs before native services.\n"
const legacyHookSHA = "85b2b5f696560596688008bbc5e2f0cecddee9fd304d9f7bc0de0530bbf10407"
const legacyScriptSHA = "f81ba79bd1e90e1b0d854ebe716ad83fb6f1ca9ee0ffeafca656ea5189c49682"

func retirementSlot(slot string) bool { return slot == "LegacySiteHook" || slot == "LegacySiteRestore" }
func generatedDestination(slot string) (string, fs.FileMode, bool) {
	switch slot {
	case "AgentUnit":
		return "etc/systemd/system/sonic-operator-agent.service", 0644, true
	case "LegacySiteHook":
		return legacyHookPath, 0644, true
	case "LegacySiteRestore":
		return legacyScriptPath, 0644, true
	}
	return "", 0, false
}
func retirementFiles(b Bundle) ([]File, error) {
	if !b.RetireLegacyHook {
		return nil, nil
	}
	slots := map[string]bool{}
	for _, f := range b.Files {
		slots[f.Slot] = true
	}
	for slot := range platformModules {
		if !slots[slot] {
			return nil, fmt.Errorf("complete site ownership required before retiring legacy restoration")
		}
	}
	for _, slot := range []string{"PlatformJSON", "HWSKUJSON", "PortConfig", "SAIProfile", "BroadcomConfig", "PlatformWheel"} {
		if !slots[slot] {
			return nil, fmt.Errorf("complete site ownership required before retiring legacy restoration")
		}
	}
	files := []File{}
	for _, slot := range []string{"LegacySiteHook", "LegacySiteRestore"} {
		files = append(files, File{Slot: slot, Data: []byte(legacyRetiredMarker), SHA256: Digest([]byte(legacyRetiredMarker))})
	}
	return files, nil
}

// Called after fresh health and protected staged content have been verified.
// Retiring is durable before either legacy file is touched; process interruption
// restores both originals through the same independent recovery transaction.
func (e *Engine) retireLegacy(j *journal) error {
	has := false
	for _, f := range j.Files {
		if !retirementSlot(f.Slot) {
			continue
		}
		has = true
		current, mode, err := e.read(f.Path)
		if err != nil || !f.ObservedExisted || Digest(current) != f.ObservedHash || mode != f.ObservedMode {
			return fmt.Errorf("legacy restoration changed before retirement")
		}
	}
	if !has {
		return nil
	}
	if e.RetirementCheck != nil {
		if err := e.RetirementCheck(); err != nil {
			return err
		}
	}
	j.Phase = "Retiring"
	if err := e.save(j); err != nil {
		return err
	}
	for i, f := range j.Files {
		if !retirementSlot(f.Slot) {
			continue
		}
		data, _, err := e.read(e.storage(j, "new", i))
		if err != nil || Digest(data) != f.Hash {
			return fmt.Errorf("retirement content verification failed")
		}
		if err := e.atomic(f.Path, data, f.Mode); err != nil {
			return err
		}
	}
	if e.Finalize != nil {
		if err := e.Finalize(); err != nil {
			return err
		}
	}
	for _, f := range j.Files {
		if !retirementSlot(f.Slot) {
			continue
		}
		data, mode, err := e.read(f.Path)
		if err != nil || Digest(data) != f.Hash || mode != f.Mode {
			return fmt.Errorf("retirement persistence verification failed")
		}
	}
	return nil
}
