// SPDX-License-Identifier: Apache-2.0
package host

import (
	"errors"
	"os"
)

// LegacyMACHook is an imported artifact identity, not a remote executable path.
// The artifact owner retains MAC ownership and the original source evidence;
// only the activation adapter at the existing hook path is replaced. A future
// transfer to typed MAC ownership requires a separately approved handoff.
type LegacyMACHook struct {
	BaseMAC string `json:"baseMAC,omitempty"`
	// Hostname is required for the Python helper, which selects its MAC by hostname.
	Hostname     string    `json:"hostname,omitempty"`
	Kind         string    `json:"kind"`
	HookSHA256   string    `json:"hookSHA256"`
	HelperSHA256 string    `json:"helperSHA256"`
	MAC          string    `json:"mac"`
	Addresses    []Address `json:"addresses"`
}

func (n *Native) validateLegacyMACHooks(desired Management, p NativeProfile, db Database) error {
	if len(p.LegacyMACHooks) > 2 {
		return ErrNative
	}
	for _, known := range []struct{ kind, hook, helper string }{{ImportedKindPython, "/etc/systemd/system/interfaces-config.service.d/dc-management-mac.conf", "/usr/local/sbin/dc-management-only-mac.py"}, {ImportedKindShell, "/etc/systemd/system/interfaces-config.service.d/management-mac.conf", "/usr/local/sbin/set-management-mac"}} {
		hook, e := n.read(known.hook)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return ErrNative
		}
		qualified := false
		for _, imported := range p.LegacyMACHooks {
			if IsImportedPythonKind(imported.Kind) != IsImportedPythonKind(known.kind) {
				continue
			}
			if !hashMatches(ImportedMACUnit(imported.Kind), imported.HookSHA256) || imported.HelperSHA256 != ImportedHelperSHA256(imported.Kind) {
				return ErrNative
			}
			helper, e := n.read(known.helper)
			if e != nil || !hashMatches(hook, imported.HookSHA256) || !hashMatches(helper, imported.HelperSHA256) {
				return ErrNative
			}
			if desired.MAC != "" {
				return ErrNative
			}
			if _, err := n.read(macDropIn); !errors.Is(err, os.ErrNotExist) {
				return ErrConflict
			}
			if mac, err := n.bootMAC(); err != nil || mac != "" {
				return ErrConflict
			}
			current, e := managementFromDB(db, desired.MAC)
			declared := Management{Interface: "eth0", MAC: desired.MAC, Addresses: imported.Addresses}
			if e != nil || !managementEqual(current, desired) || !managementEqual(declared, desired) {
				return ErrNative
			}
			qualified = true
		}
		if !qualified {
			return ErrNative
		}
	}
	return nil
}
