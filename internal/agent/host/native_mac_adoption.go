// SPDX-License-Identifier: Apache-2.0
package host

import (
	"errors"
	"os"
)

// LegacyMACHook is an imported artifact identity, not a remote executable path.
// The artifact owner retains the original hook until the equivalent typed boot
// input has been independently verified, then retires its old activation path.
type LegacyMACHook struct {
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
	for _, known := range []struct{ kind, hook, helper string }{{"dc-management-only", "/etc/systemd/system/interfaces-config.service.d/dc-management-mac.conf", "/usr/local/sbin/dc-management-only-mac.py"}, {"set-management", "/etc/systemd/system/interfaces-config.service.d/management-mac.conf", "/usr/local/sbin/set-management-mac"}} {
		hook, e := n.read(known.hook)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return ErrNative
		}
		qualified := false
		for _, imported := range p.LegacyMACHooks {
			if imported.Kind != known.kind {
				continue
			}
			helper, e := n.read(known.helper)
			if e != nil || !hashMatches(hook, imported.HookSHA256) || !hashMatches(helper, imported.HelperSHA256) {
				return ErrNative
			}
			if desired.MAC != "" && desired.MAC != imported.MAC {
				return ErrNative
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
