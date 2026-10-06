// SPDX-License-Identifier: Apache-2.0
package host

import (
	"os"
	"testing"
)

func TestImportedEqualLegacyMACHookCanBeAdoptedBeforeRetirement(t *testing.T) {
	n := &Native{ReadFile: func(path string) ([]byte, error) {
		switch path {
		case "/etc/systemd/system/interfaces-config.service.d/dc-management-mac.conf":
			return []byte("qualified-hook"), nil
		case "/usr/local/sbin/dc-management-only-mac.py":
			return []byte("qualified-helper"), nil
		}
		return nil, os.ErrNotExist
	}}
	m := validManagement()
	p := NativeProfile{LegacyMACHooks: []LegacyMACHook{{Kind: "dc-management-only", HookSHA256: digestForTest("qualified-hook"), HelperSHA256: digestForTest("qualified-helper"), MAC: m.MAC, Addresses: append([]Address{}, m.Addresses...)}}}
	db := Database{"MGMT_INTERFACE": {"eth0|10.0.0.11/24": {"gwaddr": "10.0.0.1"}}}
	if err := n.validateLegacyMACHooks(m, p, db); err != nil {
		t.Fatal("equal imported hook could not be adopted before retirement:", err)
	}
	m.MAC = "02:00:00:00:00:99"
	if n.validateLegacyMACHooks(m, p, db) == nil {
		t.Fatal("conflicting old boot MAC accepted")
	}
	m = validManagement()
	m.Addresses[0].Prefix = "10.0.0.99/24"
	if n.validateLegacyMACHooks(m, p, db) == nil {
		t.Fatal("legacy hardcoded management address ignored")
	}
}
