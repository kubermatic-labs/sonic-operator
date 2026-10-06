// SPDX-License-Identifier: Apache-2.0
package host

import (
	"os"
	"path/filepath"
	"testing"
)

func TestImportedGuardedMACHookAdoptsOnlyOmittedTypedMAC(t *testing.T) {
	helper, err := os.ReadFile(filepath.Join(os.Getenv("SONIC_TEST_MAC_FIXTURE_DIR"), "management-only-mac.py"))
	if err != nil {
		t.Skip("local captured helper fixture unavailable")
	}
	n := &Native{ReadFile: func(path string) ([]byte, error) {
		switch path {
		case "/etc/systemd/system/interfaces-config.service.d/dc-management-mac.conf":
			return ImportedMACUnit("management-mac-python"), nil
		case "/usr/local/sbin/dc-management-only-mac.py":
			return helper, nil
		}
		return nil, os.ErrNotExist
	}}
	m := validManagement()
	p := NativeProfile{LegacyMACHooks: []LegacyMACHook{{Kind: "management-mac-python", HookSHA256: digestForTest(string(ImportedMACUnit("management-mac-python"))), HelperSHA256: ImportedHelperSHA256("management-mac-python"), MAC: m.MAC, Addresses: append([]Address{}, m.Addresses...)}}}
	db := Database{"MGMT_INTERFACE": {"eth0|10.0.0.11/24": {"gwaddr": "10.0.0.1"}}}
	if n.validateLegacyMACHooks(m, p, db) == nil {
		t.Fatal("mixed typed and retained ownership accepted")
	}
	m.MAC = ""
	if err := n.validateLegacyMACHooks(m, p, db); err != nil {
		t.Fatal("equal guarded hook could not be adopted with MAC omitted:", err)
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
