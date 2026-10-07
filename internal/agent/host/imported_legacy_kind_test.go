// SPDX-License-Identifier: Apache-2.0
package host

import (
	"testing"
)

// Hooks installed by earlier releases embed the legacy kind in their adapter
// unit, and that unit's hash is pinned in the installed immutable profile.
func TestLegacyImportedKindsKeepInstalledIdentity(t *testing.T) {
	for _, tc := range []struct{ legacy, current string }{
		{ImportedKindPythonLegacy, ImportedKindPython},
		{ImportedKindShellLegacy, ImportedKindShell},
	} {
		want := "[Service]\nExecStartPost=" + RecoveryBinaryFile + " --apply-imported-boot-mac=" + tc.legacy + "\n"
		if got := string(ImportedMACUnit(tc.legacy)); got != want {
			t.Fatalf("%s adapter changed: %q", tc.legacy, got)
		}
		lh, lp, err := ImportedMACPaths(tc.legacy)
		if err != nil {
			t.Fatal(err)
		}
		ch, cp, _ := ImportedMACPaths(tc.current)
		if lh != ch || lp != cp || ImportedHelperSHA256(tc.legacy) != ImportedHelperSHA256(tc.current) {
			t.Fatalf("%s does not share the helper identity of %s", tc.legacy, tc.current)
		}
		if IsImportedPythonKind(tc.legacy) != IsImportedPythonKind(tc.current) || IsImportedShellKind(tc.legacy) != IsImportedShellKind(tc.current) {
			t.Fatalf("%s maps to the wrong helper family", tc.legacy)
		}
	}
	if IsImportedPythonKind("dc-management") || IsImportedShellKind("management-mac") {
		t.Fatal("unknown kind accepted")
	}
}

func TestImportedIdentityHostnameRules(t *testing.T) {
	for _, tc := range []struct {
		kind, hostname string
		ok             bool
	}{
		{ImportedKindPython, "leaf-01", true},
		{ImportedKindPython, "", false},
		{ImportedKindPythonLegacy, "", true},
		{ImportedKindPythonLegacy, "leaf-01", true},
		{ImportedKindPythonLegacy, "Leaf_01", false},
		{ImportedKindShell, "", true},
		{ImportedKindShell, "leaf-01", false},
		{ImportedKindShellLegacy, "", true},
		{ImportedKindShellLegacy, "leaf-01", false},
	} {
		h := LegacyMACHook{Kind: tc.kind, Hostname: tc.hostname, HelperSHA256: ImportedHelperSHA256(tc.kind), HookSHA256: digestForTest(string(ImportedMACUnit(tc.kind))), Addresses: []Address{{Prefix: "10.0.0.21/24", Gateway: "10.0.0.1"}}}
		if err := validateImportedIdentity(h); (err == nil) != tc.ok {
			t.Errorf("%s/%q: got %v, want ok=%v", tc.kind, tc.hostname, err, tc.ok)
		}
	}
	// A current-name declaration cannot borrow the legacy adapter's hash.
	h := LegacyMACHook{Kind: ImportedKindShell, HelperSHA256: ImportedHelperSHA256(ImportedKindShell), HookSHA256: digestForTest(string(ImportedMACUnit(ImportedKindShellLegacy))), Addresses: []Address{{Prefix: "10.0.0.22/24", Gateway: "10.0.0.1"}}}
	if validateImportedIdentity(h) == nil {
		t.Fatal("adapter hash of another kind accepted")
	}
}
