// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNativeBaselineAndRuntimeAllowlist(t *testing.T) {
	e, root := testEngine(t)
	os.MkdirAll(filepath.Join(root, "etc/sonic"), 0700)
	os.WriteFile(filepath.Join(root, "etc/sonic/sonic_version.yml"), []byte("image-1"), 0644)
	e.Policy.ImageSHA256 = Digest([]byte("image-1"))
	e.Policy.Runtime = map[string]RuntimeFile{"PlatformJSON": {Container: "syncd", Path: "/usr/share/sonic/platform/platform.json"}}
	n := &Native{Engine: e}
	b := testBundle()
	b.Activation = "PlatformNextBoot"
	if err := n.Baseline(); err != nil {
		t.Fatal(err)
	}
	if err := n.Preflight(b); err == nil {
		t.Fatal("unowned bootstrap accepted")
	}
	e.Policy.Runtime["PlatformJSON"] = RuntimeFile{Container: "syncd; reboot", Path: "/etc/passwd"}
	if runtimePath("PlatformJSON", e.Policy.Runtime["PlatformJSON"]) {
		t.Fatal("accepted arbitrary runtime probe")
	}
	e.Policy.Runtime["PlatformJSON"] = RuntimeFile{Container: "syncd", Path: "/usr/share/sonic/platform/platform.json"}
	e.Policy.ImageSHA256 = Digest([]byte("other-image"))
	if err := n.Baseline(); err == nil {
		t.Fatal("accepted different image baseline")
	}
}
