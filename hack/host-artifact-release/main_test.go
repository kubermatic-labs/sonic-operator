// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ironcore-dev/sonic-operator/internal/releasebundle"
)

func TestReleaseAncestryFloor(t *testing.T) {
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("git", "-C", repo, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Skip("git checkout unavailable")
	}
	head := string(out[:len(out)-1])
	saved := releasebundle.Floors
	defer func() { releasebundle.Floors = saved }()
	releasebundle.Floors = []string{head}
	if err := releasebundle.CheckAncestry(repo, head); err != nil {
		t.Fatal(err)
	}
	if releasebundle.CheckAncestry(repo, strings.Repeat("0", 40)) == nil {
		t.Fatal("unknown source commit accepted")
	}
	if releasebundle.CheckAncestry(repo, "HEAD") == nil {
		t.Fatal("abbreviated source accepted")
	}
}

func TestReleaseRejectsUnknownBinaryAndBounds(t *testing.T) {
	p := filepath.Join(t.TempDir(), "binary")
	os.WriteFile(p, []byte("PRIVATE KEY must not appear in errors"), 0600)
	if _, err := releasebundle.InspectBinary("../..", p, "agent"); err == nil {
		t.Fatal("arbitrary bytes accepted")
	}
	f, _ := os.OpenFile(p, os.O_RDWR, 0600)
	f.Truncate((96 << 20) + 1)
	f.Close()
	if _, err := releasebundle.InspectBinary("../..", p, "agent"); err == nil {
		t.Fatal("oversize binary accepted")
	}
}
