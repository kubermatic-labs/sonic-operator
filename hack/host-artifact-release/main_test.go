// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ironcore-dev/sonic-operator/internal/agent/releaseinfo"
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
	i := releaseinfo.Current()
	i.SourceCommit = strings.TrimSpace(string(out))
	if err := releasebundle.CheckAncestry(repo, i); err != nil {
		t.Fatal(err)
	}
	i.SourceCommit = strings.Repeat("0", 40)
	if releasebundle.CheckAncestry(repo, i) == nil {
		t.Fatal("unknown source commit accepted")
	}
}

func TestReleaseRejectsUnknownBinaryAndBounds(t *testing.T) {
	p := filepath.Join(t.TempDir(), "binary")
	_ = os.WriteFile(p, []byte("PRIVATE KEY must not appear in errors"), 0600)
	if _, err := releasebundle.InspectBinary("../..", p, "agent"); err == nil {
		t.Fatal("arbitrary bytes accepted")
	}
	f, _ := os.OpenFile(p, os.O_RDWR, 0600)
	_ = f.Truncate((96 << 20) + 1)
	_ = f.Close()
	if _, err := releasebundle.InspectBinary("../..", p, "agent"); err == nil {
		t.Fatal("oversize binary accepted")
	}
}
