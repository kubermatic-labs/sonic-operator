// SPDX-License-Identifier: Apache-2.0
package releasebundle

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/ironcore-dev/sonic-operator/internal/artifact"
)

func TestSourceBinaryReplacementRetainsInspectedBytes(t *testing.T) {
	fixture := os.Getenv("SONIC_TEST_RELEASE_AGENT")
	if fixture == "" {
		t.Skip("set SONIC_TEST_RELEASE_AGENT to an actual clean floor-compatible Linux release agent")
	}
	original, err := ReadBounded(fixture, 96<<20)
	if err != nil {
		t.Fatal(err)
	}
	git, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "agent")
	replacement := filepath.Join(dir, "replacement")
	if err := os.WriteFile(path, original, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(replacement, append(append([]byte(nil), original...), []byte("concurrent-rebuild")...), 0755); err != nil {
		t.Fatal(err)
	}
	// InspectBinary checks ancestry after reading ELF/build metadata. Replace the
	// path at precisely that boundary, without altering the inspected byte buffer.
	wrapper := []byte("#!/bin/sh\nif [ \"$3\" = merge-base ] && [ -f \"$RELEASE_TEST_REPLACEMENT\" ]; then\n /bin/mv \"$RELEASE_TEST_REPLACEMENT\" \"$RELEASE_TEST_TARGET\" || exit 1\nfi\nexec \"$RELEASE_TEST_GIT\" \"$@\"\n")
	if err := os.WriteFile(filepath.Join(dir, "git"), wrapper, 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RELEASE_TEST_GIT", git)
	t.Setenv("RELEASE_TEST_TARGET", path)
	t.Setenv("RELEASE_TEST_REPLACEMENT", replacement)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	build, payload, err := readInspectedBinary(repo, path, "agent")
	if err != nil {
		t.Fatal(err)
	}
	current, err := ReadBounded(path, 96<<20)
	if err != nil || artifact.Digest(current) == artifact.Digest(original) {
		t.Fatal("replacement boundary did not execute", err)
	}
	source, objects, err := ChunkSource("AgentBinary", payload)
	if err != nil {
		t.Fatal(err)
	}
	if source.SHA256 != build.SHA256 || int64(source.Size) != build.Size || source.SHA256 != artifact.Digest(original) {
		t.Fatal("published payload changed after inspection")
	}
	if err := ValidateChunks(source, objects); err != nil {
		t.Fatal(err)
	}
}
