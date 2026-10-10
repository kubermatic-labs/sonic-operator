// SPDX-License-Identifier: Apache-2.0
package releaseinfo

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

func TestDeclarationMarkersMatchConstants(t *testing.T) {
	full := append(append([]string(nil), capabilities[:]...), ImportedMACUnit)
	if declarationMarker(full) != Marker || declarationMarker(capabilities[:]) != LegacyMarker {
		t.Fatal("runtime markers differ from the declared constants")
	}
}

// Each executable must contain exactly the declaration it was built with, so
// release inspection reports the same capabilities the process declares.
func TestBuiltExecutablesCarryOneDeclaration(t *testing.T) {
	if testing.Short() {
		t.Skip("builds executables")
	}
	for _, tc := range []struct {
		tags string
		want []string
	}{
		{"", append(append([]string(nil), capabilities[:]...), ImportedMACUnit)},
		{"legacy_release", capabilities[:]},
	} {
		t.Run("tags="+tc.tags, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "declaration")
			args := []string{"build", "-trimpath", "-o", out}
			if tc.tags != "" {
				args = append(args, "-tags", tc.tags)
			}
			cmd := exec.Command("go", append(args, "./testdata/declaration")...)
			cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
			if b, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("build: %v: %s", err, b)
			}
			raw, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			caps, err := BinaryCapabilities(raw)
			if err != nil || !slices.Equal(caps, tc.want) {
				t.Fatalf("inspected %v, %v; want %v", caps, err, tc.want)
			}
			other := Marker
			if tc.tags == "" {
				other = LegacyMarker
			}
			if bytes.Contains(raw, []byte(other)) {
				t.Fatal("executable embeds a second declaration")
			}
		})
	}
}
