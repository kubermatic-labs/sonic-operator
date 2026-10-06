// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRepeatedLatePathFailureDoesNotAccumulatePayloads(t *testing.T) {
	e, root := testEngine(t)
	b := certificateBundle(t)
	// A large valid first artifact preceded the later failing key destination.
	data := []byte(`{"padding":"` + strings.Repeat("x", 4<<20) + `"}`)
	b.Files = append([]File{{Slot: "PlatformJSON", Data: data, SHA256: Digest(data)}}, b.Files...)
	os.Symlink("/etc/passwd", filepath.Join(root, "etc/sonic-operator-agent/tls.key"))
	for range 4 {
		if _, err := e.Ensure(b, time.Now()); err == nil {
			t.Fatal("late symlink accepted")
		}
	}
	entries, _ := os.ReadDir(filepath.Join(root, "host/artifacts"))
	for _, entry := range entries {
		if entry.IsDir() && len(entry.Name()) == 32 {
			t.Fatal("failed staging accumulated a token payload directory")
		}
	}
}

func TestStagingPreservesRecoverySpaceReserve(t *testing.T) {
	e, _ := testEngine(t)
	e.AvailableSpace = func(string) (uint64, error) { return RecoveryReserveBytes, nil }
	if _, err := e.Ensure(testBundle(), time.Now()); err == nil {
		t.Fatal("staging consumed the recovery reserve")
	}
}
