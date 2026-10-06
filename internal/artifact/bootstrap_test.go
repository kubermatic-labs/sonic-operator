// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func bootstrapFixture(t *testing.T) (Bundle, string) {
	t.Helper()
	b := testBundle()
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "etc/sonic"), 0700)
	image := []byte("image")
	os.WriteFile(filepath.Join(root, "etc/sonic/sonic_version.yml"), image, 0644)
	policy, _ := json.Marshal(Policy{Baseline: b.Baseline, ImageSHA256: Digest(image)})
	// Structurally valid ELF input; the injected activator never executes it.
	elf := make([]byte, 120)
	copy(elf, []byte{'\x7f', 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(elf[16:], 2)
	binary.LittleEndian.PutUint16(elf[18:], 62)
	binary.LittleEndian.PutUint32(elf[20:], 1)
	binary.LittleEndian.PutUint64(elf[32:], 64)
	binary.LittleEndian.PutUint16(elf[52:], 64)
	binary.LittleEndian.PutUint16(elf[54:], 56)
	binary.LittleEndian.PutUint16(elf[56:], 1)
	binary.LittleEndian.PutUint32(elf[64:], 1)
	b.Bootstrap = &Bootstrap{Supervisor: elf, SupervisorSHA256: Digest(elf), Policy: policy, PolicySHA256: Digest(policy), UnitSHA256: Digest([]byte(SupervisorUnit))}
	return b, root
}
func TestIndependentBootstrapEnforcesImmutableClusterInputs(t *testing.T) {
	b, root := bootstrapFixture(t)
	calls := 0
	activate := func(context.Context) error { calls++; return nil }
	if err := EnsureBootstrap(context.Background(), root, b, activate); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "usr/local/sbin/sonic-operator-artifact-supervisor")
	got, _ := os.ReadFile(path)
	if Digest(got) != b.Bootstrap.SupervisorSHA256 {
		t.Fatal("bootstrap binary not installed")
	}
	if err := EnsureBootstrap(context.Background(), root, b, activate); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("equal bootstrap restarted")
	}
	os.WriteFile(path, []byte("drift"), 0755)
	if err := EnsureBootstrap(context.Background(), root, b, activate); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(path)
	if Digest(got) != b.Bootstrap.SupervisorSHA256 || calls != 2 {
		t.Fatal("bootstrap drift not repaired by independent agent")
	}
	other := b
	other.Owner = "other-owner"
	if err := EnsureBootstrap(context.Background(), root, other, activate); err == nil {
		t.Fatal("bootstrap ownership stolen")
	}
	changed := *b.Bootstrap
	changed.UnitSHA256 = Digest([]byte("other unit"))
	b.Bootstrap = &changed
	if err := EnsureBootstrap(context.Background(), root, b, activate); err == nil {
		t.Fatal("immutable bootstrap identity changed")
	}
}
func TestBootstrapRejectsUnconfinedPolicy(t *testing.T) {
	b, root := bootstrapFixture(t)
	policy, _ := json.Marshal(Policy{Baseline: b.Baseline, ImageSHA256: Digest([]byte("image")), Platform: map[string]string{"PlatformJSON": "/etc/passwd"}})
	b.Bootstrap.Policy = policy
	b.Bootstrap.PolicySHA256 = Digest(policy)
	if err := EnsureBootstrap(context.Background(), root, b, func(context.Context) error { return nil }); err == nil {
		t.Fatal("bootstrap policy allowed arbitrary destination")
	}
}

func TestInterruptedBootstrapResumesSameDeclaredIdentity(t *testing.T) {
	b, root := bootstrapFixture(t)
	if err := EnsureBootstrap(context.Background(), root, b, func(context.Context) error { return os.ErrInvalid }); err == nil {
		t.Fatal("failed bootstrap activation claimed success")
	}
	if err := EnsureBootstrap(context.Background(), root, b, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "host/sonic-operator-artifact-bootstrap/owner.json"))
	if err != nil {
		t.Fatal(err)
	}
	var record bootstrapRecord
	if err := json.Unmarshal(raw, &record); err != nil || record.Pending {
		t.Fatal("bootstrap did not complete durable recovery")
	}
}

func TestBootstrapRuntimeCannotSpoofConsumerReadback(t *testing.T) {
	policy := Policy{ImageSHA256: coreImageSHA, Runtime: map[string]RuntimeFile{"PlatformJSON": {Container: "pmon", Path: "/usr/share/sonic/device/unrelated/platform.json"}}}
	if err := validateBootstrapPolicy(policy); err == nil {
		t.Fatal("bootstrap policy could redirect health checks to an unrelated file")
	}
}
