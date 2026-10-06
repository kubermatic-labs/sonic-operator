// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testEngine(t *testing.T) (*Engine, string) {
	t.Helper()
	root := t.TempDir()
	for _, p := range []string{"usr/local/sbin", "etc/sonic-operator-agent", "etc/systemd/system", "usr/share/sonic/device/test", "host/artifacts"} {
		if err := os.MkdirAll(filepath.Join(root, p), 0700); err != nil {
			t.Fatal(err)
		}
	}
	e, err := Open(root, "/host/artifacts", Policy{Baseline: "test-baseline", Platform: map[string]string{"PlatformJSON": "/usr/share/sonic/device/test/platform.json"}}, func() error { return nil }, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e, root
}
func TestDurableUpdateTimeoutAfterRestart(t *testing.T) {
	e, root := testEngine(t)
	b := testBundle()
	path := filepath.Join(root, "usr/share/sonic/device/test/platform.json")
	if err := os.WriteFile(path, []byte("old working file"), 0644); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	r, err := e.Ensure(b, now)
	if err != nil || r.Phase != "Staged" {
		t.Fatalf("stage: %+v %v", r, err)
	}
	if got, _ := os.ReadFile(path); string(got) != "old working file" {
		t.Fatal("agent request installed before external supervision")
	}
	if err := e.Tick(now); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, b.Files[0].Data) {
		t.Fatal("supervisor did not install")
	}
	e.Close()
	recovered, err := Open(root, "/host/artifacts", e.Policy, func() error { return nil }, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if err := recovered.Tick(now.Add(6 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != "old working file" {
		t.Fatalf("rollback: %s", got)
	}
	if _, err := recovered.Confirm(b, r.Token, now); err == nil {
		t.Fatal("stale confirmation accepted")
	}
}
func TestHealthAndOwnershipConfirmation(t *testing.T) {
	e, root := testEngine(t)
	b := testBundle()
	now := time.Now()
	r, err := e.Ensure(b, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Tick(now); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Confirm(b, "stale", now); err == nil {
		t.Fatal("accepted stale token")
	}
	other := b
	other.Generation++
	if _, err := e.Confirm(other, r.Token, now); err == nil {
		t.Fatal("accepted stale generation")
	}
	e.Health = func() error { return os.ErrInvalid }
	if _, err := e.Confirm(b, r.Token, now); err == nil {
		t.Fatal("confirmed unhealthy candidate")
	}
	e.Health = func() error { return nil }
	confirmed, err := e.Confirm(b, r.Token, now)
	if err != nil || !confirmed.Persistence || !confirmed.Runtime {
		t.Fatalf("confirmation: %+v %v", confirmed, err)
	}
	other = b
	other.Owner = "another-owner"
	if _, err := e.Ensure(other, now); err == nil {
		t.Fatal("stole ownership")
	}
	path := filepath.Join(root, "usr/share/sonic/device/test/platform.json")
	os.WriteFile(path, []byte("drift"), 0644)
	drift, err := e.Observe(b)
	if err != nil || drift.Configuration {
		t.Fatalf("missed drift %+v %v", drift, err)
	}
}
func TestSymlinksHashValidationAndSecretPrivacy(t *testing.T) {
	e, root := testEngine(t)
	b := testBundle()
	b.Files[0] = File{Slot: "AgentKey", SHA256: Digest([]byte("SECRET-KEY-MATERIAL")), Data: []byte("SECRET-KEY-MATERIAL")}
	// A lone private key is never a valid TLS candidate.
	if _, err := e.Ensure(b, time.Now()); err == nil {
		t.Fatal("accepted incomplete certificate bundle")
	}
	b = testBundle()
	path := filepath.Join(root, "usr/share/sonic/device/test/platform.json")
	if err := os.Symlink("/etc/passwd", path); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Ensure(b, time.Now()); err == nil {
		t.Fatal("accepted symlink destination")
	}
	os.Remove(path)
	b.Files[0].Data = []byte("bad hash")
	if _, err := e.Ensure(b, time.Now()); err == nil {
		t.Fatal("accepted candidate validation failure")
	}
}
func TestEqualAdoptionDoesNotRestart(t *testing.T) {
	e, root := testEngine(t)
	b := testBundle()
	os.WriteFile(filepath.Join(root, "usr/share/sonic/device/test/platform.json"), b.Files[0].Data, 0644)
	calls := 0
	e.Activate = func() error { calls++; return nil }
	r, err := e.Ensure(b, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	e.Tick(time.Now())
	if _, err := e.Confirm(b, r.Token, time.Now()); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("equal adoption restarted service")
	}
	journal, err := os.ReadFile(filepath.Join(root, "host/artifacts/journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(journal, b.Files[0].Data) {
		t.Fatal("journal contains source data")
	}
}

func TestNextBootActivationAndBootRestoration(t *testing.T) {
	e, root := testEngine(t)
	b := testBundle()
	b.Activation = "PlatformNextBoot"
	boot := "boot-one"
	e.BootID = func() string { return boot }
	now := time.Now()
	r, err := e.Ensure(b, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Tick(now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, "usr/share/sonic/device/test/platform.json")
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("platform changed before next boot")
	}
	boot = "boot-two"
	if err := e.Tick(now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Confirm(b, r.Token, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(p, []byte("image reset"), 0644)
	boot = "boot-three"
	if err := e.RestoreBoot(); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	if !bytes.Equal(got, b.Files[0].Data) {
		t.Fatal("confirmed content was not restored before native services")
	}
}

func TestStagingConflictPreservesLocalEdit(t *testing.T) {
	e, root := testEngine(t)
	b := testBundle()
	now := time.Now()
	p := filepath.Join(root, "usr/share/sonic/device/test/platform.json")
	os.WriteFile(p, []byte("old"), 0644)
	if _, err := e.Ensure(b, now); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(p, []byte("local-change"), 0644)
	if err := e.Tick(now); err == nil {
		t.Fatal("CAS conflict not reported")
	}
	got, _ := os.ReadFile(p)
	if string(got) != "local-change" {
		t.Fatal("CAS conflict overwrote local edit")
	}
}

func TestExpiredUninstalledStagePreservesLocalEdit(t *testing.T) {
	e, root := testEngine(t)
	b := testBundle()
	now := time.Now()
	p := filepath.Join(root, "usr/share/sonic/device/test/platform.json")
	os.WriteFile(p, []byte("old"), 0644)
	if _, err := e.Ensure(b, now); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(p, []byte("local-change"), 0644)
	if err := e.Tick(now.Add(6 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	if string(got) != "local-change" {
		t.Fatal("expiry overwrote local edit without any installation")
	}
}

func TestAgentExecutableCandidateValidation(t *testing.T) {
	e, _ := testEngine(t)
	b := testBundle()
	data := []byte("\x7fELFnot-an-executable")
	b.Files = []File{{Slot: "AgentBinary", Data: data, SHA256: Digest(data)}}
	if _, err := e.Ensure(b, time.Now()); err == nil {
		t.Fatal("accepted truncated ELF candidate")
	}
}

func TestInterruptedPartialInstallRollsBack(t *testing.T) {
	e, root := testEngine(t)
	b := testBundle()
	b.Files = append(b.Files, File{Slot: "HWSKUJSON", Data: []byte(`{"hwsku":1}`), SHA256: Digest([]byte(`{"hwsku":1}`))})
	e.Policy.Platform["HWSKUJSON"] = "/usr/share/sonic/device/test/hwsku.json"
	for _, name := range []string{"platform.json", "hwsku.json"} {
		os.WriteFile(filepath.Join(root, "usr/share/sonic/device/test", name), []byte("old"), 0644)
	}
	if _, err := e.Ensure(b, time.Now()); err != nil {
		t.Fatal(err)
	}
	j, err := e.load()
	if err != nil {
		t.Fatal(err)
	}
	j.Phase = "Installing"
	if err := e.save(j); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(root, "usr/share/sonic/device/test/platform.json"), b.Files[0].Data, 0644)
	e.Close()
	next, err := Open(root, "/host/artifacts", e.Policy, func() error { return nil }, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if err := next.Tick(time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"platform.json", "hwsku.json"} {
		got, _ := os.ReadFile(filepath.Join(root, "usr/share/sonic/device/test", name))
		if string(got) != "old" {
			t.Fatal("partial update survived recovery")
		}
	}
}

func TestCorruptActiveManifestCannotEscapeAllowlist(t *testing.T) {
	e, _ := testEngine(t)
	b := testBundle()
	now := time.Now()
	r, err := e.Ensure(b, now)
	if err != nil {
		t.Fatal(err)
	}
	e.Tick(now)
	if _, err := e.Confirm(b, r.Token, now); err != nil {
		t.Fatal(err)
	}
	j, err := e.load()
	if err != nil {
		t.Fatal(err)
	}
	j.Active.Files[0].Path = "etc/passwd"
	if err := e.save(j); err != nil {
		t.Fatal(err)
	}
	if _, err := e.load(); err == nil {
		t.Fatal("accepted corrupt active recovery destination")
	}
}

func TestDriftCorrectionRetainsLastConfirmedRecoveryContent(t *testing.T) {
	e, root := testEngine(t)
	b := testBundle()
	now := time.Now()
	r, err := e.Ensure(b, now)
	if err != nil {
		t.Fatal(err)
	}
	e.Tick(now)
	if _, err := e.Confirm(b, r.Token, now); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, "usr/share/sonic/device/test/platform.json")
	os.WriteFile(p, []byte("broken-drift"), 0644)
	if _, err := e.Ensure(b, now); err != nil {
		t.Fatal(err)
	}
	if err := e.Tick(now); err != nil {
		t.Fatal(err)
	}
	if err := e.Tick(now.Add(6 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	if !bytes.Equal(got, b.Files[0].Data) {
		t.Fatal("rollback restored drift instead of last confirmed version")
	}
}

func TestConfirmedUpdatePrunesUnreferencedPrivateContent(t *testing.T) {
	e, root := testEngine(t)
	b := testBundle()
	now := time.Now()
	first, err := e.Ensure(b, now)
	if err != nil {
		t.Fatal(err)
	}
	e.Tick(now)
	if _, err := e.Confirm(b, first.Token, now); err != nil {
		t.Fatal(err)
	}
	b.Generation++
	b.Files[0].Data = []byte(`{"ports":[1]}`)
	b.Files[0].SHA256 = Digest(b.Files[0].Data)
	second, err := e.Ensure(b, now)
	if err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(root, "host/artifacts", first.Token)
	if _, err := os.Stat(old); err != nil {
		t.Fatal("working content removed before health confirmation")
	}
	e.Tick(now)
	if _, err := e.Confirm(b, second.Token, now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("unreferenced prior content accumulated")
	}
}

func TestWallClockStepCannotExtendAgentRecovery(t *testing.T) {
	e, root := testEngine(t)
	clock := time.Hour
	e.Uptime = func() time.Duration { return clock }
	b := testBundle()
	now := time.Now()
	p := filepath.Join(root, "usr/share/sonic/device/test/platform.json")
	os.WriteFile(p, []byte("old"), 0644)
	if _, err := e.Ensure(b, now); err != nil {
		t.Fatal(err)
	}
	if err := e.Tick(now); err != nil {
		t.Fatal(err)
	}
	clock += 6 * time.Minute
	if err := e.Tick(now.Add(-24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	if string(got) != "old" {
		t.Fatal("wall-clock step extended the recovery deadline")
	}
}
