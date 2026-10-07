// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func syntheticWheel(t *testing.T, extra string) ([]byte, []File) {
	return syntheticWheelSources(t, extra, "")
}

func syntheticWheelSources(t *testing.T, extra, suffix string) ([]byte, []File) {
	t.Helper()
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	var files []File
	entries := map[string][]byte{}
	for slot, name := range platformModules {
		data := []byte("# " + slot + suffix + "\n")
		w, err := z.Create("sonic_platform/" + name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(data)
		entries["sonic_platform/"+name] = data
		files = append(files, File{Slot: slot, Data: data, SHA256: Digest(data)})
	}
	for name, data := range map[string]string{"METADATA": "Metadata-Version: 2.1\nName: sonic-platform\nVersion: 1.0\n", "WHEEL": "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n", "top_level.txt": "sonic_platform\n"} {
		w, _ := z.Create("sonic_platform-1.0.dist-info/" + name)
		_, _ = w.Write([]byte(data))
		entries["sonic_platform-1.0.dist-info/"+name] = []byte(data)
	}
	var record bytes.Buffer
	csvWriter := csv.NewWriter(&record)
	for name, data := range entries {
		sum := sha256.Sum256(data)
		_ = csvWriter.Write([]string{name, "sha256=" + base64.RawURLEncoding.EncodeToString(sum[:]), strconv.Itoa(len(data))})
	}
	_ = csvWriter.Write([]string{"sonic_platform-1.0.dist-info/RECORD", "", ""})
	csvWriter.Flush()
	w, _ := z.Create("sonic_platform-1.0.dist-info/RECORD")
	_, _ = w.Write(record.Bytes())
	if extra != "" {
		w, _ := z.Create(extra)
		_, _ = w.Write([]byte("unsafe"))
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), files
}
func TestWheelQualification(t *testing.T) {
	data, modules := syntheticWheel(t, "")
	b := testBundle()
	b.Files = append(modules, File{Slot: "PlatformWheel", Data: data, SHA256: Digest(data)})
	if err := validatePlatformWheel(b.Files); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../../etc/passwd", "sonic_platform/hooks.pth", "sonic_platform-1.0.dist-info/entry_points.txt", "other_package/__init__.py"} {
		bad, _ := syntheticWheel(t, name)
		b.Files[len(b.Files)-1].Data = bad
		if err := validatePlatformWheel(b.Files); err == nil {
			t.Fatalf("unsafe wheel member accepted: %s", name)
		}
	}
	b.Files[len(b.Files)-1].Data = data
	b.Files[0].Data = []byte("independent drift")
	b.Files[0].SHA256 = Digest(b.Files[0].Data)
	if err := validatePlatformWheel(b.Files); err == nil {
		t.Fatal("wheel and independently declared modules disagreed")
	}
}

func TestWheelRejectsUnconfinedRecord(t *testing.T) {
	data, _ := syntheticWheel(t, "")
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	out := zip.NewWriter(&buf)
	for _, f := range z.File {
		r, _ := f.Open()
		content, _ := io.ReadAll(r)
		_ = r.Close()
		if strings.HasSuffix(f.Name, "/RECORD") {
			content = []byte("../../../../etc/passwd,,\n")
		}
		w, _ := out.Create(f.Name)
		_, _ = w.Write(content)
	}
	_ = out.Close()
	if _, err := wheelMembers(buf.Bytes()); err == nil {
		t.Fatal("wheel RECORD permitted an unconfined uninstall destination")
	}
}
func TestNativeWheelActivationUsesExistingContainerAndProtectedRollback(t *testing.T) {
	e, root := testEngine(t)
	n := &Native{Engine: e}
	var calls []string
	e.Policy.ConsumerSHA256 = map[string]string{}
	for name := range platformConsumers {
		e.Policy.ConsumerSHA256[name] = strings.Repeat("a", 64)
	}
	n.Run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name == "/usr/bin/sha256sum" || strings.Contains(strings.Join(args, " "), " sha256sum ") {
			return []byte(strings.Repeat("a", 64) + "  file\n"), nil
		}
		if strings.Contains(strings.Join(args, " "), "--property=SubState") {
			return []byte("exited"), nil
		}
		if strings.Contains(strings.Join(args, " "), "supervisorctl status") {
			return []byte(args[len(args)-1] + " EXITED done"), nil
		}
		if strings.Contains(strings.Join(args, " "), "supervisorctl pid") {
			return []byte("0"), nil
		}
		return []byte("true"), nil
	}
	j := &journal{Version: 1, Owner: "owner", Target: "target", Baseline: e.Policy.Baseline, Generation: 1, Identity: Digest([]byte("identity")), Token: strings.Repeat("a", 32), Phase: "Activating", Files: []savedFile{{Slot: "PlatformWheel", Mode: 0644, Path: "usr/share/sonic/device/x86_64-dell_z9100_c2538-r0/sonic_platform-1.0-py3-none-any.whl"}}}
	data, _ := syntheticWheel(t, "")
	members, _ := wheelMembers(data)
	e.Policy.Platform["PlatformWheel"] = coreWheel
	n.RunInput = func(_ context.Context, input []byte, _ string, _ ...string) ([]byte, error) {
		var packet struct{ Target, Mode string }
		_ = json.Unmarshal(input, &packet)
		calls = append(calls, "package "+packet.Mode+" "+packet.Target)
		if packet.Mode == "snapshot" {
			return json.Marshal(candidatePackage(members, Digest(data)))
		}
		return []byte(`{"ok":true}`), nil
	}
	j.Files[0].Hash = Digest(data)
	j.Files[0].PreviousHash = Digest(data)
	p := filepath.Join(root, j.Files[0].Path)
	_ = os.MkdirAll(filepath.Dir(p), 0700)
	_ = os.WriteFile(p, data, 0644)
	if err := e.atomic(e.storage(j, "old", 0), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := e.atomic(e.storage(j, "new", 0), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := n.activatePlatform(j); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(calls, "\n")
	if !strings.Contains(joined, "package apply host") || !strings.Contains(joined, "package apply pmon") || strings.Contains(joined, "pip install") || !strings.Contains(joined, "supervisorctl restart xcvrd") || strings.Contains(joined, "docker rm") {
		t.Fatalf("unsafe or missing activation: %s", joined)
	}
	calls = nil
	j.Phase = "RollingBack"
	j.Files = append(j.Files, savedFile{Slot: "SAIProfile", Hash: strings.Repeat("b", 64), ObservedHash: strings.Repeat("a", 64), ObservedExisted: true, Mode: 0644, ObservedMode: 0644})
	if err := n.activatePlatform(j); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(calls, "\n"), "restart swss.service syncd.service") {
		t.Fatal("rollback did not regenerate SAI consumers")
	}
}
func TestBootActivationDefersUntilSupervisorReady(t *testing.T) {
	e, _ := testEngine(t)
	e.DeferActivation = true
	calls := 0
	e.Activate = func() error { calls++; return nil }
	b := testBundle()
	now := time.Now()
	r, err := e.Ensure(b, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Tick(now); err != nil {
		t.Fatal(err)
	}
	j, _ := e.load()
	if calls != 0 || j.Phase != "Activating" {
		t.Fatalf("activation happened before ready: %s %d", j.Phase, calls)
	}
	if _, err := e.Confirm(b, r.Token, now); err == nil {
		t.Fatal("unactivated candidate confirmed")
	}
	if err := e.Tick(now); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal(fmt.Sprint("activation calls ", calls))
	}
	if _, err := e.Confirm(b, r.Token, now); err != nil {
		t.Fatal(err)
	}
}

func TestPackageAndDaemonHealthUsesActualConsumers(t *testing.T) {
	data, _ := syntheticWheel(t, "")
	members, err := wheelMembers(data)
	if err != nil {
		t.Fatal(err)
	}
	hashes := map[string]string{}
	for name, content := range members {
		if !strings.HasSuffix(name, "/RECORD") {
			hashes[name] = Digest(content)
		}
	}
	raw, _ := json.Marshal(map[string]any{"root": "/usr/local/lib/python3.11/dist-packages", "files": hashes})
	if err := verifyPackageHashes(raw, "/usr/local/lib/python3.11/dist-packages", members); err != nil {
		t.Fatal(err)
	}
	hashes["sonic_platform/chassis.py"] = Digest([]byte("drift"))
	raw, _ = json.Marshal(map[string]any{"root": "/usr/local/lib/python3.11/dist-packages", "files": hashes})
	if err := verifyPackageHashes(raw, "/usr/local/lib/python3.11/dist-packages", members); err == nil {
		t.Fatal("ignored pmon installed module drift")
	}
	if err := verifyDaemonStatus([]byte("xcvrd RUNNING pid 43\npsud RUNNING pid 44\n"), []string{"xcvrd", "psud"}); err != nil {
		t.Fatal(err)
	}
	if err := verifyDaemonStatus([]byte("xcvrd EXITED failure\npsud RUNNING pid 44\n"), []string{"xcvrd", "psud"}); err == nil {
		t.Fatal("accepted failed persistent consumer")
	}
}

func TestInstalledPackageRecordSafetyProbe(t *testing.T) {
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	metadata := filepath.Join(root, "sonic_platform-1.0.dist-info")
	_ = os.MkdirAll(metadata, 0700)
	_ = os.WriteFile(filepath.Join(metadata, "METADATA"), []byte("Name: sonic-platform\nVersion: 1.0\n"), 0644)
	run := func() error {
		cmd := exec.Command("python3", "-B", "-c", packageSafetyProbe, root)
		cmd.Env = append(os.Environ(), "PYTHONPATH="+root)
		return cmd.Run()
	}
	_ = os.WriteFile(filepath.Join(metadata, "RECORD"), []byte("sonic_platform/chassis.py,,\n"), 0644)
	if err := run(); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(metadata, "RECORD"), []byte("../../../../etc/passwd,,\n"), 0644)
	if err := run(); err == nil {
		t.Fatal("pip uninstall could escape approved package files")
	}
}

func TestRuntimeOnlyDriftTriggersNativeActivation(t *testing.T) {
	e, _ := testEngine(t)
	b := testBundle()
	now := time.Now()
	r, err := e.Ensure(b, now)
	if err != nil {
		t.Fatal(err)
	}
	_ = e.Tick(now)
	if _, err := e.Confirm(b, r.Token, now); err != nil {
		t.Fatal(err)
	}
	e.Health = func() error { return os.ErrInvalid }
	calls := 0
	e.Activate = func() error { calls++; e.Health = func() error { return nil }; return nil }
	r, err = e.Ensure(b, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Tick(now); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("runtime package drift was not enforced")
	}
	if _, err := e.Confirm(b, r.Token, now); err != nil {
		t.Fatal(err)
	}
}

func TestSAIProfileCannotSelectArbitraryRuntimeFile(t *testing.T) {
	if err := validateCandidates([]File{{Slot: "SAIProfile", Data: []byte("SAI_INIT_CONFIG_FILE=/etc/passwd\nSAI_NUM_ECMP_MEMBERS=64\n")}}); err == nil {
		t.Fatal("arbitrary SAI input path accepted")
	}
}

func TestNativeConsumerFingerprintsFailClosed(t *testing.T) {
	e, _ := testEngine(t)
	n := &Native{Engine: e, Run: func(context.Context, string, ...string) ([]byte, error) {
		return []byte(strings.Repeat("a", 64) + "  file\n"), nil
	}}
	if err := n.consumerBaseline(context.Background()); err == nil {
		t.Fatal("missing consumer qualification accepted")
	}
	e.Policy.ConsumerSHA256 = map[string]string{}
	for name := range platformConsumers {
		e.Policy.ConsumerSHA256[name] = strings.Repeat("a", 64)
	}
	if err := n.consumerBaseline(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.Policy.ConsumerSHA256["pmon-init"] = strings.Repeat("b", 64)
	if err := n.consumerBaseline(context.Background()); err == nil {
		t.Fatal("changed native generator accepted")
	}
}

func TestRuntimeSAISelectionMustUseGeneratedInput(t *testing.T) {
	if err := verifySAICommand([]byte("/usr/bin/dsserve\x00/usr/bin/syncd\x00--diag\x00-p\x00/etc/sai.d/sai.profile\x00")); err != nil {
		t.Fatal(err)
	}
	if err := verifySAICommand([]byte("/usr/bin/syncd\x00-p\x00/tmp/sai.profile\x00")); err == nil {
		t.Fatal("shadow runtime SAI profile accepted")
	}
}

func TestPlatformProgrammingRejectsWarmBootReuse(t *testing.T) {
	e, root := testEngine(t)
	n := &Native{Engine: e}
	_ = os.MkdirAll(filepath.Join(root, "proc"), 0700)
	p := filepath.Join(root, "proc/cmdline")
	_ = os.WriteFile(p, []byte("quiet SONIC_BOOT_TYPE=fast"), 0644)
	if err := n.ColdPlatformBoot(); err == nil {
		t.Fatal("fast-boot ASIC reuse accepted for changed platform input")
	}
	_ = os.WriteFile(p, []byte("quiet"), 0644)
	if err := n.ColdPlatformBoot(); err != nil {
		t.Fatal(err)
	}
}

func TestAgentRotationDoesNotRestartUnchangedPlatform(t *testing.T) {
	e, _ := testEngine(t)
	calls := 0
	n := &Native{Engine: e, Run: func(context.Context, string, ...string) ([]byte, error) { calls++; return []byte("true"), nil }}
	j := &journal{Phase: "Activating", Activation: "AgentRestart", Files: []savedFile{{Slot: "PlatformWheel", Path: strings.TrimPrefix(coreWheel, "/"), Hash: strings.Repeat("a", 64), ObservedHash: strings.Repeat("a", 64), ObservedExisted: true, Mode: 0644, ObservedMode: 0644}}}
	if err := n.activatePlatform(j); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("agent-only update touched platform daemons")
	}
}
