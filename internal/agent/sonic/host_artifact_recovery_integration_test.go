//go:build integration

// SPDX-License-Identifier: Apache-2.0
package sonic

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ironcore-dev/sonic-operator/internal/agent/artifactstate"
	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
	"github.com/ironcore-dev/sonic-operator/internal/agent/releaseinfo"
	"github.com/ironcore-dev/sonic-operator/internal/artifact"
)

func combinedFixture(t *testing.T, f *hostDeviceFixture) host.RecoveryConfig {
	t.Helper()
	m := f.agent
	for _, pair := range []struct {
		field *string
		name  string
	}{{&m.journalDir, "vlan"}, {&m.breakoutJournalDir, "breakout"}, {&m.networkJournalDir, "network"}} {
		if *pair.field == "" {
			*pair.field = filepath.Join(f.dir, pair.name)
		}
		if err := os.MkdirAll(*pair.field, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(*pair.field, ".lock"), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	hostDir := filepath.Join(f.dir, "host/sonic-operator-host-journal")
	if err := os.MkdirAll(filepath.Dir(hostDir), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(f.dir, "journal"), hostDir); err != nil {
		t.Fatal(err)
	}
	m.hostJournalDir = hostDir
	m.artifactStateDir = filepath.Join(f.dir, "host/sonic-operator-artifacts")
	cfg := host.RecoveryConfig{JournalDir: hostDir, RedisAddress: "fixture", VLANJournalDir: m.journalDir, BreakoutJournalDir: m.breakoutJournalDir, NetworkJournalDir: m.networkJournalDir}
	wire := cfg
	wire.JournalDir = "/host/sonic-operator-host-journal"
	wire.VLANJournalDir, wire.BreakoutJournalDir, wire.NetworkJournalDir = "/vlan", "/breakout", "/network"
	raw, _ := json.Marshal(wire)
	if err := os.MkdirAll(filepath.Join(f.dir, "etc/sonic"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "etc/sonic/sonic-operator-host-recovery.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func combinedAgentBytes() []byte {
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
	return elf
}

// Use command assembly and its real two-level fencing; substitute the native
// process/image probes (no fixture executable is ever run). Native qualification
// and package/TLS authority retain their component lifecycle suites.
func combinedArtifactEngine(t *testing.T, root string, m *SonicAgent) *artifact.Engine {
	t.Helper()
	info := releaseinfo.Current()
	info.SourceCommit = strings.Repeat("a", 40)
	policy := artifact.Policy{Baseline: "test", AgentBuilds: map[string]artifact.ReleaseBuild{artifact.Digest(combinedAgentBytes()): info, artifact.Digest(append(combinedAgentBytes(), []byte("old")...)): info}}
	e, _, err := artifact.NewNativeEngine(root, "/host/sonic-operator-artifacts", policy, &ArtifactWriterFence{agent: m})
	if err != nil {
		t.Fatal(err)
	}
	e.Preflight = func(artifact.Bundle) error { return nil }
	e.PlanTLS = nil
	e.RecoveryInput = nil
	e.PlanPlatform = nil
	e.Finalize = nil
	e.RetirementCheck = nil
	e.PauseRuntime = false
	e.BootID = func() string { return "fixture-boot" }
	e.Uptime = nil
	e.ProcessID = nil
	e.Activate = func() error { return nil }
	e.Health = func() error { return nil }
	e.ActivateAgentRecovery = func() error { return nil }
	e.AgentRecoveryHealth = func() error {
		data, err := os.ReadFile(filepath.Join(root, "usr/local/sbin/sonic-operator-agent"))
		if err != nil || !bytes.Equal(data, append(combinedAgentBytes(), []byte("old")...)) {
			return os.ErrInvalid
		}
		return nil
	}
	return e
}

func stageCombinedArtifact(t *testing.T, root string, e *artifact.Engine) {
	t.Helper()
	p := filepath.Join(root, "usr/local/sbin/sonic-operator-agent")
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, append(combinedAgentBytes(), []byte("old")...), 0755); err != nil {
		t.Fatal(err)
	}
	elf := combinedAgentBytes()
	b := artifact.Bundle{Owner: "artifact", Target: "switch", Baseline: "test", Generation: 1, Files: []artifact.File{{Slot: "AgentBinary", Data: elf, SHA256: artifact.Digest(elf)}}}
	seedArtifactAgentTLS(t, root, &b)
	if _, err := e.Ensure(b, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestCombinedStandaloneRecoveryReleasesDualPending(t *testing.T) {
	f, _, _ := hostNetworkFixture(t)
	cfg := combinedFixture(t, f)
	he, err := host.NewRecoveryEngine(cfg, watchdogAssemblyFixture{SonicAgent: f.agent, native: f.native})
	if err != nil {
		t.Fatal(err)
	}
	q := hostRepairRequest()
	candidate := hostCandidate()
	q.Management = &candidate
	if _, err := he.Ensure(t.Context(), q, "first"); err != nil {
		t.Fatal(err)
	}
	hostFile := filepath.Join(cfg.JournalDir, "host.json")
	raw, err := os.ReadFile(hostFile)
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]json.RawMessage
	var pending map[string]json.RawMessage
	_ = json.Unmarshal(raw, &record)
	_ = json.Unmarshal(record["pending"], &pending)
	pending["rollbackRequired"] = json.RawMessage("true")
	record["pending"], _ = json.Marshal(pending)
	raw, _ = json.Marshal(record)
	if err := os.WriteFile(hostFile, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := he.RecoverExpired(t.Context()); err != nil {
		t.Fatal(err)
	}
	e := combinedArtifactEngine(t, f.dir, f.agent)
	stageCombinedArtifact(t, f.dir, e)
	now := time.Now()
	if err := e.Tick(now); err != nil {
		t.Fatal(err)
	}
	if err := e.Tick(now); err != nil {
		t.Fatal(err)
	}
	// Reproduce a historical dual-pending state using an actual authenticated
	// host record; no synthetic boolean can authorize this recovery.
	if err := os.WriteFile(hostFile, raw, 0600); err != nil {
		t.Fatal(err)
	}
	beforeDB, err := f.fullDB()
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := os.ReadFile(f.file("/etc/sonic/sonic-operator-host-profile.json"))
	e.Close()
	e = combinedArtifactEngine(t, f.dir, f.agent)
	defer e.Close()
	if err := e.Tick(now.Add(6 * time.Minute)); !errors.Is(err, artifactstate.ErrForeignPending) {
		t.Fatal("fresh supervisor did not identify foreign recovery", err)
	}
	if err := e.AgentRecoveryHealth(); err != nil {
		t.Fatal("fresh supervisor could not restore old agent", err)
	}
	afterHost, _ := os.ReadFile(hostFile)
	if !bytes.Equal(raw, afterHost) {
		t.Fatal("old-agent fallback rewrote host journal")
	}
	afterDB, _ := f.fullDB()
	afterProfile, _ := os.ReadFile(f.file("/etc/sonic/sonic-operator-host-profile.json"))
	if !bytes.Equal(beforeDB, afterDB) || !bytes.Equal(profile, afterProfile) {
		t.Fatal("agent fallback touched typed inputs")
	}
	if !errors.Is(artifactstate.CheckPending(f.agent.artifactStateDir), artifactstate.ErrReserved) {
		t.Fatal("premature reservation release")
	}
	changed := q
	changed.Revision = "2"
	if _, err := he.Ensure(t.Context(), changed, "new"); err == nil {
		t.Fatal("changed host intent borrowed recovery authority")
	}
	// Reopen through the exact standalone constructor after agent restoration.
	he, err = host.NewRecoveryEngine(cfg, watchdogAssemblyFixture{SonicAgent: f.agent, native: f.native})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := he.RecoverExpired(ctx); err != nil {
		t.Fatal("dual-pending recovery deadlocked", err)
	}
	if err := host.CheckPending(cfg.JournalDir); err != nil {
		t.Fatal(err)
	}
	if err := e.Tick(now.Add(7 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := artifactstate.CheckPending(f.agent.artifactStateDir); err != nil {
		t.Fatal("reservation never released", err)
	}
}

func TestCombinedArtifactPublicationWorker(t *testing.T) {
	root := os.Getenv("SONIC_COMBINED_PUBLICATION_WORKER")
	if root == "" {
		return
	}
	m := &SonicAgent{journalDir: filepath.Join(root, "vlan"), breakoutJournalDir: filepath.Join(root, "breakout"), networkJournalDir: filepath.Join(root, "network"), artifactStateDir: filepath.Join(root, "host/sonic-operator-artifacts")}
	e := combinedArtifactEngine(t, root, m)
	defer e.Close()
	_ = os.WriteFile(filepath.Join(root, "worker-ready"), nil, 0600)
	if err := e.Tick(time.Now()); !errors.Is(err, artifactstate.ErrForeignPending) {
		t.Fatalf("artifact must lose to published host Pending: %v", err)
	}
}

func TestCombinedPublicationInterprocessHostWins(t *testing.T) {
	f, _, _ := hostNetworkFixture(t)
	cfg := combinedFixture(t, f)
	e := combinedArtifactEngine(t, f.dir, f.agent)
	stageCombinedArtifact(t, f.dir, e)
	e.Close()
	he, err := host.NewRecoveryEngine(cfg, watchdogAssemblyFixture{SonicAgent: f.agent, native: f.native})
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	publication := f.native.BeforePublication
	once := false
	f.native.BeforePublication = func(ctx context.Context) error {
		if !once {
			once = true
			close(entered)
			<-release
		}
		return publication(ctx)
	}
	q := hostRepairRequest()
	candidate := hostCandidate()
	q.Management = &candidate
	done := make(chan error, 1)
	go func() { _, err := he.Ensure(t.Context(), q, "transport"); done <- err }()
	<-entered
	cmd := exec.Command(os.Args[0], "-test.run=^TestCombinedArtifactPublicationWorker$")
	cmd.Env = append(os.Environ(), "SONIC_COMBINED_PUBLICATION_WORKER="+f.dir)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		close(release)
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(filepath.Join(f.dir, "worker-ready")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			close(release)
			_ = cmd.Wait()
			t.Fatal("worker did not start", output.String())
		}
		time.Sleep(time.Millisecond)
	}
	if err := artifactstate.CheckPending(f.agent.artifactStateDir); err != nil {
		t.Fatal("artifact published while host held locks", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err, output.String())
	}
	if err := artifactstate.CheckPending(f.agent.artifactStateDir); err != nil {
		t.Fatal("losing artifact published", err)
	}
	raw, _ := os.ReadFile(filepath.Join(cfg.JournalDir, "host.json"))
	if !strings.Contains(string(raw), "observedActiveMAC") {
		t.Fatal("host observation lost")
	}
}

func TestCombinedReservationSurvivesSupervisorCrashBeforeHostPublication(t *testing.T) {
	f, _, _ := hostNetworkFixture(t)
	cfg := combinedFixture(t, f)
	e := combinedArtifactEngine(t, f.dir, f.agent)
	stageCombinedArtifact(t, f.dir, e)
	if err := e.Tick(time.Now()); err != nil {
		t.Fatal(err)
	}
	e.Close() // New agent/watchdog must consult the durable reservation.
	he, err := host.NewRecoveryEngine(cfg, watchdogAssemblyFixture{SonicAgent: f.agent, native: f.native})
	if err != nil {
		t.Fatal(err)
	}
	before, _ := f.fullDB()
	for _, m := range []host.Management{hostBefore(), hostCandidate()} {
		q := hostRepairRequest()
		q.Management = &m
		if _, err := he.Ensure(t.Context(), q, "new-agent"); !errors.Is(err, artifactstate.ErrReserved) {
			t.Fatalf("host published after reservation crash: %v", err)
		}
	}
	if _, err := os.Stat(filepath.Join(cfg.JournalDir, "host.json")); !os.IsNotExist(err) {
		t.Fatal("denied host published a claim", err)
	}
	after, _ := f.fullDB()
	if !bytes.Equal(before, after) {
		t.Fatal("denied host changed CONFIG_DB")
	}
	if err := os.WriteFile(filepath.Join(f.agent.artifactStateDir, "reservation.json"), []byte(`{"phase":"ForeignRecovery"}`), 0600); err != nil {
		t.Fatal(err)
	}
	called := false
	if err := f.agent.withHostRecordedRecovery(t.Context(), func(context.Context) error { called = true; return nil }); err == nil || called {
		t.Fatal("corrupt reservation authorized native replay")
	}
}
