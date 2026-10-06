// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ironcore-dev/sonic-operator/internal/agent/artifactstate"
)

// Native commands which need a switch/process namespace are represented by a
// fixture facade. Package snapshots, replacement and restoration execute the
// production Python transaction against real files in isolated directories.
type generationFixture struct {
	t                                           *testing.T
	e                                           *Engine
	n                                           *Native
	root                                        string
	bundle                                      Bundle
	policy                                      Policy
	boot                                        string
	ready                                       bool
	configured, loaded                          string
	incarnation                                 string
	finalHealthPending                          bool
	packageCalls, daemonRestarts, agentRestarts int
	failSnapshot                                string
	interruptApply                              bool
	holdRepair                                  bool
}

func newGenerationFixture(t *testing.T) *generationFixture {
	e, root, b := retirementFixture(t)
	root, _ = filepath.EvalSymlinks(root)
	b.RetireLegacyHook = false
	b.Activation = "PlatformNextBoot"
	seed, _ := bootstrapFixture(t)
	binary := seed.Bootstrap.Supervisor
	b.Files = append(b.Files, File{Slot: "AgentBinary", SHA256: Digest(binary), Data: binary})
	os.WriteFile(filepath.Join(root, "usr/local/sbin/sonic-operator-agent"), binary, 0755)
	completeAgentFixture(t, e, &b)
	e.Policy.AgentBuilds[Digest(append(append([]byte(nil), binary...), []byte("next-agent")...))] = testReleaseBuild()
	e.Policy.ConsumerSHA256 = map[string]string{}
	for name := range platformConsumers {
		e.Policy.ConsumerSHA256[name] = strings.Repeat("a", 64)
	}
	e.Policy.Runtime = map[string]RuntimeFile{"PlatformJSON": {Container: "pmon", Path: "/usr/share/sonic/platform/platform.json"}, "HWSKUJSON": {Container: "syncd", Path: "/usr/share/sonic/hwsku/hwsku.json"}, "PortConfig": {Container: "syncd", Path: "/usr/share/sonic/hwsku/port_config.ini"}, "SAIProfile": {Container: "syncd", Path: "/usr/share/sonic/hwsku/sai.profile"}, "BroadcomConfig": {Container: "syncd", Path: "/usr/share/sonic/hwsku/dc-flex-with-sfp.config.bcm"}}
	var wheel File
	for _, f := range b.Files {
		if f.Slot == "PlatformWheel" {
			wheel = f
		}
	}
	members, err := wheelMembers(wheel.Data)
	if err != nil {
		t.Fatal(err)
	}
	h := &generationFixture{t: t, e: e, root: root, bundle: b, policy: e.Policy, boot: "boot-0", ready: true, incarnation: "container-0"}
	for _, target := range []string{"host", "pmon"} {
		for name, entry := range candidatePackage(members, wheel.SHA256, target).Entries {
			p := filepath.Join(h.packageRoot(target), name)
			os.MkdirAll(filepath.Dir(p), 0700)
			os.WriteFile(p, entry.Data, os.FileMode(entry.Mode))
		}
	}
	h.wire()
	return h
}
func (h *generationFixture) packageRoot(target string) string {
	if target == "host" {
		return filepath.Join(h.root, "usr/local/lib/python3.13/dist-packages")
	}
	return filepath.Join(h.root, "pmon/lib")
}
func (h *generationFixture) wire() {
	h.n = &Native{Engine: h.e, Run: h.run, RunInput: h.input}
	h.e.BootID = func() string { return h.boot }
	h.e.DeferActivation = true
	h.e.PlanPlatform = h.n.PlanPlatform
	h.e.Activate = h.n.Activate
	h.e.RestorePackages = h.n.RestorePackages
	h.e.BootRuntimeRestore = h.n.RestoreBootRuntime
	h.e.Health = func() error {
		j, err := h.e.load()
		if err != nil {
			return err
		}
		if h.finalHealthPending && (j.Phase == "ActivatingBoot" || j.Phase == "RecoveringBoot") {
			return ErrActivationPending
		}
		if j.Phase == "ActivatingBoot" || j.Phase == "RecoveringBoot" {
			copy := *j
			copy.Files = j.Active.Files
			j = &copy
		}
		return h.n.platformHealth(context.Background(), j)
	}
}
func (h *generationFixture) reopen() {
	h.e.Close()
	var err error
	h.e, err = Open(h.root, "/host/artifacts", h.policy, func() error { return nil }, func() error { return nil })
	if err != nil {
		h.t.Fatal(err)
	}
	h.wire()
}
func (h *generationFixture) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	text := strings.Join(args, " ")
	if strings.Contains(text, "{{.Id}}") {
		return []byte(h.incarnation), nil
	}
	for _, arg := range args {
		if arg == bootRuntimeProbe {
			return []byte(Digest([]byte(h.configured + "\x00" + h.loaded))), nil
		}
	}
	if strings.Contains(text, "--property=SubState") {
		if !h.ready {
			return []byte("start"), nil
		}
		return []byte("exited"), nil
	}
	if strings.Contains(text, " inspect ") || len(args) > 0 && args[0] == "inspect" {
		return []byte("true"), nil
	}
	if strings.Contains(text, "supervisorctl status") {
		var out strings.Builder
		at := 0
		for i, arg := range args {
			if arg == "status" {
				at = i + 1
				break
			}
		}
		for _, daemon := range args[at:] {
			state := "RUNNING"
			if daemon == "dependent-startup" || daemon == "start" {
				state = "EXITED"
			}
			fmt.Fprintf(&out, "%s %s fixture\n", daemon, state)
		}
		return []byte(out.String()), nil
	}
	if strings.Contains(text, "supervisorctl pid") {
		return []byte("42"), nil
	}
	if strings.Contains(text, "supervisorctl restart") {
		h.daemonRestarts++
		h.loaded = h.configured
		return []byte("ok"), nil
	}
	if name == "/usr/bin/systemctl" && strings.Contains(text, "restart sonic-operator-agent") {
		h.agentRestarts++
	}
	for _, arg := range args {
		if arg == packageHashProbe {
			target := "host"
			canonical := "/usr/local/lib/python3.13/dist-packages"
			if len(args) > 1 && args[0] == "exec" {
				target = "pmon"
				canonical = "/usr/local/lib/python3.11/dist-packages"
			}
			cmd := exec.CommandContext(ctx, "python3", "-I", "-S", "-B", "-c", packageHashProbe, h.packageRoot(target))
			raw, err := cmd.Output()
			if err != nil {
				return nil, err
			}
			var value map[string]any
			json.Unmarshal(raw, &value)
			value["root"] = canonical
			return json.Marshal(value)
		}
		if arg == launcherProofProbe {
			expected := args[len(args)-3]
			if h.loaded == "" || h.loaded != expected {
				return nil, fmt.Errorf("fixture process has another launch identity")
			}
			return []byte("verified"), nil
		}
	}
	if strings.Contains(text, "sha256sum") || name == "/usr/bin/sha256sum" {
		p := args[len(args)-1]
		for slot, runtime := range h.policy.Runtime {
			if runtime.Path == p || slot == "SAIProfile" && p == "/etc/sai.d/sai.profile" {
				raw, err := os.ReadFile(filepath.Join(h.root, h.policy.Platform[slot]))
				if err != nil {
					return nil, err
				}
				return []byte(Digest(raw) + "  file"), nil
			}
		}
		return []byte(strings.Repeat("a", 64) + "  file"), nil
	}
	if strings.Contains(text, "/cmdline") {
		return []byte("/usr/bin/syncd\x00-p\x00/etc/sai.d/sai.profile\x00"), nil
	}
	return []byte("ok"), nil
}
func (h *generationFixture) input(ctx context.Context, input []byte, _ string, args ...string) ([]byte, error) {
	var request map[string]json.RawMessage
	if err := json.Unmarshal(input, &request); err != nil {
		return nil, err
	}
	if raw, ok := request["manifest"]; ok {
		var manifest []byte
		json.Unmarshal(raw, &manifest)
		h.configured = Digest(manifest)
		return []byte("ready"), nil
	}
	var target, mode string
	json.Unmarshal(request["target"], &target)
	json.Unmarshal(request["mode"], &mode)
	if mode == "snapshot" && h.failSnapshot == target {
		return nil, fmt.Errorf("snapshot interrupted")
	}
	if mode == "restore" && target == "pmon" && h.holdRepair {
		return nil, fmt.Errorf("repair held until supervisor restart")
	}
	if mode != "snapshot" {
		h.packageCalls++
	}
	root, _ := json.Marshal(h.packageRoot(target))
	state, _ := json.Marshal(filepath.Join(h.root, "package-state", target))
	request["fixtureRoot"] = root
	request["fixtureState"] = state
	packet, _ := json.Marshal(request)
	script := packageTransactionScript + "\nr=json.load(sys.stdin)\n"
	if mode == "apply" && target == "pmon" && h.interruptApply {
		h.interruptApply = false
		script += "def stop_after_metadata(name):\n if name.endswith('/METADATA'): os._exit(77)\n"
	} else {
		script += "stop_after_metadata=None\n"
	}
	script += "print(json.dumps(transaction(r['fixtureRoot'],r['fixtureState'],r['token'],r['mode'],r.get('before'),r.get('candidate'),stop_after_metadata,observed=r.get('observed')),sort_keys=True,separators=(',',':')))\n"
	cmd := exec.CommandContext(ctx, "python3", "-I", "-B", "-c", script)
	cmd.Stdin = bytes.NewReader(packet)
	out, err := cmd.CombinedOutput()
	if err != nil {
		h.t.Logf("fixture package %s/%s: %v %s", target, mode, err, out)
	}
	return out, err
}
func (h *generationFixture) confirmInitial() string {
	now := time.Now()
	result, err := h.e.Ensure(h.bundle, now)
	if err != nil {
		h.t.Fatal(err)
	}
	h.boot = "boot-1"
	if err := h.e.Tick(now); err != nil {
		h.t.Fatal(err)
	}
	if err := h.e.Tick(now); err != nil {
		h.t.Fatal(err)
	}
	if _, err := h.e.Confirm(h.bundle, result.Token, now); err != nil {
		h.t.Fatal(err)
	}
	return result.Token
}

func TestAgentOnlyGenerationRetainsPackageAuthorityForConfirmBootAndRollback(t *testing.T) {
	for _, confirm := range []bool{true, false} {
		t.Run(fmt.Sprint("confirm=", confirm), func(t *testing.T) {
			h := newGenerationFixture(t)
			defer func() { h.e.Close() }()
			first := h.confirmInitial()
			manifest := h.loaded
			beforeCalls, beforeRestarts := h.packageCalls, h.daemonRestarts
			h.bundle.Generation++
			h.bundle.Activation = "AgentRestart"
			for i := range h.bundle.Files {
				if h.bundle.Files[i].Slot == "AgentBinary" {
					h.bundle.Files[i].Data = append(append([]byte(nil), h.bundle.Files[i].Data...), []byte("next-agent")...)
					h.bundle.Files[i].SHA256 = Digest(h.bundle.Files[i].Data)
				}
			}
			now := time.Now()
			result, err := h.e.Ensure(h.bundle, now)
			if err != nil {
				t.Fatal(err)
			}
			h.e.Tick(now)
			if err := h.e.Tick(now); err != nil {
				t.Fatal(err)
			}
			if confirm {
				if _, err := h.e.Confirm(h.bundle, result.Token, now); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := h.e.Tick(now.Add(6 * time.Minute)); err != nil {
					t.Fatal(err)
				}
			}
			if h.packageCalls != beforeCalls || h.daemonRestarts != beforeRestarts || h.loaded != manifest {
				t.Fatal("agent rotation or rollback restarted unchanged platform")
			}
			if err := artifactstate.CheckPending(h.e.reservationDir()); err != nil {
				t.Fatal(err)
			}
			current, err := h.e.load()
			if err != nil || len(current.Packages) != 2 || current.LauncherManifest != manifest {
				t.Fatal("package authority lost across agent generation")
			}
			if confirm {
				if _, err := os.Stat(filepath.Join(h.root, "host/artifacts", first)); !os.IsNotExist(err) {
					t.Fatal("old token unexpectedly retained instead of cloned authority")
				}
			}
			h.reopen()
			h.boot = "boot-2"
			if err := h.e.RestoreBoot(); err != nil {
				t.Fatal(err)
			}
			if err := h.e.Tick(time.Now()); err != nil {
				t.Fatal(err)
			}
			if err := artifactstate.CheckPending(h.e.reservationDir()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOwnedPackageSourceDriftUsesConfirmedBeforeAuthority(t *testing.T) {
	for _, interrupt := range []bool{false, true} {
		t.Run(fmt.Sprint("interrupt=", interrupt), func(t *testing.T) {
			h := newGenerationFixture(t)
			defer func() { h.e.Close() }()
			h.confirmInitial()
			p := filepath.Join(h.packageRoot("pmon"), "sonic_platform/chassis.py")
			before, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			os.WriteFile(p, []byte("# owned source drift\n"), 0644)
			h.bundle.Generation++
			now := time.Now()
			r, err := h.e.Ensure(h.bundle, now)
			if err != nil {
				t.Fatal(err)
			}
			h.boot = "repair-boot"
			if err := h.e.Tick(now); err != nil {
				t.Fatal(err)
			}
			h.interruptApply = interrupt
			h.holdRepair = interrupt
			err = h.e.Tick(now)
			if interrupt && h.interruptApply {
				t.Fatal("test did not reach the owned package mutation boundary")
			}
			if !interrupt {
				if err != nil {
					t.Fatal(err)
				}
				j, _ := h.e.load()
				if j.Phase != "AwaitingConfirmation" {
					t.Fatalf("declared drift repair became %s", j.Phase)
				}
				if _, err := h.e.Confirm(h.bundle, r.Token, now); err != nil {
					t.Fatal(err)
				}
			} else {
				if err == nil {
					t.Fatal("injected process interruption did not hold recovery")
				}
				h.reopen()
				h.holdRepair = false
				if err := h.e.Tick(now.Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				j, _ := h.e.load()
				if j.Phase != "RolledBack" {
					t.Fatalf("interruption recovery phase %s", j.Phase)
				}
			}
			got, _ := os.ReadFile(p)
			if !bytes.Equal(got, before) {
				t.Fatal("known-good package source was not restored/enforced")
			}
			if err := artifactstate.CheckPending(h.e.reservationDir()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUnknownPackagePathIsNotAuthorizedByObservedDrift(t *testing.T) {
	h := newGenerationFixture(t)
	defer func() { h.e.Close() }()
	h.confirmInitial()
	p := filepath.Join(h.packageRoot("pmon"), "sonic_platform/foreign.py")
	os.WriteFile(p, []byte("unowned"), 0644)
	h.bundle.Generation++
	now := time.Now()
	if _, err := h.e.Ensure(h.bundle, now); err != nil {
		t.Fatal(err)
	}
	h.boot = "repair-boot"
	h.e.Tick(now)
	if err := h.e.Tick(now); err == nil {
		t.Fatal("unknown package path did not block repair")
	}
	got, _ := os.ReadFile(p)
	if string(got) != "unowned" {
		t.Fatal("repair removed foreign package content")
	}
}

func TestDriftRepairRetainsBeforeAuthorityWhenPreparationFails(t *testing.T) {
	h := newGenerationFixture(t)
	defer func() { h.e.Close() }()
	h.confirmInitial()
	p := filepath.Join(h.packageRoot("pmon"), "sonic_platform/chassis.py")
	before, _ := os.ReadFile(p)
	os.WriteFile(p, []byte("# owned drift\n"), 0644)
	h.bundle.Generation++
	now := time.Now()
	if _, err := h.e.Ensure(h.bundle, now); err != nil {
		t.Fatal(err)
	}
	h.boot = "repair-boot"
	h.e.Tick(now)
	h.failSnapshot = "pmon"
	if err := h.e.Tick(now); err != nil {
		t.Fatal(err)
	}
	j, err := h.e.load()
	if err != nil || j.Phase != "RolledBack" {
		t.Fatalf("preparation failure did not recover: %+v %v", j, err)
	}
	got, _ := os.ReadFile(p)
	if !bytes.Equal(got, before) {
		t.Fatal("failure before pair publication lost confirmed recovery bytes")
	}
	if err := artifactstate.CheckPending(h.e.reservationDir()); err != nil {
		t.Fatal(err)
	}
}

func TestConfirmedBootRecoveryOutlivesStartupWindowWithoutAgentReplay(t *testing.T) {
	h := newGenerationFixture(t)
	defer func() { h.e.Close() }()
	h.confirmInitial()
	manifest := h.loaded
	agentRestarts := h.agentRestarts
	clock := time.Hour
	dependencies := 0
	setup := func() {
		h.e.Uptime = func() time.Duration { return clock }
		h.e.MutationGuard = func(_ context.Context, fn func() error) error { return fn() }
		h.e.AgentRecoveryGuard = func(_ context.Context, _, _, _ string, fn func() error) error { dependencies++; return fn() }
		h.e.ActivateAgentRecovery = func() error { h.agentRestarts++; return nil }
		h.e.AgentRecoveryHealth = func() error { return nil }
	}
	setup()
	h.boot = "delayed-boot"
	h.ready = false
	if err := h.e.RestoreBoot(); err != nil {
		t.Fatal(err)
	}
	if err := h.e.Tick(time.Now()); err == nil {
		t.Fatal("unfinished native startup incorrectly verified")
	}
	clock += 6 * time.Minute
	_ = h.e.Tick(time.Now().Add(6 * time.Minute))
	if dependencies != 0 || h.agentRestarts != agentRestarts {
		t.Fatal("ordinary boot readiness error invoked agent dependency recovery")
	}
	j, err := h.e.load()
	if err != nil {
		t.Fatal(err)
	}
	if j.Phase != "RecoveringBoot" {
		t.Fatalf("expired boot phase %s", j.Phase)
	}
	h.reopen()
	setup()
	h.ready = true
	if err := h.e.Tick(time.Now().Add(7 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	j, err = h.e.load()
	if err != nil || j.Phase != "Confirmed" || j.BootPriorPhase != "" || j.Active.BootID != h.boot {
		t.Fatalf("boot did not converge to confirmed authority: %+v %v", j, err)
	}
	if h.loaded != manifest || dependencies != 0 || h.agentRestarts != agentRestarts {
		t.Fatal("boot recovery changed version or replayed old agent")
	}
	if err := artifactstate.CheckPending(h.e.reservationDir()); err != nil {
		t.Fatal(err)
	}
}
