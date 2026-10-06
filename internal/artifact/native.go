// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"time"
)

type Native struct {
	Engine   *Engine
	Run      func(context.Context, string, ...string) ([]byte, error)
	RunInput func(context.Context, []byte, string, ...string) ([]byte, error)
}

func nativeCommand(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	return nativeCommandContext(ctx, name, args...)
}
func nativeCommandContext(ctx context.Context, name string, args ...string) ([]byte, error) {
	// Command output is never returned as an error or logged: a consumer could
	// print credentials or artifact bytes on startup failure.
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return nil, fmt.Errorf("native artifact lifecycle check failed")
	}
	return out, nil
}
func (n *Native) Baseline() error {
	b, _, err := n.Engine.read("etc/sonic/sonic_version.yml")
	if err != nil || !shaPattern.MatchString(n.Engine.Policy.ImageSHA256) || Digest(b) != n.Engine.Policy.ImageSHA256 {
		return fmt.Errorf("installed SONiC image differs from approved baseline")
	}
	return nil
}
func runtimePath(slot string, r RuntimeFile) bool {
	if r.Container != "syncd" && r.Container != "pmon" {
		return false
	}
	if path.Clean(r.Path) != r.Path || !path.IsAbs(r.Path) {
		return false
	}
	p := r.Path
	if strings.HasPrefix(p, "/usr/share/sonic/platform/") {
		p = "/usr/share/sonic/device/runtime/" + strings.TrimPrefix(p, "/usr/share/sonic/platform/")
	}
	if strings.HasPrefix(p, "/usr/share/sonic/hwsku/") {
		p = "/usr/share/sonic/device/runtime/" + strings.TrimPrefix(p, "/usr/share/sonic/hwsku/")
	}
	return validPlatformPath(slot, p)
}
func (n *Native) Preflight(b Bundle) error {
	if b.Bootstrap == nil {
		return fmt.Errorf("Kubernetes-owned bootstrap declaration required")
	}
	if err := n.Engine.verifyBootstrap(b.Owner, b.Target, b.Bootstrap); err != nil {
		return err
	}
	if err := n.Baseline(); err != nil {
		return err
	}
	if err := validatePlatformWheel(b.Files); err != nil {
		return err
	}
	for _, f := range b.Files {
		p, _, _ := Destination(f.Slot)
		if p == "" {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			err := n.consumerBaseline(ctx)
			cancel()
			if err != nil {
				return err
			}
			break
		}
	}
	if b.RetireLegacyHook {
		if _, err := retirementFiles(b); err != nil {
			return err
		}
		for p, want := range map[string]string{legacyHookPath: legacyHookSHA, legacyScriptPath: legacyScriptSHA} {
			data, _, err := n.Engine.read(p)
			if err != nil || (Digest(data) != want && string(data) != legacyRetiredMarker) {
				return fmt.Errorf("legacy restore files differ from qualified baseline")
			}
		}
	}
	for _, f := range b.Files {
		p, _, err := Destination(f.Slot)
		if err != nil {
			return err
		}
		if p != "" {
			continue
		}
		if b.Activation != "PlatformNextBoot" {
			destination, mode, err := n.Engine.destination(f.Slot)
			if err != nil {
				return err
			}
			current, currentMode, err := n.Engine.read(destination)
			if err != nil || Digest(current) != f.SHA256 || mode != currentMode {
				return fmt.Errorf("platform changes require explicit PlatformNextBoot activation")
			}
		}
		moduleName, isModule := platformModules[f.Slot]
		if f.Slot == "PlatformWheel" || isModule {
			wanted := coreWheel
			if isModule {
				wanted = "/usr/local/lib/python3.13/dist-packages/sonic_platform/" + moduleName
			}
			if n.Engine.Policy.ImageSHA256 != "0cd0ea6266506346ed0b456976bfa6ce6a6cca01f0494edf051cbe1d31a47906" || n.Engine.Policy.Platform[f.Slot] != wanted {
				return fmt.Errorf("platform package layout differs from qualified image")
			}
		} else if !runtimePath(f.Slot, n.Engine.Policy.Runtime[f.Slot]) {
			return fmt.Errorf("platform runtime consumer is not in the approved baseline")
		}
		// The legacy hook writes its historical version at boot. Until its
		// bounded migration is qualified, it must never race a changed bundle.
		if legacy, _, err := n.Engine.read(legacyHookPath); err == nil && string(legacy) != legacyRetiredMarker {
			if Digest(legacy) != legacyHookSHA {
				return fmt.Errorf("unqualified legacy restoration hook")
			}
			destination, _, err := n.Engine.destination(f.Slot)
			if err != nil {
				return err
			}
			current, _, err := n.Engine.read(destination)
			if err != nil || Digest(current) != f.SHA256 {
				return fmt.Errorf("legacy site restore hook migration required before platform changes")
			}
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("legacy restore hook cannot be safely inspected")
		}
	}
	if b.Agent != nil && (b.Agent.ReadOnly || !b.Agent.Artifacts) {
		return fmt.Errorf("managed agent must retain artifact confirmation capability")
	}
	if b.Agent != nil {
		old, _, err := n.Engine.read("etc/systemd/system/sonic-operator-agent.service")
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		for _, arg := range strings.Fields(string(old)) {
			if strings.HasPrefix(arg, "--host-journal-dir=") && (arg != "--host-journal-dir=/host/sonic-operator-host-journal" || (!b.Agent.HostConfig && !b.Agent.HostGuard)) {
				return fmt.Errorf("existing host recovery guard cannot be removed or rebound")
			}
		}
	}
	unit, _, err := n.Engine.read("etc/systemd/system/sonic-operator-agent.service")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, arg := range strings.Fields(string(unit)) {
		for flag, dir := range map[string]string{"--vlan-authority-journal-dir=": "/host/sonic-operator-vlan-journal", "--breakout-journal-dir=": "/host/sonic-operator-breakout-journal", "--network-journal-dir=": "/host/sonic-operator-network-journal"} {
			if strings.HasPrefix(arg, flag) && arg != flag+dir {
				return fmt.Errorf("agent journals differ from qualified artifact writer fence")
			}
		}
	}
	return nil
}
func (n *Native) Finalize() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := n.command(ctx, "/usr/bin/systemctl", "daemon-reload")
	return err
}
func (n *Native) RetirementCheck() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	state, err := n.command(ctx, "/usr/bin/systemctl", "show", "--property=SubState", "--value", "rc-local.service")
	if err != nil || strings.TrimSpace(string(state)) != "exited" {
		return fmt.Errorf("legacy rc-local writer has not finished")
	}
	return nil
}
func (n *Native) PID() string {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := n.command(ctx, "/usr/bin/systemctl", "show", "--property=MainPID", "--value", "sonic-operator-agent.service")
	if err != nil {
		return ""
	}
	pid := strings.TrimSpace(string(out))
	value, err := strconv.Atoi(pid)
	if err != nil || value < 1 {
		return ""
	}
	return pid
}
func (n *Native) BootID() string {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
func (n *Native) Uptime() time.Duration {
	raw, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return -1
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 1 {
		return -1
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || seconds < 0 {
		return -1
	}
	return time.Duration(seconds * float64(time.Second))
}
func (n *Native) Health() error {
	return n.health(false)
}
func (n *Native) AgentRecoveryHealth() error { return n.health(true) }
func (n *Native) health(agentOnly bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := func(name string, args ...string) ([]byte, error) { return n.command(ctx, name, args...) }
	if err := n.Baseline(); err != nil {
		return err
	}
	e := n.Engine
	j, err := e.load()
	if err != nil || j == nil {
		return fmt.Errorf("artifact journal unavailable")
	}
	if (j.Phase == "ActivatingBoot" || j.Phase == "RecoveringBoot") && j.Active != nil {
		copy := *j
		copy.Files = j.Active.Files
		copy.PreviousPID = ""
		copy.Phase = "Confirmed"
		j = &copy
	}
	if agentOnly {
		copy := *j
		copy.Phase = "RollingBack"
		if j.BootPriorPhase != "" && j.Active != nil {
			copy.Files = append([]savedFile(nil), j.Active.Files...)
			for i := range copy.Files {
				copy.Files[i].Existed = true
				copy.Files[i].PreviousHash = copy.Files[i].Hash
				copy.Files[i].PreviousMode = copy.Files[i].Mode
			}
		}
		j = &copy
	}
	if err := e.verifyBootstrap(j.Owner, j.Target, nil); err != nil {
		return err
	}
	for _, service := range []string{"sonic-operator-agent.service", "sonic-operator-artifact-supervisor.service"} {
		if _, err := command("/usr/bin/systemctl", "is-enabled", "--quiet", service); err != nil {
			return err
		}
	}
	pid := n.PID()
	if pid == "" || (agentMutation(j) && j.Phase != "RollingBack" && j.PreviousPID != "" && pid == j.PreviousPID) {
		return fmt.Errorf("restarted agent process not verified")
	}
	if agentMutation(j) && j.Phase == "RollingBack" && j.RollbackPID != "" && pid == j.RollbackPID {
		return fmt.Errorf("recovered agent process has not restarted")
	}
	// /proc/PID/exe is a kernel magic symlink, read only here with a validated PID.
	running, err := os.Open("/proc/" + pid + "/exe")
	if err != nil {
		return fmt.Errorf("running agent executable unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(running, MaxBundleBytes+1))
	running.Close()
	if err != nil || len(data) > MaxBundleBytes {
		return fmt.Errorf("running agent executable unreadable")
	}
	installed, _, err := e.read("usr/local/sbin/sonic-operator-agent")
	if err != nil || Digest(data) != Digest(installed) {
		return fmt.Errorf("running and installed agent executables differ")
	}
	if err := ValidateAgentRelease(e.Policy, Digest(data)); err != nil {
		return err
	}
	for _, f := range j.Files {
		if j.Phase == "RollingBack" {
			if !f.Existed {
				continue
			}
		}
		if SecretSlot(f.Slot) {
			args, err := os.ReadFile("/proc/" + pid + "/cmdline")
			if err != nil {
				return fmt.Errorf("agent TLS process arguments unavailable")
			}
			if err := verifyAgentTLSArguments(args); err != nil {
				return err
			}
			// Check the process mount namespace as well as host file readback.
			// Fixed paths and a validated numeric PID prevent arbitrary reads.
			file, err := os.Open("/proc/" + pid + "/root/" + f.Path)
			if err != nil {
				return fmt.Errorf("agent namespace TLS file unavailable")
			}
			data, err := io.ReadAll(io.LimitReader(file, MaxBundleBytes+1))
			file.Close()
			hash := f.Hash
			if j.Phase == "RollingBack" {
				hash = f.PreviousHash
			}
			if err != nil || Digest(data) != hash {
				return fmt.Errorf("agent namespace TLS content differs from declaration")
			}
		}
		if f.Slot == "AgentUnit" {
			unit, _, err := e.read(f.Path)
			if err != nil {
				return err
			}
			var expected string
			for _, line := range strings.Split(string(unit), "\n") {
				if strings.HasPrefix(line, "ExecStart=") {
					expected = strings.TrimPrefix(line, "ExecStart=")
				}
			}
			commandLine, err := os.ReadFile("/proc/" + pid + "/cmdline")
			if err != nil || expected == "" || strings.Join(strings.Split(strings.TrimRight(string(commandLine), "\x00"), "\x00"), " ") != expected {
				return fmt.Errorf("active agent options differ from declared unit")
			}
			continue
		}
	}
	if err := n.verifyLoadedTLS(j); err != nil {
		return err
	}
	if agentOnly {
		return nil
	}
	return n.platformHealth(ctx, j)
}
func (n *Native) ActivateAgentRecovery() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := n.command(ctx, "/usr/bin/systemctl", "daemon-reload"); err != nil {
		return err
	}
	_, err := n.command(ctx, "/usr/bin/systemctl", "--no-block", "restart", "sonic-operator-agent.service")
	return err
}
func (n *Native) Activate() error {
	e := n.Engine
	j, err := e.load()
	if err != nil || j == nil {
		return fmt.Errorf("activation journal unavailable")
	}
	ctx, cancel := n.activationContext(j)
	defer cancel()
	if err := n.activatePlatformContext(ctx, j); err != nil {
		return err
	}
	if _, err := n.command(ctx, "/usr/bin/systemctl", "daemon-reload"); err != nil {
		return err
	}
	if _, err := n.command(ctx, "/usr/bin/systemctl", "enable", "sonic-operator-agent.service"); err != nil {
		return err
	}
	// Nonblocking is essential during ordered boot: the agent is After this
	// supervisor, whose readiness must not wait on the agent startup job.
	if !agentMutation(j) {
		return nil
	}
	_, err = n.command(ctx, "/usr/bin/systemctl", "--no-block", "restart", "sonic-operator-agent.service")
	return err
}
