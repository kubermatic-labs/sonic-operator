// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
)

const bootstrapState = "/host/sonic-operator-artifact-bootstrap"
const supervisorPath = "usr/local/sbin/sonic-operator-artifact-supervisor"
const supervisorUnitPath = "etc/systemd/system/sonic-operator-artifact-supervisor.service"
const bootstrapPolicyPath = "etc/sonic-operator-agent/artifact-baseline.json"
const SupervisorUnit = `# SPDX-License-Identifier: Apache-2.0
[Unit]
Description=Durable SONiC artifact recovery supervisor
After=local-fs.target
Before=sonic-operator-agent.service syncd.service swss.service pmon.service rc-local.service platform-modules-z9100.service
RequiresMountsFor=/host

[Service]
Type=notify
NotifyAccess=main
ExecStart=/usr/local/sbin/sonic-operator-artifact-supervisor
Restart=always
RestartSec=2
User=root
Group=root
UMask=0077
Environment=GOMEMLIMIT=512MiB
MemoryHigh=768M
MemoryMax=1G
RuntimeDirectory=sonic-operator-artifacts
RuntimeDirectoryMode=0700

[Install]
WantedBy=multi-user.target
`

type Bootstrap struct {
	HostRecovery     *HostRecoveryBootstrap `json:"hostRecovery,omitempty"`
	SupervisorSHA256 string                 `json:"supervisorSHA256"`
	Supervisor       []byte                 `json:"supervisor,omitempty"`
	PolicySHA256     string                 `json:"policySHA256"`
	Policy           []byte                 `json:"policy,omitempty"`
	UnitSHA256       string                 `json:"unitSHA256"`
}

func (b Bootstrap) Validate(content bool) error {
	if err := b.HostRecovery.Validate(content); err != nil {
		return err
	}
	if !shaPattern.MatchString(b.SupervisorSHA256) || !shaPattern.MatchString(b.PolicySHA256) || b.UnitSHA256 != Digest([]byte(SupervisorUnit)) {
		return fmt.Errorf("invalid immutable bootstrap identity")
	}
	if content && (Digest(b.Supervisor) != b.SupervisorSHA256 || Digest(b.Policy) != b.PolicySHA256) {
		return fmt.Errorf("bootstrap content identity mismatch")
	}
	return nil
}

type bootstrapRecord struct {
	HostSHA256       string `json:"hostSHA256,omitempty"`
	Owner            string `json:"owner"`
	Target           string `json:"target"`
	Baseline         string `json:"baseline"`
	SupervisorSHA256 string `json:"supervisorSHA256"`
	PolicySHA256     string `json:"policySHA256"`
	UnitSHA256       string `json:"unitSHA256"`
	Pending          bool   `json:"pending"`
}

// EnsureBootstrap runs in the main agent, not the supervisor it repairs. Its
// immutable owner/content binding is saved before writes. An interrupted first
// installation is resumed from the same Kubernetes-owned inputs on the next RPC.
// It never changes the main agent binary, networking or running platform daemons.
//
//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func EnsureBootstrap(ctx context.Context, root string, b Bundle, activate func(context.Context) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := b.Validate(false); err != nil {
		return err
	}
	if b.Bootstrap == nil {
		return fmt.Errorf("declared bootstrap source required")
	}
	if err := b.Bootstrap.Validate(true); err != nil {
		return err
	}
	if err := validateCandidates([]File{{Slot: "AgentBinary", Data: b.Bootstrap.Supervisor}}); err != nil {
		return err
	}
	var policy Policy
	if Decode(b.Bootstrap.Policy, &policy) != nil || policy.Baseline != b.Baseline {
		return fmt.Errorf("bootstrap policy baseline mismatch")
	}
	if err := validateBootstrapPolicy(policy); err != nil {
		return err
	}
	e, err := Open(root, bootstrapState, policy, func() error { return nil }, func() error { return nil })
	if err != nil {
		return err
	}
	defer e.Close()
	image, _, err := e.read("etc/sonic/sonic_version.yml")
	if err != nil || Digest(image) != policy.ImageSHA256 {
		return fmt.Errorf("bootstrap image baseline mismatch")
	}
	desired := bootstrapRecord{Owner: b.Owner, Target: b.Target, Baseline: b.Baseline, SupervisorSHA256: b.Bootstrap.SupervisorSHA256, PolicySHA256: b.Bootstrap.PolicySHA256, UnitSHA256: b.Bootstrap.UnitSHA256}
	desired.HostSHA256 = b.Bootstrap.HostRecovery.identity()
	recordPath := e.state + "/owner.json"
	raw, _, err := e.read(recordPath)
	pending := false
	missingOwner := errors.Is(err, fs.ErrNotExist)
	if err == nil {
		var old bootstrapRecord
		if Decode(raw, &old) != nil {
			return fmt.Errorf("invalid bootstrap owner record")
		}
		pending = old.Pending
		old.Pending = false
		if old != desired {
			return fmt.Errorf("immutable bootstrap owner or identity conflict")
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	files := []struct {
		path string
		data []byte
		mode fs.FileMode
	}{{supervisorPath, b.Bootstrap.Supervisor, 0755}, {supervisorUnitPath, []byte(SupervisorUnit), 0644}, {bootstrapPolicyPath, b.Bootstrap.Policy, 0600}}
	changed := pending
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		data, mode, err := e.read(f.path)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		changed = changed || err != nil || Digest(data) != Digest(f.data) || mode != f.mode
	}
	if !changed {
		if missingOwner {
			record, _ := json.Marshal(desired)
			return e.atomic(recordPath, record, 0600)
		}
		return nil
	}
	desired.Pending = true
	if err := ctx.Err(); err != nil {
		return err
	}
	record, _ := json.Marshal(desired)
	if err := e.atomic(recordPath, record, 0600); err != nil {
		return err
	}
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		data, mode, err := e.read(f.path)
		if err == nil && Digest(data) == Digest(f.data) && mode == f.mode {
			continue
		}
		if err := e.atomic(f.path, f.data, f.mode); err != nil {
			return err
		}
	}
	if err := activate(ctx); err != nil {
		return fmt.Errorf("bootstrap supervisor activation pending")
	}
	desired.Pending = false
	record, _ = json.Marshal(desired)
	return e.atomic(recordPath, record, 0600)
}

func ActivateBootstrap(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	for _, args := range [][]string{{"daemon-reload"}, {"enable", "sonic-operator-artifact-supervisor.service"}, {"restart", "sonic-operator-artifact-supervisor.service"}} {
		if _, err := nativeCommandContext(ctx, "/usr/bin/systemctl", args...); err != nil {
			return err
		}
	}
	return nil
}
func BootstrapAgent(ctx context.Context, b Bundle, newFence func() (WriterFence, error)) error {
	if err := EnsureBootstrap(ctx, "/", b, ActivateBootstrap); err != nil {
		return err
	}
	if err := bootstrapRunning(ctx, b); err != nil {
		if err = ActivateBootstrap(ctx); err != nil {
			return err
		}
		if err = bootstrapRunning(ctx, b); err != nil {
			return err
		}
	}
	if b.Bootstrap.HostRecovery != nil {
		if newFence == nil {
			return fmt.Errorf("host bootstrap fence constructor required")
		}
		fence, err := newFence()
		if err != nil {
			return err
		}
		return EnsureHostBootstrap(ctx, "/", b, fence, ActivateHostBootstrap)
	}
	return nil
}
func bootstrapRunning(ctx context.Context, b Bundle) error {
	if b.Bootstrap == nil {
		return fmt.Errorf("missing bootstrap declaration")
	}
	for property, want := range map[string]string{"FragmentPath": "/etc/systemd/system/sonic-operator-artifact-supervisor.service", "DropInPaths": "", "NeedDaemonReload": "no"} {
		raw, err := nativeCommandContext(ctx, "/usr/bin/systemctl", "show", "--property="+property, "--value", "sonic-operator-artifact-supervisor.service")
		if err != nil || strings.TrimSpace(string(raw)) != want {
			return fmt.Errorf("active bootstrap unit differs from declared baseline")
		}
	}
	if _, err := nativeCommandContext(ctx, "/usr/bin/systemctl", "is-enabled", "--quiet", "sonic-operator-artifact-supervisor.service"); err != nil {
		return err
	}
	raw, err := nativeCommandContext(ctx, "/usr/bin/systemctl", "show", "--property=MainPID", "--value", "sonic-operator-artifact-supervisor.service")
	if err != nil {
		return err
	}
	pid := strings.TrimSpace(string(raw))
	number, err := strconv.Atoi(pid)
	if err != nil || number < 1 {
		return fmt.Errorf("bootstrap supervisor not running")
	}
	f, err := os.Open("/proc/" + pid + "/exe")
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, MaxBundleBytes+1))
	if err != nil || Digest(data) != b.Bootstrap.SupervisorSHA256 {
		return fmt.Errorf("running supervisor differs from immutable declaration")
	}
	return nil
}

func (e *Engine) verifyBootstrap(owner, target string, b *Bootstrap) error {
	raw, _, err := e.read(bootstrapState[1:] + "/owner.json")
	if err != nil {
		return fmt.Errorf("bootstrap has no durable Kubernetes owner")
	}
	var record bootstrapRecord
	if Decode(raw, &record) != nil || record.Owner != owner || record.Target != target || record.Baseline != e.Policy.Baseline || record.Pending {
		return fmt.Errorf("bootstrap ownership verification failed")
	}
	if b != nil && (record.SupervisorSHA256 != b.SupervisorSHA256 || record.PolicySHA256 != b.PolicySHA256 || record.UnitSHA256 != b.UnitSHA256) {
		return fmt.Errorf("declared bootstrap differs from installed owner")
	}
	if b != nil && record.HostSHA256 != b.HostRecovery.identity() {
		return fmt.Errorf("immutable host baseline differs")
	}
	if record.HostSHA256 != "" {
		r, err := host.CheckInstallationReceipt(func(p string) ([]byte, error) {
			raw, mode, err := e.read(strings.TrimPrefix(p, "/"))
			want := fs.FileMode(0644)
			if p == host.RecoveryReceiptFile || p == host.RecoveryConfigFile || p == host.RecoveryProfileFile || strings.HasPrefix(p, host.RecoveryBootstrapDir+"/content/") {
				want = 0600
			}
			if strings.HasPrefix(p, "/usr/local/sbin/") {
				want = 0755
			}
			if err == nil && mode != want {
				return nil, fmt.Errorf("host installation mode drift")
			}
			return raw, err
		}, true)
		if err != nil || r.Owner != owner || r.Target != target || r.SuiteSHA256 != record.HostSHA256 {
			return fmt.Errorf("confirmed host bootstrap required")
		}
	}
	for _, f := range []struct {
		path, hash string
		mode       fs.FileMode
	}{{supervisorPath, record.SupervisorSHA256, 0755}, {supervisorUnitPath, record.UnitSHA256, 0644}, {bootstrapPolicyPath, record.PolicySHA256, 0600}} {
		data, mode, err := e.read(f.path)
		if err != nil || Digest(data) != f.hash || mode != f.mode {
			return fmt.Errorf("declared immutable bootstrap drift")
		}
	}
	return nil
}
