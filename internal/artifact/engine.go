// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/ironcore-dev/sonic-operator/internal/agent/artifactstate"

	"golang.org/x/sys/unix"
)

// Policy is installed locally with the supervisor, not accepted over RPC.
// Platform maps finite slots to exact baseline-reviewed files. Unknown slots or
// paths are rejected, including during recovery after a policy change.
type Policy struct {
	AgentBuilds    map[string]ReleaseBuild `json:"agentBuilds,omitempty"`
	ConsumerSHA256 map[string]string       `json:"consumerSHA256,omitempty"`
	Baseline       string                  `json:"baseline"`
	Platform       map[string]string       `json:"platform,omitempty"`
	ImageSHA256    string                  `json:"imageSHA256,omitempty"`
	Runtime        map[string]RuntimeFile  `json:"runtime,omitempty"`
}
type RuntimeFile struct {
	Container string `json:"container"`
	Path      string `json:"path"`
}
type savedFile struct {
	ObservedHash    string      `json:"observedHash,omitempty"`
	ObservedMode    fs.FileMode `json:"observedMode,omitempty"`
	ObservedExisted bool        `json:"observedExisted"`
	Slot            string      `json:"slot"`
	Path            string      `json:"path"`
	Hash            string      `json:"hash"`
	Mode            fs.FileMode `json:"mode"`
	PreviousHash    string      `json:"previousHash,omitempty"`
	PreviousMode    fs.FileMode `json:"previousMode,omitempty"`
	Existed         bool        `json:"existed"`
}

// journal intentionally has no Bundle, Data, PEM, source reference or error field.
type journal struct {
	BootRuntimeIdentity  string            `json:"bootRuntimeIdentity,omitempty"`
	BootRuntimeApplied   bool              `json:"bootRuntimeApplied,omitempty"`
	PackagesPrepared     bool              `json:"packagesPrepared"`
	LauncherManifest     string            `json:"launcherManifest,omitempty"`
	Packages             []packageRecovery `json:"packages,omitempty"`
	BootPriorPhase       string            `json:"bootPriorPhase,omitempty"`
	Version              int               `json:"version"`
	Reserved             bool              `json:"reserved,omitempty"`
	DependencyActivated  bool              `json:"dependencyActivated,omitempty"`
	Reason               string            `json:"reason,omitempty"`
	RuntimePlatformDrift bool              `json:"runtimePlatformDrift,omitempty"`
	RuntimeAgentDrift    bool              `json:"runtimeAgentDrift,omitempty"`
	DeadlineUptime       int64             `json:"deadlineUptime,omitempty"`
	ActivationBootID     string            `json:"activationBootID,omitempty"`
	RollbackPID          string            `json:"rollbackPID,omitempty"`
	Active               *bootManifest     `json:"active,omitempty"`
	RollbackActivated    bool              `json:"rollbackActivated,omitempty"`
	PreviousPID          string            `json:"previousPID,omitempty"`
	Activation           string            `json:"activation,omitempty"`
	BootID               string            `json:"bootID,omitempty"`
	Owner                string            `json:"owner"`
	Target               string            `json:"target"`
	Baseline             string            `json:"baseline"`
	Generation           int64             `json:"generation"`
	Identity             string            `json:"identity"`
	Token                string            `json:"token"`
	Phase                string            `json:"phase"`
	Deadline             time.Time         `json:"deadline"`
	Changed              bool              `json:"changed"`
	Files                []savedFile       `json:"files"`
}
type bootManifest struct {
	Packages         []packageRecovery `json:"packages,omitempty"`
	LauncherManifest string            `json:"launcherManifest,omitempty"`
	Token            string            `json:"token"`
	Files            []savedFile       `json:"files"`
	BootID           string            `json:"bootID,omitempty"`
}
type Engine struct {
	atomicCheckpoint      func(string, string) error
	AvailableSpace        func(string) (uint64, error)
	PlanTLS               func(Bundle) (bool, error)
	RecoveryInput         func(string) ([]byte, fs.FileMode, bool, error)
	BootRuntimeRestore    func() error
	RestorePackages       func() error
	AgentRecoveryGuard    func(context.Context, string, string, string, func() error) error
	ActivateAgentRecovery func() error
	AgentRecoveryHealth   func() error
	ValidatePlatformBoot  func() error
	MutationGuard         func(context.Context, func() error) error
	PlanPlatform          func(Bundle) (bool, error)
	PauseRuntime          bool
	Finalize              func() error
	RetirementCheck       func() error
	DeferActivation       bool
	mu                    requestMutex
	requestContext        context.Context
	root                  *os.Root
	state                 string
	lock                  *os.File
	Policy                Policy
	Health                func() error
	Activate              func() error
	BootID                func() string
	Preflight             func(Bundle) error
	ProcessID             func() string
	Uptime                func() time.Duration
}

func Open(root, state string, policy Policy, health, activate func() error) (*Engine, error) {
	return openStore(root, state, policy, health, activate, true)
}

func openStore(root, state string, policy Policy, health, activate func() error, prune bool) (*Engine, error) {
	if policy.Baseline == "" || health == nil || activate == nil || !path.IsAbs(state) || path.Clean(state) != state {
		return nil, fmt.Errorf("invalid supervisor configuration")
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	e := &Engine{root: r, state: strings.TrimPrefix(state, "/"), Policy: policy, Health: health, Activate: activate}
	for slot, p := range policy.Platform {
		if !validPlatformPath(slot, p) {
			_ = r.Close()
			return nil, fmt.Errorf("invalid baseline destination allowlist")
		}
	}
	if err := e.safe(e.state); err != nil {
		_ = r.Close()
		return nil, err
	}
	if err := e.mkdirDurable(e.state); err != nil {
		_ = r.Close()
		return nil, err
	}
	info, err := r.Stat(e.state)
	if err != nil || info.Mode().Perm() != 0700 {
		_ = r.Close()
		return nil, fmt.Errorf("private supervisor state required")
	}
	if err := e.safe(path.Join(e.state, ".lock")); err != nil {
		_ = r.Close()
		return nil, err
	}
	l, err := r.OpenFile(path.Join(e.state, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		_ = r.Close()
		return nil, err
	}
	if err := unix.Flock(int(l.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = l.Close()
		_ = r.Close()
		return nil, fmt.Errorf("supervisor already running")
	}
	e.lock = l
	if prune {
		if err := e.pruneAbandoned(); err != nil {
			e.Close()
			return nil, err
		}
	}
	return e, nil
}
func (e *Engine) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.lock != nil {
		_ = e.lock.Close()
		e.lock = nil
	}
	if e.root != nil {
		_ = e.root.Close()
	}
}

func validPlatformPath(slot, p string) bool {
	fixed, _, err := Destination(slot)
	if err != nil || fixed != "" || path.Clean(p) != p || !path.IsAbs(p) {
		return false
	}
	names := map[string]string{"PlatformJSON": "platform.json", "HWSKUJSON": "hwsku.json", "PortConfig": "port_config.ini", "SAIProfile": "sai.profile", "BroadcomConfig": "dc-flex-with-sfp.config.bcm", "PlatformInit": "__init__.py", "PlatformChassis": "chassis.py", "PlatformSFP": "sfp.py", "PlatformEEPROM": "eeprom.py", "PlatformPSU": "psu.py", "PlatformFan": "fan.py", "PlatformThermal": "thermal.py", "PlatformAPI": "platform.py"}
	names["PlatformComponent"] = "component.py"
	names["PlatformFanDrawer"] = "fan_drawer.py"
	if slot == "PlatformWheel" {
		return strings.HasPrefix(p, "/usr/share/sonic/device/") && strings.HasSuffix(path.Base(p), ".whl")
	}
	if path.Base(p) != names[slot] {
		return false
	}
	return strings.HasPrefix(p, "/usr/share/sonic/device/") || (strings.HasPrefix(slot, "Platform") && strings.Contains(p, "/sonic_platform/") && (strings.HasPrefix(p, "/usr/local/lib/python3.") || strings.HasPrefix(p, "/usr/lib/python3/")))
}
func (e *Engine) destination(slot string) (string, fs.FileMode, error) {
	if p, mode, ok := generatedDestination(slot); ok {
		return p, mode, nil
	}
	p, m, err := Destination(slot)
	if err != nil {
		return "", 0, err
	}
	if p == "" {
		p = e.Policy.Platform[slot]
		if p == "" {
			return "", 0, fmt.Errorf("platform slot not approved by installed baseline")
		}
	}
	return strings.TrimPrefix(p, "/"), m, nil
}

// OpenRoot confines resolution even if a path changes; additionally refuse all
// symlinks rather than silently adopting their targets. Parent directories must
// not be writable by unprivileged users.
func (e *Engine) safe(p string) error {
	if p == "" || path.IsAbs(p) || path.Clean(p) != p || p == ".." || strings.HasPrefix(p, "../") {
		return fmt.Errorf("unsafe artifact path")
	}
	parts := strings.Split(p, "/")
	for i := range parts {
		info, err := e.root.Lstat(strings.Join(parts[:i+1], "/"))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("artifact path inspection failed")
		}
		if info.Mode()&fs.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("artifact path is symlink or untrusted writable")
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Geteuid()) {
			return fmt.Errorf("artifact path has an untrusted owner")
		}
		if i < len(parts)-1 && !info.IsDir() {
			return fmt.Errorf("artifact parent is not a directory")
		}
	}
	return nil
}
func (e *Engine) read(p string) ([]byte, fs.FileMode, error) {
	if err := e.safe(p); err != nil {
		return nil, 0, err
	}
	f, err := e.root.Open(p)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxBundleBytes {
		return nil, 0, fmt.Errorf("invalid artifact file")
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxBundleBytes+1))
	return b, info.Mode().Perm(), err
}
func (e *Engine) atomic(p string, b []byte, mode fs.FileMode) error {
	if e.requestContext != nil {
		if err := e.requestContext.Err(); err != nil {
			return err
		}
	}
	if err := e.safe(p); err != nil {
		return err
	}
	dir := path.Dir(p)
	if err := e.mkdirDurable(dir); err != nil {
		return err
	}
	token := make([]byte, 12)
	if _, err := rand.Read(token); err != nil {
		return err
	}
	tmp := path.Join(dir, ".artifact-"+hex.EncodeToString(token))
	f, err := e.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer func() { _ = e.root.Remove(tmp) }()
	_, err = f.Write(b)
	if err == nil {
		err = f.Chmod(mode)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err := e.root.Rename(tmp, p); err != nil {
		return err
	}
	d, err := e.root.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

func (e *Engine) syncDir(p string) error {
	d, err := e.root.Open(p)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
func (e *Engine) mkdirDurable(p string) error {
	parts := strings.Split(p, "/")
	for i := range parts {
		dir := strings.Join(parts[:i+1], "/")
		err := e.root.Mkdir(dir, 0700)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return err
		}
		if err := e.syncDir(path.Dir(dir)); err != nil {
			return err
		}
	}
	return nil
}
func (e *Engine) load() (*journal, error) {
	b, _, err := e.read(path.Join(e.state, "journal.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	j := &journal{}
	if Decode(b, j) != nil || j.Version != 1 || j.Owner == "" || len(j.Token) != 32 || j.Baseline != e.Policy.Baseline || !validPhase(j.Phase) || !validReason(j.Reason) {
		return nil, fmt.Errorf("invalid or incompatible recovery journal")
	}
	if _, err := hex.DecodeString(j.Token); err != nil {
		return nil, fmt.Errorf("invalid recovery token")
	}
	if err := e.validateManifest(j.Files); err != nil {
		return nil, err
	}
	if err := validatePackageRecords(j.Packages); err != nil {
		return nil, err
	}
	if j.LauncherManifest != "" && !shaPattern.MatchString(j.LauncherManifest) {
		return nil, fmt.Errorf("invalid launcher identity")
	}
	if j.BootRuntimeIdentity != "" && !shaPattern.MatchString(j.BootRuntimeIdentity) {
		return nil, fmt.Errorf("invalid boot runtime identity")
	}
	if j.Active != nil {
		if err := validatePackageRecords(j.Active.Packages); err != nil {
			return nil, err
		}
		if len(j.Active.Token) != 32 {
			return nil, fmt.Errorf("invalid active recovery token")
		}
		if _, err := hex.DecodeString(j.Active.Token); err != nil {
			return nil, fmt.Errorf("invalid active recovery token")
		}
		if err := e.validateManifest(j.Active.Files); err != nil {
			return nil, err
		}
	}
	var presence struct {
		PackagesPrepared *bool `json:"packagesPrepared"`
	}
	if err := json.Unmarshal(b, &presence); err != nil {
		return nil, err
	}
	if presence.PackagesPrepared == nil {
		if err := e.normalizeLegacyPackages(j); err != nil {
			return nil, err
		}
	}
	return j, nil
}
func (e *Engine) validateManifest(files []savedFile) error {
	if len(files) < 1 || len(files) > 67 {
		return fmt.Errorf("invalid recovery manifest size")
	}
	seen := map[string]bool{}
	for _, f := range files {
		p, mode, err := e.destination(f.Slot)
		if f.Slot == "AgentUnit" {
			p = "etc/systemd/system/sonic-operator-agent.service"
			mode = 0644
			err = nil
		}
		if err != nil || p != f.Path || !shaPattern.MatchString(f.Hash) || f.Mode != mode || seen[p] || (f.Existed && (!shaPattern.MatchString(f.PreviousHash) || f.PreviousMode&^0777 != 0)) {
			return fmt.Errorf("recovery destination changed")
		}
		seen[p] = true
	}
	return nil
}
func (e *Engine) save(j *journal) error {
	if j.Version == 0 {
		j.Version = 1
	}
	b, err := json.Marshal(j)
	if err != nil {
		return err
	}
	return e.atomic(path.Join(e.state, "journal.json"), b, 0600)
}
func (e *Engine) storage(j *journal, which string, i int) string {
	return path.Join(e.state, j.Token, which, fmt.Sprint(i))
}

func (e *Engine) Ensure(b Bundle, now time.Time) (result *Result, retErr error) {
	return e.ensure(context.Background(), b, now)
}
func (e *Engine) EnsureContext(ctx context.Context, b Bundle, now time.Time) (*Result, error) {
	return e.ensure(ctx, b, now)
}

//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func (e *Engine) ensure(ctx context.Context, b Bundle, now time.Time) (result *Result, retErr error) {
	if err := e.mu.LockContext(ctx); err != nil {
		return nil, err
	}
	defer e.mu.Unlock()
	defer e.bindRequest(ctx)()
	if err := b.Validate(true); err != nil {
		return nil, err
	}
	if e.Preflight != nil {
		if err := e.Preflight(b); err != nil {
			return nil, err
		}
	}
	if b.Baseline != e.Policy.Baseline {
		return nil, fmt.Errorf("installed baseline mismatch")
	}
	old, err := e.load()
	if err != nil {
		return nil, err
	}
	if err := e.pruneAbandoned(); err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			_ = e.pruneAbandoned()
		}
	}()
	runtimeDrift := false
	if old != nil {
		if old.Owner != b.Owner || old.Target != b.Target || old.Generation > b.Generation {
			return nil, fmt.Errorf("artifact ownership conflict")
		}
		if old.Generation == b.Generation && old.Identity != b.Identity() {
			return nil, fmt.Errorf("artifact identity changed without a new generation")
		}
		if old.Phase != "Confirmed" && old.Phase != "RolledBack" {
			if old.Identity != b.Identity() {
				return nil, fmt.Errorf("artifact recovery pending")
			}
			return e.observe(b, old)
		}
		if old.Phase == "RolledBack" && old.Identity == b.Identity() {
			return nil, fmt.Errorf("candidate rolled back; declare a new generation")
		}
		// Removing a slot cannot silently relinquish durable ownership.
		slots := map[string]bool{}
		for _, f := range b.Files {
			slots[f.Slot] = true
		}
		slots["AgentUnit"] = b.Agent != nil
		slots["LegacySiteHook"] = b.RetireLegacyHook
		slots["LegacySiteRestore"] = b.RetireLegacyHook
		for _, f := range old.Files {
			if !slots[f.Slot] {
				return nil, fmt.Errorf("removing owned artifact slots is unsupported")
			}
		}
		r, err := e.observe(b, old)
		if err == nil && old.Identity == b.Identity() && !r.Runtime {
			runtimeDrift = true
		}
		if err == nil && r.Configuration && r.Runtime && r.Persistence && old.Identity == b.Identity() {
			return r, nil
		}
	}
	files := append([]File(nil), b.Files...)
	forcePlatform := false
	forceTLS := false
	if e.PlanTLS != nil {
		forceTLS, err = e.PlanTLS(b)
		if err != nil {
			return nil, err
		}
	}
	if e.PlanPlatform != nil {
		var err error
		forcePlatform, err = e.PlanPlatform(b)
		if err != nil {
			return nil, err
		}
	}
	retired, err := retirementFiles(b)
	if err != nil {
		return nil, err
	}
	files = append(files, retired...)
	if b.Agent != nil {
		unit, _ := AgentUnit(*b.Agent)
		files = append(files, File{Slot: "AgentUnit", SHA256: Digest(unit), Data: unit})
	}
	if err := validateCandidates(files); err != nil {
		return nil, err
	}
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return nil, err
	}
	j := &journal{Version: 1, Owner: b.Owner, Target: b.Target, Baseline: b.Baseline, Generation: b.Generation, Identity: b.Identity(), Token: hex.EncodeToString(token), Phase: "Staged", Deadline: now.Add(5 * time.Minute)}
	j.Changed = runtimeDrift
	j.RuntimePlatformDrift = forcePlatform
	j.RuntimeAgentDrift = runtimeDrift && !forcePlatform
	j.RuntimeAgentDrift = j.RuntimeAgentDrift || forceTLS
	j.Changed = j.Changed || forcePlatform
	j.Changed = j.Changed || forceTLS
	if err := e.armDeadline(j, now); err != nil {
		return nil, err
	}
	if old != nil {
		j.Active = old.Active
	}
	j.Activation = b.Activation
	if e.BootID != nil {
		j.BootID = e.BootID()
	}
	if e.ProcessID != nil {
		j.PreviousPID = e.ProcessID()
	}
	seen := map[string]bool{}
	plans := make([]stagedPlan, 0, len(files))
	for _, f := range files {
		p, m, err := e.destination(f.Slot)
		if f.Slot == "AgentUnit" {
			p = "etc/systemd/system/sonic-operator-agent.service"
			m = 0644
			err = nil
		}
		if err != nil {
			return nil, err
		}
		if seen[p] {
			return nil, fmt.Errorf("duplicate baseline destination")
		}
		seen[p] = true
		previous, mode, err := e.read(p)
		exists := err == nil
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		sf := savedFile{Slot: f.Slot, Path: p, Hash: f.SHA256, Mode: m, Existed: exists, PreviousMode: mode, ObservedExisted: exists, ObservedMode: mode}
		if exists {
			sf.ObservedHash = Digest(previous)
		}
		// Keep last confirmed bytes as rollback material even when the current
		// file has drifted. CAS still binds to the actual pre-stage observation.
		if j.Active != nil {
			for index, activeFile := range j.Active.Files {
				if activeFile.Slot != f.Slot {
					continue
				}
				active := *j
				active.Token = j.Active.Token
				working, _, err := e.read(e.storage(&active, "new", index))
				if err != nil || Digest(working) != activeFile.Hash {
					return nil, fmt.Errorf("last confirmed recovery content unavailable")
				}
				previous = working
				sf.Existed = true
				sf.PreviousMode = activeFile.Mode
				break
			}
		}
		if sf.Existed {
			if j.Active == nil && e.RecoveryInput != nil {
				data, mode, ok, err := e.RecoveryInput(f.Slot)
				if err != nil {
					return nil, err
				}
				if ok {
					previous = data
					sf.PreviousMode = mode
				}
			}
			sf.PreviousHash = Digest(previous)
		}
		plans = append(plans, stagedPlan{file: f, record: sf, previous: previous})
		j.Changed = j.Changed || (!retirementSlot(f.Slot) && (!exists || sf.ObservedHash != sf.Hash || mode != m))
		j.Files = append(j.Files, sf)
	}
	if err := validateAgentPlans(e.Policy, plans); err != nil {
		return nil, err
	}
	if err := e.stagingSpace(plans); err != nil {
		return nil, err
	}
	for i, p := range plans {
		if p.record.Existed {
			if err := e.atomic(e.storage(j, "old", i), p.previous, 0600); err != nil {
				return nil, err
			}
		}
		if err := e.atomic(e.storage(j, "new", i), p.file.Data, 0600); err != nil {
			return nil, err
		}
	}
	if err := e.inheritPackages(j); err != nil {
		return nil, err
	}
	if err := e.save(j); err != nil {
		return nil, err
	}
	if err := e.pruneContent(j); err != nil {
		return nil, err
	}
	return &Result{Phase: j.Phase, Token: j.Token, Identity: j.Identity}, nil
}

//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func validateCandidates(files []File) error {
	if err := validatePlatformWheel(files); err != nil {
		return err
	}
	certs := map[string][]byte{}
	for _, f := range files {
		if f.Slot == "SAIProfile" {
			if err := validateSAIProfile(f.Data); err != nil {
				return err
			}
		}
		if SecretSlot(f.Slot) {
			certs[f.Slot] = f.Data
		}
		if (f.Slot == "PlatformJSON" || f.Slot == "HWSKUJSON") && !json.Valid(f.Data) {
			return fmt.Errorf("invalid platform JSON candidate")
		}
		if f.Slot == "AgentBinary" {
			binary, err := elf.NewFile(bytes.NewReader(f.Data))
			if err != nil {
				return fmt.Errorf("agent candidate is not a valid ELF executable")
			}
			valid := (binary.Type == elf.ET_EXEC || binary.Type == elf.ET_DYN) && binary.Machine == elf.EM_X86_64 && binary.Class == elf.ELFCLASS64 && len(binary.Progs) > 0
			_ = binary.Close()
			if !valid {
				return fmt.Errorf("agent candidate does not match supported x86-64 baseline")
			}
		}
	}
	if len(certs) > 0 {
		pair, err := tls.X509KeyPair(certs["AgentCertificate"], certs["AgentKey"])
		if err != nil {
			return fmt.Errorf("invalid certificate/key candidate")
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(certs["AgentCA"]) {
			return fmt.Errorf("invalid CA candidate")
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return fmt.Errorf("invalid certificate candidate")
		}
		// AgentCA is the server's client-auth trust bundle. The server issuer
		// may be a different external PKI; its trust is proved by the controller's
		// fresh mTLS handshake, not by incorrectly treating client CAs as issuers.
		now := time.Now()
		if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
			return fmt.Errorf("server certificate candidate is not currently valid")
		}
		usageOK := len(leaf.ExtKeyUsage) == 0
		for _, usage := range leaf.ExtKeyUsage {
			usageOK = usageOK || usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny
		}
		if !usageOK {
			return fmt.Errorf("certificate candidate lacks server authentication usage")
		}
		previous := leaf
		for _, der := range pair.Certificate[1:] {
			certificate, err := x509.ParseCertificate(der)
			if err != nil {
				return fmt.Errorf("invalid intermediate certificate candidate")
			}
			if previous.CheckSignatureFrom(certificate) != nil || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
				return fmt.Errorf("invalid server certificate chain")
			}
			previous = certificate
		}
	}
	return nil
}

// Tick is invoked only by the external supervisor, never by the agent process.
// A partially installed transaction is rolled back after any supervisor crash.
func (e *Engine) Tick(now time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if e.MutationGuard != nil {
		entered := false
		err := e.MutationGuard(ctx, func() error { entered = true; return e.tick(ctx, now) })
		if err != nil && !entered && errors.Is(err, artifactstate.ErrForeignPending) {
			return errors.Join(err, e.restoreAgentDependencyContext(ctx, now))
		}
		return err
	}
	return e.tick(ctx, now)
}

//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func (e *Engine) tick(ctx context.Context, now time.Time) error {
	if err := e.mu.LockContext(ctx); err != nil {
		return err
	}
	defer e.mu.Unlock()
	j, err := e.load()
	if err != nil || j == nil {
		return err
	}
	if j.Phase == "RestoringBoot" || ((j.Phase == "WaitingForeign" || j.Phase == "RestoringAgent") && j.BootPriorPhase != "") {
		return e.restoreBootLocked()
	}
	if j.Phase == "ActivatingBoot" || j.Phase == "RecoveringBoot" {
		if e.BootID != nil && j.BootID != e.BootID() {
			return e.restoreBootLocked()
		}
		if j.Phase == "ActivatingBoot" && e.expired(j, now) {
			j.Phase = "RecoveringBoot"
			j.Reason = "BootRecovery"
			if err := e.save(j); err != nil {
				return err
			}
		}
		if e.PauseRuntime {
			return nil
		}
		if e.BootRuntimeRestore != nil {
			if err := e.BootRuntimeRestore(); err != nil {
				return err
			}
		}
		j, err = e.load()
		if err != nil {
			return err
		}
		j.Active.BootID = e.BootID()
		j.Phase = j.BootPriorPhase
		j.BootPriorPhase = ""
		if err := e.save(j); err != nil {
			return err
		}
		return e.release(j)
	}
	if j.Phase == "Confirmed" || j.Phase == "RolledBack" {
		return e.release(j)
	}
	if !j.Reserved {
		r, err := artifactstate.Read(e.reservationDir())
		if err != nil {
			return err
		}
		if r != nil && r.Phase != "Idle" {
			if r.Token != j.Token || r.Manifest != j.Identity {
				return fmt.Errorf("reservation/journal identity mismatch")
			}
			j.Reserved = true
			j.Phase = "RolledBack"
			if err := e.save(j); err != nil {
				return err
			}
			return e.release(j)
		}
	}
	if j.Phase == "Staged" && j.Activation == "PlatformNextBoot" && e.BootID != nil {
		if j.Changed && j.BootID == e.BootID() {
			return nil
		}
		if err := e.armDeadline(j, now); err != nil {
			return err
		}
		if j.BootID != e.BootID() {
			j.PreviousPID = ""
		}
		j.BootID = e.BootID()
	}
	if j.Phase == "Staged" && e.expired(j, now) {
		j.Phase = "RolledBack"
		return e.save(j)
	}
	if j.Phase == "Installing" || j.Phase == "Retiring" || j.Phase == "RollingBack" || j.Phase == "RestoringAgent" || j.Phase == "WaitingForeign" || ((j.Phase == "AwaitingConfirmation" || j.Phase == "Activating") && e.expired(j, now)) {
		return e.rollback(j)
	}
	if j.Phase == "Activating" {
		if e.PauseRuntime {
			return nil
		}
		if err := e.Activate(); err != nil {
			if latest, loadErr := e.load(); loadErr == nil && latest != nil && latest.Token == j.Token {
				j = latest
			} else {
				return errors.Join(err, loadErr)
			}
			if errors.Is(err, ErrActivationPending) {
				j.Reason = "WaitingConsumers"
				_ = e.save(j)
				return nil
			}
			j.Reason = "CandidateActivation"
			if errors.Is(err, ErrConsumerMismatch) {
				j.Reason = "ConsumerMismatch"
			}
			if errors.Is(err, ErrPackageRepair) {
				j.Reason = "PackageRepair"
			}
			return e.rollback(j)
		}
		j, err = e.load()
		if err != nil {
			return err
		}
		j.Phase = "AwaitingConfirmation"
		return e.save(j)
	}
	if j.Phase != "Staged" {
		return nil
	}
	if err := e.validateProtectedAgent(j, "new", j.Files); err != nil {
		return err
	}
	if err := e.validateProtectedAgent(j, "old", j.Files); err != nil {
		return err
	}
	if platformMutation(j) && e.ValidatePlatformBoot != nil {
		if err := e.ValidatePlatformBoot(); err != nil {
			return err
		}
	}
	// Check every old value before the first mutation; a conflict belongs to
	// the local writer and must not be overwritten by rollback.
	for _, f := range j.Files {
		old, mode, err := e.read(f.Path)
		if (f.ObservedExisted && (err != nil || Digest(old) != f.ObservedHash || mode != f.ObservedMode)) || (!f.ObservedExisted && !errors.Is(err, fs.ErrNotExist)) {
			j.Phase = "Conflict"
			j.Reason = "SourceConflict"
			if err := e.save(j); err != nil {
				return err
			}
			return fmt.Errorf("artifact staging compare-and-swap conflict")
		}
	}
	if err := e.reserve(j); err != nil {
		return err
	}
	j.Phase = "Installing"
	if err := e.save(j); err != nil {
		return err
	}
	for i, f := range j.Files {
		if retirementSlot(f.Slot) {
			continue
		}
		if packageGeneratedSlot(j, f.Slot) || f.Slot == "PlatformWheel" {
			continue
		}
		data, _, err := e.read(e.storage(j, "new", i))
		if err != nil || Digest(data) != f.Hash {
			return e.rollback(j)
		}
		if !f.ObservedExisted || f.ObservedHash != f.Hash || f.ObservedMode != f.Mode {
			if err := e.atomic(f.Path, data, f.Mode); err != nil {
				return e.rollback(j)
			}
		}
	}
	j.Phase = "AwaitingConfirmation"
	if e.DeferActivation && j.Changed {
		j.Phase = "Activating"
		return e.save(j)
	}
	if err := e.save(j); err != nil {
		return err
	}
	if j.Changed {
		if err := e.Activate(); err != nil {
			latest, loadErr := e.load()
			if loadErr != nil || latest == nil || latest.Token != j.Token {
				return errors.Join(err, loadErr)
			}
			j = latest
			j.Reason = "CandidateActivation"
			return e.rollback(j)
		}
	}
	return nil
}

//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func (e *Engine) rollback(j *journal) error {
	if err := e.validateProtectedAgent(j, "old", j.Files); err != nil {
		return err
	}
	if j.Phase != "RollingBack" && e.ProcessID != nil {
		j.RollbackPID = e.ProcessID()
	}
	j.Phase = "RollingBack"
	if err := e.save(j); err != nil {
		return err
	}
	if j.RollbackActivated {
		if err := e.Health(); err != nil {
			return fmt.Errorf("recovery health not yet verified")
		}
		j.Phase = "RolledBack"
		if err := e.save(j); err != nil {
			return err
		}
		return e.release(j)
	}
	for i, f := range j.Files {
		if packageGeneratedSlot(j, f.Slot) {
			continue
		}
		if f.Existed {
			b, _, err := e.read(e.storage(j, "old", i))
			if err != nil || Digest(b) != f.PreviousHash {
				return fmt.Errorf("protected recovery content unavailable")
			}
			if err := e.atomic(f.Path, b, f.PreviousMode); err != nil {
				return err
			}
		} else {
			if err := e.safe(f.Path); err != nil {
				return err
			}
			if err := e.root.Remove(f.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			if err := e.syncDir(path.Dir(f.Path)); err != nil {
				return err
			}
		}
	}
	if e.PauseRuntime && len(j.Packages) > 0 {
		return ErrActivationPending
	}
	if e.RestorePackages != nil {
		if err := e.RestorePackages(); err != nil {
			j.Reason = "PackageRepair"
			_ = e.save(j)
			return err
		}
	}
	if j.Changed {
		if e.PauseRuntime {
			return ErrActivationPending
		}
		if err := e.Activate(); err != nil {
			return fmt.Errorf("recovery activation failed")
		}
		latest, err := e.load()
		if err != nil || latest == nil || latest.Token != j.Token {
			return fmt.Errorf("recovery journal changed")
		}
		j = latest
	}
	if e.Finalize != nil {
		if err := e.Finalize(); err != nil {
			return err
		}
	}
	j.RollbackActivated = true
	if err := e.save(j); err != nil {
		return err
	}
	if err := e.Health(); err != nil {
		return fmt.Errorf("recovery health not yet verified")
	}
	j.Phase = "RolledBack"
	if err := e.save(j); err != nil {
		return err
	}
	return e.release(j)
}
func (e *Engine) Observe(b Bundle) (*Result, error) {
	return e.ObserveContext(context.Background(), b)
}
func (e *Engine) ObserveContext(ctx context.Context, b Bundle) (*Result, error) {
	if err := e.mu.LockContext(ctx); err != nil {
		return nil, err
	}
	defer e.mu.Unlock()
	defer e.bindRequest(ctx)()
	if err := b.Validate(false); err != nil {
		return nil, err
	}
	j, err := e.load()
	if err != nil {
		return nil, err
	}
	return e.observe(b, j)
}
func (e *Engine) observe(b Bundle, j *journal) (*Result, error) {
	r := &Result{Phase: "Unowned", Identity: b.Identity()}
	if j == nil {
		return r, nil
	}
	if j.Owner != b.Owner || j.Target != b.Target {
		return nil, fmt.Errorf("artifact ownership conflict")
	}
	r.Phase = j.Phase
	r.Reason = j.Reason
	r.Token = j.Token
	r.Identity = j.Identity
	if j.Identity != b.Identity() {
		return r, nil
	}
	r.Configuration = true
	r.Persistence = true
	for i, f := range j.Files {
		data, mode, err := e.read(f.Path)
		if (!retirementSlot(f.Slot) || j.Phase == "Confirmed") && (err != nil || Digest(data) != f.Hash || mode != f.Mode) {
			r.Configuration = false
		}
		data, _, err = e.read(e.storage(j, "new", i))
		if err != nil || Digest(data) != f.Hash {
			r.Persistence = false
		}
	}
	r.Runtime = r.Configuration && e.Health() == nil
	r.Persistence = r.Persistence && j.Phase == "Confirmed"
	return r, nil
}
func (e *Engine) Confirm(b Bundle, token string, now time.Time) (*Result, error) {
	return e.ConfirmContext(context.Background(), b, token, now)
}
func (e *Engine) ConfirmContext(ctx context.Context, b Bundle, token string, now time.Time) (*Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if e.MutationGuard != nil {
		var result *Result
		err := e.MutationGuard(ctx, func() error { var err error; result, err = e.confirm(ctx, b, token, now); return err })
		return result, err
	}
	return e.confirm(ctx, b, token, now)
}
func (e *Engine) confirm(ctx context.Context, b Bundle, token string, now time.Time) (*Result, error) {
	started := time.Now()
	if err := e.mu.LockContext(ctx); err != nil {
		return nil, err
	}
	defer e.mu.Unlock()
	defer e.bindRequest(ctx)()
	if err := b.Validate(false); err != nil {
		return nil, err
	}
	j, err := e.load()
	if err != nil {
		return nil, err
	}
	if j == nil || j.Owner != b.Owner || j.Target != b.Target || j.Identity != b.Identity() || j.Token != token || j.Phase != "AwaitingConfirmation" || e.expired(j, now) {
		return nil, fmt.Errorf("stale or expired artifact confirmation")
	}
	r, err := e.observe(b, j)
	if err != nil || !r.Configuration || !r.Runtime {
		return nil, fmt.Errorf("candidate health not verified")
	}
	for i, f := range j.Files {
		data, _, err := e.read(e.storage(j, "new", i))
		if err != nil || Digest(data) != f.Hash {
			return nil, fmt.Errorf("candidate persistence not verified")
		}
	}
	if err := e.retireLegacy(j); err != nil {
		return nil, err
	}
	j.Phase = "Confirmed"
	if e.expired(j, now.Add(time.Since(started))) {
		return nil, fmt.Errorf("artifact confirmation expired during health verification")
	}
	j.Active = &bootManifest{Token: j.Token, Files: append([]savedFile(nil), j.Files...), BootID: j.BootID, Packages: append([]packageRecovery(nil), j.Packages...), LauncherManifest: j.LauncherManifest}
	if err := e.save(j); err != nil {
		return nil, err
	}
	if err := e.release(j); err != nil {
		return nil, err
	}
	if err := e.pruneContent(j); err != nil {
		return nil, err
	}
	return e.observe(b, j)
}
