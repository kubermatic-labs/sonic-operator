// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/ironcore-dev/sonic-operator/internal/agent/artifactstate"
	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
)

type hostInstallFile struct {
	path   string
	data   []byte
	mode   fs.FileMode
	source string
}

type hostBootstrapQualifier interface {
	QualifyHostBootstrap(context.Context, []byte, bool) error
	// VerifyHostBootstrap is strictly read-only: effective units/timer and local
	// installation readiness, without activation or a new ownership publication.
	VerifyHostBootstrap(context.Context) error
}

func (h *HostRecoveryBootstrap) identity() string {
	if h == nil {
		return ""
	}
	b := Bundle{Bootstrap: &Bootstrap{HostRecovery: h}}.WithoutContent()
	raw, _ := json.Marshal(b.Bootstrap.HostRecovery)
	return Digest(raw)
}
func (h *HostRecoveryBootstrap) files() []hostInstallFile {
	cfg, _ := host.EncodeRecoveryConfig(host.FleetRecoveryConfig())
	out := make([]hostInstallFile, 0, 5+2*len(h.MACHooks))
	out = append(out, hostInstallFile{host.RecoveryBinaryFile, h.Binary, 0755, ""}, hostInstallFile{host.RecoveryProfileFile, h.Profile, 0600, ""}, hostInstallFile{host.RecoveryConfigFile, cfg, 0600, ""})
	// Protected helper and profile precede the activation adapter. Never restart
	// interfaces-config or execute the imported helper during adoption.
	for _, m := range h.MACHooks {
		_, helper, _ := host.ImportedMACPaths(m.Kind)
		out = append(out, hostInstallFile{helper, m.Helper, 0755, ""})
	}
	out = append(out, hostInstallFile{host.RecoveryServiceFile, host.RecoveryServiceUnit(), 0644, ""}, hostInstallFile{host.RecoveryTimerFile, host.RecoveryTimerUnit(), 0644, ""})
	for _, m := range h.MACHooks {
		hook, _, _ := host.ImportedMACPaths(m.Kind)
		out = append(out, hostInstallFile{hook, host.ImportedMACUnit(m.Kind), 0644, m.SourceHookSHA256})
	}
	return out
}

func EnsureHostBootstrap(ctx context.Context, root string, b Bundle, fence WriterFence, activate func(context.Context) error) error {
	return ensureHostBootstrap(ctx, root, b, fence, activate, nil)
}

//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func ensureHostBootstrap(ctx context.Context, root string, b Bundle, fence WriterFence, activate func(context.Context) error, fault func(string) error) error {
	if b.Bootstrap == nil || b.Bootstrap.HostRecovery == nil || fence == nil || activate == nil {
		return fmt.Errorf("complete host bootstrap and exclusion required")
	}
	if err := b.Validate(false); err != nil {
		return err
	}
	// Clone the payload-bearing declaration too; never mutate caller slices.
	copyHost := *b.Bootstrap.HostRecovery
	copyHost.MACHooks = append([]MACHookBootstrap(nil), copyHost.MACHooks...)
	h := &copyHost
	qualifier, ok := fence.(hostBootstrapQualifier)
	if !ok {
		return fmt.Errorf("native host bootstrap qualifier required")
	}
	checkpoint := func(phase string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if fault != nil {
			return fault(phase)
		}
		return nil
	}
	e, err := openStore(root, host.RecoveryBootstrapDir, Policy{Baseline: b.Baseline}, func() error { return nil }, func() error { return nil }, false)
	if err != nil {
		return err
	}
	defer e.Close()
	if err := e.syncDir(e.state); err != nil {
		return err
	}
	directory, err := e.root.Open(e.state)
	if err != nil {
		return err
	}
	entries, err := directory.ReadDir(-1)
	_ = directory.Close()
	if err != nil {
		return err
	}
	e.requestContext = ctx
	if fault != nil {
		e.atomicCheckpoint = func(path, phase string) error { return fault(phase + ":" + path) }
	}
	read := func(p string) ([]byte, error) { raw, _, err := e.read(strings.TrimPrefix(p, "/")); return raw, err }
	files := h.files()
	desired := host.InstallationReceipt{Owner: b.Owner, Target: b.Target, Baseline: b.Baseline, SuiteSHA256: h.identity(), Files: map[string]string{}}
	for _, f := range files {
		desired.Files[f.path] = Digest(f.data)
	}
	desired.Files[host.RecoveryBinaryFile] = h.BinarySHA256
	desired.Files[host.RecoveryProfileFile] = h.ProfileSHA256
	for _, m := range h.MACHooks {
		_, helper, _ := host.ImportedMACPaths(m.Kind)
		desired.Files[helper] = m.HelperSHA256
		if desired.Sources == nil {
			desired.Sources = map[string]string{}
		}
		desired.Sources[m.Kind] = m.SourceHookSHA256
	}
	identity, _ := json.Marshal(desired)
	attemptID := Digest(identity)
	for _, entry := range entries {
		name := entry.Name()
		if name == ".lock" || name == "owner.json" || name == "content" || name == "install-"+attemptID || name == ".host-install-"+attemptID+"-"+Digest([]byte(e.state+"/owner.json")) {
			continue
		}
		// Legacy nonce scratch has no recorded path ownership. Preserve it as
		// evidence; the new writer never creates or reclaims these names.
		if nonce, err := hex.DecodeString(strings.TrimPrefix(name, ".artifact-")); err == nil && len(nonce) == 12 && strings.HasPrefix(name, ".artifact-") && !entry.IsDir() {
			if err := e.safe(e.state + "/" + name); err != nil {
				return err
			}
			continue
		}
		return fmt.Errorf("unrecognized or foreign host install binding")
	}
	receipt := strings.TrimPrefix(host.RecoveryReceiptFile, "/")
	bound := false
	confirmed := false
	if raw, err := read(host.RecoveryReceiptFile); err == nil {
		var old host.InstallationReceipt
		if Decode(raw, &old) != nil {
			return fmt.Errorf("invalid host bootstrap owner")
		}
		if old.Phase != "Prepared" && old.Phase != "Installing" && old.Phase != "Verifying" && old.Phase != "Confirmed" {
			return fmt.Errorf("invalid host install phase")
		}
		confirmed = old.Phase == "Confirmed"
		old.Phase = ""
		if !reflect.DeepEqual(old, desired) {
			return fmt.Errorf("immutable host bootstrap owner conflict")
		}
		bound = true
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	// An artifact's own Active reservation must not prevent its controller from
	// observing and confirming it. Under the retained install lock, an exactly
	// bound healthy suite needs no host mutation, publication or writer permit.
	if confirmed && verifyHostBootstrapFiles(e, desired) == nil {
		if err := qualifier.VerifyHostBootstrap(ctx); err == nil {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	if bound {
		if err = h.payloads(func(hash string, p *[]byte, _ uint64) error {
			if len(*p) != 0 {
				return nil
			}
			raw, mode, err := e.read(e.state + "/content/" + hash)
			if err != nil || mode != 0600 || Digest(raw) != hash {
				return fmt.Errorf("protected host resume payload unavailable")
			}
			*p = raw
			return nil
		}); err != nil {
			return err
		}
	}
	if err = h.Validate(true); err != nil {
		return err
	}
	if err = validateCandidates([]File{{Slot: "AgentBinary", Data: h.Binary}}); err != nil {
		return err
	}
	files = h.files()
	writer := newHostInstallWriter(e, h, desired)
	save := func(phase string) error {
		desired.Phase = phase
		raw, _ := json.Marshal(desired)
		if err := writer.write(receipt, raw, 0600); err != nil {
			return err
		}
		return checkpoint(phase)
	}
	cfg := host.FleetRecoveryConfig()
	// This private install lock survives the activation interval. The complete
	// writer locks and host flock deliberately do not.
	exclusive := func(fn func() error) error {
		return fence.WithMutation(ctx, func() error {
			if err := artifactstate.CheckPending(filepath.Join(root, artifactstate.DefaultDir)); err != nil {
				return err
			}
			dir := strings.TrimPrefix(cfg.JournalDir, "/")
			if err := e.safe(dir); err != nil {
				return err
			}
			if err := e.mkdirDurable(dir); err != nil {
				return err
			}
			return host.WithArtifactExclusion(ctx, filepath.Join(root, cfg.JournalDir), fn)
		})
	}
	err = exclusive(func() error {
		// A legacy store may contain durable ownership; it is never migrated/adopted.
		if _, err := e.root.Lstat("var/lib/sonic-operator/host"); !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("explicit host journal migration required")
		}
		for _, f := range files {
			data, mode, err := e.read(strings.TrimPrefix(f.path, "/"))
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			if !bound && f.source != "" && errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("original imported activation source missing")
			}
			if !bound && err == nil && (mode != f.mode || (Digest(data) != Digest(f.data) && (f.source == "" || Digest(data) != f.source))) {
				return fmt.Errorf("unowned host destination conflicts")
			}
		}
		if err := qualifier.QualifyHostBootstrap(ctx, h.Profile, bound); err != nil {
			return fmt.Errorf("native host baseline qualification failed")
		}
		// Imported original bytes are pinned evidence, retained even after uncertain
		// publication. No source command is executed or used as recovery authority.
		if err := writer.bind(); err != nil {
			return err
		}
		if err := writer.reclaim(); err != nil {
			return err
		}
		if err := writer.space(h); err != nil {
			return err
		}
		if err = h.payloads(func(hash string, p *[]byte, _ uint64) error {
			dest := e.state + "/content/" + hash
			data, mode, err := e.read(dest)
			if err == nil {
				if Digest(data) != hash || mode != 0600 {
					return fmt.Errorf("protected host payload drift")
				}
				return writer.write(dest, *p, 0600)
			}
			if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			return writer.write(dest, *p, 0600)
		}); err != nil {
			return err
		}
		if err = save("Prepared"); err != nil {
			return err
		}
		if err = save("Installing"); err != nil {
			return err
		}
		for _, f := range files {
			if err = writer.write(strings.TrimPrefix(f.path, "/"), f.data, f.mode); err != nil {
				return err
			}
			if err = checkpoint(f.path); err != nil {
				return err
			}
		}
		if _, err = host.CheckInstallationReceipt(read, false); err != nil {
			return err
		}
		return save("Verifying")
	})
	if err != nil {
		return err
	}
	if err = activate(ctx); err != nil {
		return fmt.Errorf("host installation verification pending")
	}
	if err = checkpoint("Activated"); err != nil {
		return err
	}
	return exclusive(func() error {
		if _, err := host.CheckInstallationReceipt(read, false); err != nil {
			return err
		}
		if err := qualifier.QualifyHostBootstrap(ctx, h.Profile, false); err != nil {
			return fmt.Errorf("host state changed during installation")
		}
		return save("Confirmed")
	})
}

func verifyHostBootstrapFiles(e *Engine, want host.InstallationReceipt) error {
	read := func(p string) ([]byte, error) {
		data, mode, err := e.read(strings.TrimPrefix(p, "/"))
		if err != nil {
			return nil, err
		}
		expected := fs.FileMode(0644)
		if p == host.RecoveryReceiptFile || p == host.RecoveryConfigFile || p == host.RecoveryProfileFile || strings.HasPrefix(p, host.RecoveryBootstrapDir+"/content/") {
			expected = 0600
		}
		if strings.HasPrefix(p, "/usr/local/sbin/") {
			expected = 0755
		}
		if mode != expected {
			return nil, fmt.Errorf("host installation mode drift")
		}
		return data, nil
	}
	got, err := host.CheckInstallationReceipt(read, true)
	if err != nil {
		return err
	}
	got.Phase = ""
	want.Phase = ""
	if !reflect.DeepEqual(got, want) {
		return fmt.Errorf("host immutable receipt changed")
	}
	return nil
}

// ActivateHostBootstrap invokes only compiled fixed commands. The verifier is
// read-only and does not recover Pending or apply boot MAC state.
func ActivateHostBootstrap(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if _, err := nativeCommandContext(ctx, "/usr/bin/systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := checkHostBootstrapCommand(ctx); err != nil {
		return err
	}
	for _, args := range [][]string{{"enable", "sonic-operator-host-recovery.timer"}, {"start", "sonic-operator-host-recovery.timer"}} {
		if _, err := nativeCommandContext(ctx, "/usr/bin/systemctl", args...); err != nil {
			return err
		}
	}
	for _, op := range []string{"is-enabled", "is-active"} {
		if _, err := nativeCommandContext(ctx, "/usr/bin/systemctl", op, "--quiet", "sonic-operator-host-recovery.timer"); err != nil {
			return err
		}
	}
	return nil
}

type hostCheckOutput struct{ bytes.Buffer }

func (b *hostCheckOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > MaxMetadataBytes {
		return 0, fmt.Errorf("host verifier output too large")
	}
	return b.Buffer.Write(p)
}
func checkHostBootstrapCommand(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, host.RecoveryBinaryFile, "--check-installation")
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	var output hostCheckOutput
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("local host verifier failed")
	}
	var check host.InstallationCheck
	if Decode(output.Bytes(), &check) != nil {
		return fmt.Errorf("invalid local host verifier response")
	}
	r, err := (&host.Native{}).InstallationReceipt(false)
	if err != nil || check.SuiteSHA256 != r.SuiteSHA256 || check.ConfigSHA256 != r.Files[host.RecoveryConfigFile] || check.ProfileSHA256 != r.Files[host.RecoveryProfileFile] {
		return fmt.Errorf("local host verifier identity mismatch")
	}
	return nil
}
