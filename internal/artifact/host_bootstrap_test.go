// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
)

func hostBootstrapFixture(t *testing.T) *HostRecoveryBootstrap {
	t.Helper()
	profile, err := os.ReadFile("../../config/agent/profiles/202411.1216684-48c2d4c3e.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := host.EncodeRecoveryConfig(host.FleetRecoveryConfig())
	binary := []byte("host-recovery-test-binary")
	return &HostRecoveryBootstrap{Binary: binary, BinarySHA256: Digest(binary), Profile: profile, ProfileSHA256: Digest(profile), ServiceSHA256: Digest(host.RecoveryServiceUnit()), TimerSHA256: Digest(host.RecoveryTimerUnit()), ConfigSHA256: Digest(cfg), JournalLayout: "FleetHostV1"}
}

func TestHostBootstrapProcessInterruption(t *testing.T) {
	for _, phase := range []string{"Prepared", host.RecoveryBinaryFile, host.RecoveryProfileFile, host.RecoveryConfigFile, host.RecoveryServiceFile, host.RecoveryTimerFile, "Verifying", "Activated", "Confirmed"} {
		t.Run(phase, func(t *testing.T) {
			b, root := bootstrapFixture(t)
			b.Bootstrap.HostRecovery = hostBootstrapFixture(t)
			b.Agent = &AgentOptions{BindAddress: "0.0.0.0", Port: 50051, HostGuard: true}
			b.Bootstrap.HostRecovery.Binary = b.Bootstrap.Supervisor
			b.Bootstrap.HostRecovery.BinarySHA256 = b.Bootstrap.SupervisorSHA256
			payload, _ := json.Marshal(b)
			input := filepath.Join(root, "request.json")
			if err := os.WriteFile(input, payload, 0600); err != nil {
				t.Fatal(err)
			}
			journal := filepath.Join(root, host.FleetRecoveryConfig().JournalDir)
			if err := os.MkdirAll(filepath.Join(journal, "native-runtime"), 0700); err != nil {
				t.Fatal(err)
			}
			evidence := filepath.Join(journal, "native-runtime/preserved.json")
			if err := os.WriteFile(evidence, []byte("private-existing-receipt"), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestHostBootstrapProcessWorker$")
			cmd.Env = append(os.Environ(), "SONIC_HOST_INSTALL_ROOT="+root, "SONIC_HOST_INSTALL_PHASE="+phase)
			if err := cmd.Run(); err == nil {
				t.Fatal("child did not stop")
			} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 86 {
				t.Fatal(err)
			}
			read := func(path string) ([]byte, error) { return os.ReadFile(filepath.Join(root, path)) }
			if phase != "Confirmed" {
				if _, err := host.CheckInstallationReceipt(read, true); err == nil {
					t.Fatal("interrupted suite authorizes HostManage")
				}
			}
			if err := EnsureHostBootstrap(t.Context(), root, b.WithoutContent(), &hostInstallFence{}, func(context.Context) error { return nil }); err != nil {
				t.Fatal(err)
			}
			if _, err := host.CheckInstallationReceipt(read, true); err != nil {
				t.Fatal(err)
			}
			if data, _ := os.ReadFile(evidence); string(data) != "private-existing-receipt" {
				t.Fatal("native runtime evidence overwritten")
			}
		})
	}
}
func TestHostBootstrapProcessWorker(t *testing.T) {
	root := os.Getenv("SONIC_HOST_INSTALL_ROOT")
	if root == "" {
		t.Skip("child only")
	}
	syscall.Umask(0077)
	raw, err := os.ReadFile(filepath.Join(root, "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	var b Bundle
	if json.Unmarshal(raw, &b) != nil {
		t.Fatal("invalid child request")
	}
	err = ensureHostBootstrap(t.Context(), root, b, &hostInstallFence{}, func(context.Context) error { return nil }, func(phase string) error {
		if phase == os.Getenv("SONIC_HOST_INSTALL_PHASE") {
			os.Exit(86)
		}
		return nil
	})
	t.Fatal("child did not reach boundary", err)
}

func TestHostBootstrapRejectsUnownedConflictAndUnsafeParents(t *testing.T) {
	for _, kind := range []string{"conflict", "symlink", "writable-parent"} {
		t.Run(kind, func(t *testing.T) {
			b, root := bootstrapFixture(t)
			b.Bootstrap.HostRecovery = hostBootstrapFixture(t)
			b.Agent = &AgentOptions{BindAddress: "0.0.0.0", Port: 50051, HostGuard: true}
			b.Bootstrap.HostRecovery.Binary = b.Bootstrap.Supervisor
			b.Bootstrap.HostRecovery.BinarySHA256 = b.Bootstrap.SupervisorSHA256
			parent := filepath.Join(root, "usr/local/sbin")
			if err := os.MkdirAll(parent, 0700); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "conflict":
				_ = os.WriteFile(filepath.Join(root, host.RecoveryBinaryFile), []byte("foreign"), 0755)
			case "symlink":
				_ = os.Symlink("missing", filepath.Join(root, host.RecoveryBinaryFile))
			case "writable-parent":
				_ = os.Chmod(parent, 0777)
			}
			called := false
			if EnsureHostBootstrap(t.Context(), root, b, &hostInstallFence{}, func(context.Context) error { called = true; return nil }) == nil || called {
				t.Fatal("unsafe unowned install accepted")
			}
			if _, err := os.Stat(filepath.Join(root, host.RecoveryReceiptFile)); !os.IsNotExist(err) {
				t.Fatal("unsafe install published owner")
			}
		})
	}
}

type hostInstallFence struct{ held bool }

func (f *hostInstallFence) VerifyHostBootstrap(context.Context) error { return nil }

func (f *hostInstallFence) QualifyHostBootstrap(context.Context, []byte, bool) error { return nil }

func (f *hostInstallFence) WithMutation(_ context.Context, fn func() error) error {
	if f.held {
		return errors.New("recursive lock")
	}
	f.held = true
	defer func() { f.held = false }()
	return fn()
}
func (f *hostInstallFence) WithAgentRecovery(context.Context, string, string, string, func() error) error {
	return errors.New("not recovery")
}

func TestHostBootstrapResumesEveryInstallPrefix(t *testing.T) {
	phases := []string{"Prepared", "Installing", host.RecoveryBinaryFile, host.RecoveryProfileFile, host.RecoveryConfigFile, host.RecoveryServiceFile, host.RecoveryTimerFile, "Verifying", "Activated", "Confirmed"}
	for _, phase := range phases {
		t.Run(phase, func(t *testing.T) {
			b, root := bootstrapFixture(t)
			b.Bootstrap.HostRecovery = hostBootstrapFixture(t)
			b.Agent = &AgentOptions{BindAddress: "0.0.0.0", Port: 50051, HostGuard: true}
			b.Bootstrap.HostRecovery.Binary = b.Bootstrap.Supervisor
			b.Bootstrap.HostRecovery.BinarySHA256 = b.Bootstrap.SupervisorSHA256
			fence := &hostInstallFence{}
			read := func(p string) ([]byte, error) { return os.ReadFile(filepath.Join(root, p)) }
			activate := func(context.Context) error {
				if fence.held {
					t.Fatal("activation holds writer locks")
				}
				if _, err := host.CheckInstallationReceipt(read, true); err == nil {
					t.Fatal("Host Manage enabled during activation")
				}
				return host.WithArtifactExclusion(t.Context(), filepath.Join(root, host.FleetRecoveryConfig().JournalDir), func() error { return nil })
			}
			err := ensureHostBootstrap(t.Context(), root, b, fence, activate, func(p string) error {
				if p == phase {
					return errors.New("interrupted")
				}
				return nil
			})
			if err == nil {
				t.Fatal("selected prefix not interrupted")
			}
			other := b
			other.Owner = "foreign"
			if EnsureHostBootstrap(t.Context(), root, other, fence, activate) == nil {
				t.Fatal("foreign owner resumed install")
			}
			if err = EnsureHostBootstrap(t.Context(), root, b, fence, activate); err != nil {
				t.Fatal(err)
			}
			if _, err = host.CheckInstallationReceipt(read, true); err != nil {
				t.Fatal("no confirmed receipt", err)
			}
			if _, err = os.Stat(filepath.Join(root, "usr/local/sbin/sonic-operator-agent")); !os.IsNotExist(err) {
				t.Fatal("host install touched AgentBinary")
			}
		})
	}
}
func TestHostBootstrapPayloadBoundaries(t *testing.T) {
	h := hostBootstrapFixture(t)
	b := Bundle{Owner: "owner", Target: "target", Generation: 1, Baseline: "base", Files: []File{{Slot: "AgentBinary", SHA256: Digest([]byte("agent"))}}, Bootstrap: &Bootstrap{SupervisorSHA256: Digest([]byte("supervisor")), PolicySHA256: Digest([]byte("policy")), UnitSHA256: Digest([]byte(SupervisorUnit)), HostRecovery: h}}
	b.Agent = &AgentOptions{BindAddress: "0.0.0.0", Port: 50051, HostGuard: true}
	if err := h.Validate(true); err != nil {
		t.Fatal(err)
	}
	if MetadataOnly(b) == nil {
		t.Fatal("host binary leaked into metadata")
	}
	identity := b.Identity()
	meta := b.WithoutContent()
	if err := MetadataOnly(meta); err != nil {
		t.Fatal(err)
	}
	if identity != meta.Identity() {
		t.Fatal("identity includes host bytes")
	}
	raw, _ := json.Marshal(meta)
	if len(raw) > MaxMetadataBytes {
		t.Fatal("oversized metadata")
	}
	wanted := wantedBlobs(meta, "bootstrap")
	if wanted[h.BinarySHA256] != 96<<20 || wanted[h.ProfileSHA256] != 256<<10 {
		t.Fatal("missing host upload limits")
	}
	h.Binary = []byte("corrupted")
	if h.Validate(true) == nil {
		t.Fatal("corrupt binary accepted")
	}
}

func TestHostBootstrapCannotExtendExistingImmutableBaseline(t *testing.T) {
	b, root := bootstrapFixture(t)
	if err := EnsureBootstrap(t.Context(), root, b, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	ownerPath := filepath.Join(root, bootstrapState, "owner.json")
	before, _ := os.ReadFile(ownerPath)
	b.Bootstrap.HostRecovery = hostBootstrapFixture(t)
	b.Agent = &AgentOptions{BindAddress: "0.0.0.0", Port: 50051, HostGuard: true}
	if EnsureBootstrap(t.Context(), root, b, func(context.Context) error { return nil }) == nil {
		t.Fatal("immutable baseline silently extended")
	}
	after, _ := os.ReadFile(ownerPath)
	if string(before) != string(after) {
		t.Fatal("prior immutable owner rewritten")
	}
}

func TestHostBootstrapEveryPayloadIsStrippedAndHydrated(t *testing.T) {
	b, root := bootstrapFixture(t)
	b.Bootstrap.HostRecovery = hostBootstrapFixture(t)
	b.Agent = &AgentOptions{BindAddress: "0.0.0.0", Port: 50051, HostGuard: true}
	h := b.Bootstrap.HostRecovery
	for _, which := range []string{"binary", "profile", "source", "helper"} {
		t.Run(which, func(t *testing.T) {
			meta := b.WithoutContent()
			m := meta.Bootstrap.HostRecovery
			m.MACHooks = []MACHookBootstrap{{Kind: "management-mac-shell", SourceHookSHA256: Digest([]byte("source")), HelperSHA256: host.ImportedHelperSHA256("management-mac-shell")}}
			switch which {
			case "binary":
				m.Binary = []byte("leak")
			case "profile":
				m.Profile = []byte("leak")
			case "source":
				m.MACHooks[0].SourceHook = []byte("leak")
			case "helper":
				m.MACHooks[0].Helper = []byte("leak")
			}
			if MetadataOnly(meta) == nil {
				t.Fatal("payload leaked", which)
			}
			if err := MetadataOnly(meta.WithoutContent()); err != nil {
				t.Fatal(err)
			}
		})
	}
	meta := b.WithoutContent()
	content := b.BootstrapContent()
	blobs := []Blob{}
	for hash, data := range content {
		blobs = append(blobs, Blob{SHA256: hash, Size: uint64(len(data))})
	}
	s, offsets, err := PrepareContent(t.Context(), root, meta, "bootstrap", blobs)
	if err != nil {
		t.Fatal(err)
	}
	for _, offset := range offsets {
		data := content[offset.SHA256]
		for start := 0; start < len(data); {
			end := min(start+ChunkBytes, len(data))
			if _, err = UploadContent(t.Context(), root, s.ID, offset.SHA256, uint64(start), data[start:end]); err != nil {
				t.Fatal(err)
			}
			start = end
		}
	}
	got, err := HydrateContent(t.Context(), root, meta, "bootstrap", s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if Digest(got.Bootstrap.HostRecovery.Binary) != h.BinarySHA256 || Digest(got.Bootstrap.HostRecovery.Profile) != h.ProfileSHA256 || got.Identity() != b.Identity() {
		t.Fatal("host bytes lost across chunk transport")
	}
}

func TestHostBootstrapImportedInstallPrefixesRetainOriginalEvidence(t *testing.T) {
	for _, kind := range []string{"management-mac-python", "management-mac-shell"} {
		helperName := "set-management-mac.sh"
		if kind == "management-mac-python" {
			helperName = "management-only-mac.py"
		}
		helper, err := os.ReadFile(filepath.Join(os.Getenv("SONIC_TEST_MAC_FIXTURE_DIR"), helperName))
		if err != nil {
			t.Skip("local captured helper fixture unavailable")
		}
		hookPath, helperPath, _ := host.ImportedMACPaths(kind)
		for _, phase := range []string{helperPath, hookPath} {
			t.Run(phase, func(t *testing.T) {
				b, root := bootstrapFixture(t)
				h := hostBootstrapFixture(t)
				b.Bootstrap.HostRecovery = h
				b.Agent = &AgentOptions{BindAddress: "0.0.0.0", Port: 50051, HostGuard: true}
				h.Binary = b.Bootstrap.Supervisor
				h.BinarySHA256 = b.Bootstrap.SupervisorSHA256
				original := []byte("[Service]\nExecStartPost=" + helperPath + "\n")
				interpreter := "imported-shell"
				ph := host.LegacyMACHook{Kind: kind, BaseMAC: "00:00:5e:00:53:01", MAC: "02:00:5e:00:53:01", Addresses: []host.Address{{Prefix: "10.0.0.22/24", Gateway: "10.0.0.1"}}, HelperSHA256: host.ImportedHelperSHA256(kind), HookSHA256: Digest(host.ImportedMACUnit(kind))}
				if kind == "management-mac-python" {
					original = []byte("[Service]\nExecStartPost=/usr/bin/python3 " + helperPath + " boot\n")
					interpreter = "imported-python"
					ph.BaseMAC = "00:00:5e:00:53:02"
					ph.MAC = "02:00:5e:00:53:02"
					ph.Hostname = "leaf-01"
					ph.Addresses[0].Prefix = "10.0.0.21/24"
				}
				var profile host.NativeProfile
				_ = json.Unmarshal(h.Profile, &profile)
				profile.LegacyMACHooks = []host.LegacyMACHook{ph}
				profile.ConsumerSHA256[interpreter] = Digest([]byte("interpreter"))
				h.Profile, _ = json.Marshal(profile)
				h.ProfileSHA256 = Digest(h.Profile)
				h.MACHooks = []MACHookBootstrap{{Kind: kind, SourceHook: original, SourceHookSHA256: Digest(original), Helper: helper, HelperSHA256: Digest(helper)}}
				for path, data := range map[string][]byte{hookPath: original, helperPath: helper} {
					local := filepath.Join(root, path)
					if err := os.MkdirAll(filepath.Dir(local), 0700); err != nil {
						t.Fatal(err)
					}
					mode := os.FileMode(0644)
					if path == helperPath {
						mode = 0755
					}
					if err := os.WriteFile(local, data, mode); err != nil {
						t.Fatal(err)
					}
				}
				if err := ensureHostBootstrap(t.Context(), root, b, &hostInstallFence{}, func(context.Context) error { return nil }, func(p string) error {
					if p == phase {
						return errors.New("crash prefix")
					}
					return nil
				}); err == nil {
					t.Fatal("prefix not interrupted")
				}
				if err := EnsureHostBootstrap(t.Context(), root, b.WithoutContent(), &hostInstallFence{}, func(context.Context) error { return nil }); err != nil {
					t.Fatal(err)
				}
				raw, err := os.ReadFile(filepath.Join(root, host.RecoveryBootstrapDir, "content", Digest(original)))
				if err != nil || string(raw) != string(original) {
					t.Fatal("original hook evidence lost")
				}
				raw, _ = os.ReadFile(filepath.Join(root, hookPath))
				if string(raw) != string(host.ImportedMACUnit(kind)) {
					t.Fatal("unguarded original hook still installed")
				}
			})
		}
	}
}
