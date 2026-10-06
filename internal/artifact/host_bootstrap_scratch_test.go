// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
)

func TestHostBootstrapScratchCrashIsBounded(t *testing.T) {
	for _, dest := range []string{"content", "binary"} {
		for _, phase := range []string{"temp-created", "temp-written", "temp-synced"} {
			t.Run(dest+"/"+phase, func(t *testing.T) {
				b, root := bootstrapFixture(t)
				h := hostBootstrapFixture(t)
				b.Bootstrap.HostRecovery = h
				b.Agent = &AgentOptions{HostGuard: true, BindAddress: "0.0.0.0", Port: 50051}
				h.Binary = append(append([]byte{}, b.Bootstrap.Supervisor...), make([]byte, 2<<20)...)
				h.BinarySHA256 = Digest(h.Binary)
				target := strings.TrimPrefix(host.RecoveryBinaryFile, "/")
				if dest == "content" {
					target = strings.TrimPrefix(host.RecoveryBootstrapDir, "/") + "/content/" + h.BinarySHA256
				}
				request, _ := json.Marshal(b)
				if err := os.WriteFile(filepath.Join(root, "request.json"), request, 0600); err != nil {
					t.Fatal(err)
				}
				for attempt := 0; attempt < 4; attempt++ {
					cmd := exec.Command(os.Args[0], "-test.run=^TestHostBootstrapProcessWorker$")
					cmd.Env = append(os.Environ(), "SONIC_HOST_INSTALL_ROOT="+root, "SONIC_HOST_INSTALL_PHASE="+phase+":"+target)
					if err := cmd.Run(); err == nil {
						t.Fatal("child did not crash inside atomic write")
					} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 86 {
						t.Fatal("wrong child exit", err)
					}
					count, size := hostScratchFiles(t, root)
					if count > 1 || size > int64(len(h.Binary)) {
						t.Fatalf("unbounded host scratch after %d crashes: files=%d bytes=%d", attempt+1, count, size)
					}
				}
				if err := EnsureHostBootstrap(t.Context(), root, b, &hostInstallFence{}, func(context.Context) error { return nil }); err != nil {
					t.Fatal("cannot recover bounded scratch", err)
				}
				if count, size := hostScratchFiles(t, root); count != 0 || size != 0 {
					t.Fatalf("completed install retained scratch: %d/%d", count, size)
				}
				read := func(path string) ([]byte, error) { return os.ReadFile(filepath.Join(root, path)) }
				if _, err := host.CheckInstallationReceipt(read, true); err != nil {
					t.Fatal(err)
				}
				protected, err := os.ReadFile(filepath.Join(root, host.RecoveryBootstrapDir, "content", h.BinarySHA256))
				if err != nil || Digest(protected) != h.BinarySHA256 {
					t.Fatal("protected recovery payload lost")
				}
			})
		}
	}
}

func hostScratchFiles(t *testing.T, root string) (int, int64) {
	t.Helper()
	count := 0
	var size int64
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && (strings.HasPrefix(info.Name(), ".artifact-") || strings.HasPrefix(info.Name(), ".host-install-")) {
			count++
			size += info.Size()
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return count, size
}

func scratchBootstrapFixture(t *testing.T) (Bundle, string) {
	t.Helper()
	b, root := bootstrapFixture(t)
	h := hostBootstrapFixture(t)
	b.Bootstrap.HostRecovery = h
	b.Agent = &AgentOptions{HostGuard: true, BindAddress: "0.0.0.0", Port: 50051}
	h.Binary = append(append([]byte{}, b.Bootstrap.Supervisor...), make([]byte, 2<<20)...)
	h.BinarySHA256 = Digest(h.Binary)
	return b, root
}

func TestHostScratchAttemptRejectsForeignIdentityAndTampering(t *testing.T) {
	for _, change := range []string{"owner", "suite", "symlink", "mode", "oversized"} {
		t.Run(change, func(t *testing.T) {
			b, root := scratchBootstrapFixture(t)
			h := b.Bootstrap.HostRecovery
			err := ensureHostBootstrap(t.Context(), root, b, &hostInstallFence{}, func(context.Context) error { return nil }, func(phase string) error {
				if phase == "temp-synced:"+strings.TrimPrefix(host.RecoveryBootstrapDir, "/")+"/content/"+h.BinarySHA256 {
					return errors.New("interruption")
				}
				return nil
			})
			if err == nil {
				t.Fatal("did not stop in protected payload publication")
			}
			matches, err := filepath.Glob(filepath.Join(root, host.RecoveryBootstrapDir, "content/.host-install-*"))
			if err != nil || len(matches) != 1 {
				t.Fatal("missing owned scratch", matches, err)
			}
			original, err := os.ReadFile(matches[0])
			if err != nil {
				t.Fatal(err)
			}
			bad := b
			switch change {
			case "owner":
				bad.Owner = "foreign"
			case "suite":
				copyBootstrap := *b.Bootstrap
				copyHost := *h
				copyBootstrap.HostRecovery = &copyHost
				bad.Bootstrap = &copyBootstrap
				copyHost.Binary = append(append([]byte{}, h.Binary...), 1)
				copyHost.BinarySHA256 = Digest(copyHost.Binary)
			case "symlink":
				if err := os.Remove(matches[0]); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("foreign", matches[0]); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(matches[0], 0666); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				if err := os.WriteFile(matches[0], append(original, 1), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if EnsureHostBootstrap(t.Context(), root, bad, &hostInstallFence{}, func(context.Context) error { t.Fatal("untrusted scratch activated"); return nil }) == nil {
				t.Fatal("untrusted identity/scratch accepted", change)
			}
			if _, err := os.Lstat(matches[0]); err != nil {
				t.Fatal("untrusted scratch erased", err)
			}
			if change == "owner" || change == "suite" {
				data, _ := os.ReadFile(matches[0])
				if string(data) != string(original) {
					t.Fatal("foreign request rewrote scratch")
				}
			}
		})
	}
}

func TestHostScratchRecoveryReclaimsOnlyBoundScratchBeforeReserveCheck(t *testing.T) {
	b, root := scratchBootstrapFixture(t)
	h := b.Bootstrap.HostRecovery
	if err := EnsureHostBootstrap(t.Context(), root, b, &hostInstallFence{}, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	e, err := openStore(root, host.RecoveryBootstrapDir, Policy{Baseline: b.Baseline}, func() error { return nil }, func() error { return nil }, false)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	raw, _, err := e.read(e.state + "/owner.json")
	if err != nil {
		t.Fatal(err)
	}
	var receipt host.InstallationReceipt
	if Decode(raw, &receipt) != nil {
		t.Fatal("bad receipt")
	}
	w := newHostInstallWriter(e, h, receipt)
	if err := w.bind(); err != nil {
		t.Fatal(err)
	}
	dest := strings.TrimPrefix(host.RecoveryBinaryFile, "/")
	if err := os.WriteFile(filepath.Join(root, dest), []byte("drift"), 0755); err != nil {
		t.Fatal(err)
	}
	scratch := filepath.Join(root, w.scratch(dest))
	if err := os.WriteFile(scratch, h.Binary, 0755); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(root, filepath.Dir(dest), ".artifact-0123456789abcdef01234567")
	if err := os.WriteFile(foreign, []byte("foreign-generation-scratch"), 0600); err != nil {
		t.Fatal(err)
	}
	short := uint64(0)
	e.AvailableSpace = func(string) (uint64, error) {
		retained := uint64(0)
		if info, err := os.Stat(scratch); err == nil {
			retained = uint64(info.Size())
		}
		return RecoveryReserveBytes + uint64(len(h.Binary)) + MaxMetadataBytes - retained - short, nil
	}
	if err := w.space(h); err == nil {
		t.Fatal("unreclaimed allocation ignored")
	}
	if err := w.reclaim(); err != nil {
		t.Fatal(err)
	}
	if err := w.space(h); err != nil {
		t.Fatal("bounded scratch prevented resume at exact reserve", err)
	}
	short = 1
	if err := w.space(h); err == nil {
		t.Fatal("repair consumed declared reserve")
	}
	short = 0
	if err := w.write(dest, h.Binary, 0755); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(foreign); string(data) != "foreign-generation-scratch" {
		t.Fatal("foreign scratch changed")
	}
	if data, _, err := e.read(e.state + "/content/" + h.BinarySHA256); err != nil || Digest(data) != h.BinarySHA256 {
		t.Fatal("protected payload changed")
	}
}
