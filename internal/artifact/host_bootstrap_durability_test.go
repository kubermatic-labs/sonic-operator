// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
)

func hostReceiptPhase(root string) string {
	raw, _ := os.ReadFile(filepath.Join(root, host.RecoveryReceiptFile))
	var r host.InstallationReceipt
	_ = json.Unmarshal(raw, &r)
	return r.Phase
}

func TestHostBootstrapResumeRequiresDestinationDurability(t *testing.T) {
	for _, destination := range []string{"binary", "last-content"} {
		for _, interruption := range []string{"process-exit", "directory-sync-error"} {
			t.Run(destination+"/"+interruption, func(t *testing.T) {
				b, root := scratchBootstrapFixture(t)
				target := strings.TrimPrefix(host.RecoveryBinaryFile, "/")
				if destination == "last-content" {
					target = strings.TrimPrefix(host.RecoveryBootstrapDir, "/") + "/content/" + b.Bootstrap.HostRecovery.ProfileSHA256
				}
				failure := errors.New("injected directory sync failure")
				if interruption == "process-exit" {
					raw, _ := json.Marshal(b)
					if err := os.WriteFile(filepath.Join(root, "request.json"), raw, 0600); err != nil {
						t.Fatal(err)
					}
					cmd := exec.Command(os.Args[0], "-test.run=^TestHostBootstrapProcessWorker$")
					cmd.Env = append(os.Environ(), "SONIC_HOST_INSTALL_ROOT="+root, "SONIC_HOST_INSTALL_PHASE=renamed:"+target)
					if err := cmd.Run(); err == nil {
						t.Fatal("did not exit after rename")
					} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 86 {
						t.Fatal(err)
					}
				} else {
					err := ensureHostBootstrap(t.Context(), root, b, &hostInstallFence{}, func(context.Context) error { t.Fatal("activated interrupted installation"); return nil }, func(event string) error {
						if event == "destination-sync:"+target {
							return failure
						}
						return nil
					})
					if !errors.Is(err, failure) {
						t.Fatal("did not fail directory sync after rename", err)
					}
				}
				local := filepath.Join(root, target)
				before, err := os.Stat(local)
				if err != nil {
					t.Fatal("renamed file not visible", err)
				}
				if count, _ := hostScratchFiles(t, root); count != 0 {
					t.Fatal("scratch remained after rename")
				}
				if hostReceiptPhase(root) == "Confirmed" {
					t.Fatal("interruption published Confirmed")
				}
				// Model failure of the exact destination filesystem's durability barrier,
				// including another matching payload in that same content directory.
				attempted := false
				activations := 0
				err = ensureHostBootstrap(t.Context(), root, b, &hostInstallFence{}, func(context.Context) error { activations++; return nil }, func(event string) error {
					if dest, ok := strings.CutPrefix(event, "destination-sync:"); ok && path.Dir(dest) == path.Dir(target) {
						attempted = true
						return failure
					}
					return nil
				})
				if !errors.Is(err, failure) || !attempted || activations != 0 || hostReceiptPhase(root) == "Confirmed" {
					t.Fatalf("matching resume bypassed durability: err=%v sync=%t activations=%d phase=%s", err, attempted, activations, hostReceiptPhase(root))
				}
				synced := false
				err = ensureHostBootstrap(t.Context(), root, b, &hostInstallFence{}, func(context.Context) error {
					if !synced {
						t.Fatal("activation preceded destination durability")
					}
					activations++
					return nil
				}, func(event string) error {
					if dest, ok := strings.CutPrefix(event, "destination-synced:"); ok && path.Dir(dest) == path.Dir(target) {
						synced = true
					}
					return nil
				})
				if err != nil || !synced || activations != 1 || hostReceiptPhase(root) != "Confirmed" {
					t.Fatalf("durable resume failed: %v synced=%t activations=%d", err, synced, activations)
				}
				after, err := os.Stat(local)
				if err != nil || !os.SameFile(before, after) {
					t.Fatal("matching destination rewritten instead of synced", err)
				}
			})
		}
	}
}

func TestHostBootstrapResumeRejectsReplacedDurabilityIdentity(t *testing.T) {
	for _, change := range []string{"file", "directory", "symlink", "mode"} {
		t.Run(change, func(t *testing.T) {
			b, root := scratchBootstrapFixture(t)
			target := strings.TrimPrefix(host.RecoveryBinaryFile, "/")
			interrupted := errors.New("exit after rename")
			if err := ensureHostBootstrap(t.Context(), root, b, &hostInstallFence{}, func(context.Context) error { return nil }, func(event string) error {
				if event == "renamed:"+target {
					return interrupted
				}
				return nil
			}); !errors.Is(err, interrupted) {
				t.Fatal(err)
			}
			changed := false
			activations := 0
			local := filepath.Join(root, target)
			err := ensureHostBootstrap(t.Context(), root, b, &hostInstallFence{}, func(context.Context) error { activations++; return nil }, func(event string) error {
				if event != "destination-sync:"+target || changed {
					return nil
				}
				changed = true
				switch change {
				case "file":
					if err := os.Rename(local, local+".old"); err != nil {
						return err
					}
					return os.WriteFile(local, b.Bootstrap.HostRecovery.Binary, 0755)
				case "directory":
					dir := filepath.Dir(local)
					if err := os.Rename(dir, dir+".old"); err != nil {
						return err
					}
					if err := os.Mkdir(dir, 0700); err != nil {
						return err
					}
					return os.Link(filepath.Join(dir+".old", filepath.Base(local)), local)
				case "symlink":
					if err := os.Rename(local, local+".old"); err != nil {
						return err
					}
					return os.Symlink(local+".old", local)
				case "mode":
					return os.Chmod(local, 0666)
				}
				return nil
			})
			if err == nil || !changed || activations != 0 || hostReceiptPhase(root) == "Confirmed" {
				t.Fatalf("replaced durability identity accepted: %v changed=%t activations=%d", err, changed, activations)
			}
		})
	}
}
