//go:build integration

// SPDX-License-Identifier: Apache-2.0
package sonic

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
)

func TestHostForeignMACRecoveryPreservesBootInputs(t *testing.T) {
	rdb := newVLANRedis(t)
	f := seedHostDeviceFixture(t, rdb)
	path := filepath.Join(f.dir, "journal/host.json")
	raw, _ := os.ReadFile(path)
	var record map[string]any
	_ = json.Unmarshal(raw, &record)
	pending := record["pending"].(map[string]any)
	pending["macOwned"] = false
	pending["observedActiveMAC"] = hostCandidate().MAC
	pending["candidate"].(map[string]any)["mac"] = ""
	raw, _ = json.Marshal(record)
	_ = os.WriteFile(path, raw, 0600)
	boot := "/etc/sonic/sonic-operator-management.json"
	drop := "/etc/systemd/system/interfaces-config.service.d/90-sonic-operator-management.conf"
	beforeBoot, _ := os.ReadFile(f.file(boot))
	beforeDrop, _ := os.ReadFile(f.file(drop))
	k := f.kernel()
	k.MAC = "02:00:00:00:00:88"
	f.putKernel(k)
	// A fresh standalone reader must accept the optional field and preserve a MAC
	// never observed by the transaction: it has address authority only.
	e, err := host.NewEngine(filepath.Join(f.dir, "journal"), f.native)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.RecoverExpired(t.Context()); err != nil {
		t.Fatalf("foreign-MAC restart recovery: %v", err)
	}
	afterBoot, _ := os.ReadFile(f.file(boot))
	afterDrop, _ := os.ReadFile(f.file(drop))
	if string(beforeBoot) != string(afterBoot) || string(beforeDrop) != string(afterDrop) || f.kernel().MAC != k.MAC {
		t.Fatal("foreign MAC or boot bytes overwritten")
	}
	if f.kernel().Addresses[hostCandidate().Addresses[0].Prefix] || !f.kernel().Addresses[hostBefore().Addresses[0].Prefix] {
		t.Fatal("address cleanup lost")
	}
}

func TestHostOmittedMACPublicationCrashAndWatchdogRestart(t *testing.T) {
	for _, phase := range []string{"rollback-cas", "address-add"} {
		t.Run(phase, func(t *testing.T) {
			rdb := newVLANRedis(t)
			f := seedHostDeviceFixture(t, rdb)
			journal := filepath.Join(f.dir, "journal/host.json")
			if err := os.Remove(journal); err != nil {
				t.Fatal(err)
			}
			boot := "/etc/sonic/sonic-operator-management.json"
			drop := "/etc/systemd/system/interfaces-config.service.d/90-sonic-operator-management.conf"
			beforeBoot, _ := os.ReadFile(f.file(boot))
			beforeDrop, _ := os.ReadFile(f.file(drop))
			opts := rdb.Options()
			cfg := hostWorkerConfig{Dir: f.dir, Addr: opts.Addr, Username: opts.Username, Password: opts.Password, Crash: phase, Mode: "ensure-foreign-mac"}
			input, _ := json.Marshal(cfg)
			path := filepath.Join(f.dir, "worker.json")
			if err := os.WriteFile(path, input, 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestHostNativeCrashWorker$")
			cmd.Env = append(os.Environ(), "SONIC_HOST_CRASH_WORKER="+path)
			if err := cmd.Run(); err == nil {
				t.Fatal("worker did not crash")
			} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 86 {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(journal)
			if err != nil {
				t.Fatal(err)
			}
			var record map[string]any
			if json.Unmarshal(raw, &record) != nil {
				t.Fatal("invalid real publication")
			}
			p := record["pending"].(map[string]any)
			if owned, ok := p["macOwned"].(bool); !ok || owned || p["observedActiveMAC"] != hostCandidate().MAC {
				t.Fatal("new transaction lost ownership/observation", p)
			}
			p["rollbackRequired"] = true
			raw, _ = json.Marshal(record)
			if err := os.WriteFile(journal, raw, 0600); err != nil {
				t.Fatal(err)
			}
			f = openHostDeviceFixture(t, f.dir, rdb, "")
			kernel := f.kernel()
			kernel.MAC = "02:00:00:00:00:88"
			f.putKernel(kernel)
			e, err := host.NewRecoveryEngine(host.RecoveryConfig{JournalDir: filepath.Join(f.dir, "journal"), RedisAddress: opts.Addr}, watchdogAssemblyFixture{SonicAgent: f.agent, native: f.native})
			if err != nil {
				t.Fatal(err)
			}
			if err = e.RecoverExpired(t.Context()); err != nil {
				t.Fatal("standalone omitted-MAC recovery failed", err)
			}
			afterBoot, _ := os.ReadFile(f.file(boot))
			afterDrop, _ := os.ReadFile(f.file(drop))
			if string(beforeBoot) != string(afterBoot) || string(beforeDrop) != string(afterDrop) || f.kernel().MAC != kernel.MAC {
				t.Fatal("recovery changed foreign MAC/boot inputs")
			}
			if f.kernel().Addresses[hostBefore().Addresses[0].Prefix] || !f.kernel().Addresses[hostCandidate().Addresses[0].Prefix] || f.kernel().Rules["10.0.0.11"] {
				t.Fatal("candidate address/rule cleanup failed")
			}
			if err = host.CheckPending(filepath.Join(f.dir, "journal")); err != nil {
				t.Fatal("recovery did not durably finish", err)
			}
		})
	}
}
