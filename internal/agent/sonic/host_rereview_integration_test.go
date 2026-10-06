//go:build integration

// SPDX-License-Identifier: Apache-2.0
package sonic

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
)

func expireHostTestIntent(t *testing.T, dir string) {
	t.Helper()
	path := filepath.Join(dir, "journal/host.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]json.RawMessage
	var pending map[string]json.RawMessage
	if json.Unmarshal(data, &record) != nil || json.Unmarshal(record["pending"], &pending) != nil {
		t.Fatal("missing test intent")
	}
	pending["rollbackRequired"] = json.RawMessage("true")
	record["pending"], _ = json.Marshal(pending)
	data, _ = json.Marshal(record)
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestHostMACDriftIntentRetainsObservedAuthorityAcrossCrash(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(map[bool]string{false: "observed-drift", true: "unrecorded-foreign-mac"}[foreign], func(t *testing.T) {
			f, rdb, _ := hostNetworkFixture(t)
			k := f.kernel()
			k.MAC = "02:00:00:00:00:77"
			f.putKernel(k)
			options := rdb.Options()
			cfg := hostWorkerConfig{Dir: f.dir, Addr: options.Addr, Username: options.Username, Password: options.Password, Crash: "rollback-cas", Mode: "ensure"}
			data, _ := json.Marshal(cfg)
			path := filepath.Join(f.dir, "worker.json")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestHostNativeCrashWorker$")
			cmd.Env = append(os.Environ(), "SONIC_HOST_CRASH_WORKER="+path)
			if err := cmd.Run(); err == nil {
				t.Fatal("worker did not interrupt pre-MAC dispatch")
			} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 86 {
				t.Fatal("worker failed before selected boundary")
			}
			if f.kernel().MAC != "02:00:00:00:00:77" {
				t.Fatal("crash occurred after active MAC was changed")
			}
			expireHostTestIntent(t, f.dir)
			f = openHostDeviceFixture(t, f.dir, rdb, "")
			if foreign {
				k = f.kernel()
				k.MAC = "02:00:00:00:00:88"
				f.putKernel(k)
			}
			e, err := host.NewEngine(filepath.Join(f.dir, "journal"), f.native)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			err = e.RecoverExpired(ctx)
			if foreign {
				if err == nil || f.kernel().MAC != "02:00:00:00:00:88" {
					t.Fatal("unrecorded MAC must remain blocked")
				}
				if host.CheckPending(filepath.Join(f.dir, "journal")) == nil {
					t.Fatal("foreign MAC released fence")
				}
				return
			}
			if err != nil {
				t.Fatal("own pre-dispatch MAC rejected by new watchdog", err)
			}
			if f.kernel().MAC != hostBefore().MAC || !f.kernel().Up {
				t.Fatal("declared active MAC not restored")
			}
			if err = host.CheckPending(filepath.Join(f.dir, "journal")); err != nil {
				t.Fatal("restored transaction remains pending", err)
			}
		})
	}
}

func TestHostImmediateRollbackRetainsExclusionAfterApplyFailure(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "live-rpc", true: "canceled-rpc"}[canceled], func(t *testing.T) {
			f, _, _ := hostNetworkFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			original := f.native.Run
			failed := false
			f.native.Run = func(ctx context.Context, args []string, input []byte) ([]byte, error) {
				out, err := original(ctx, args, input)
				if !failed && strings.Join(args, " ") == "ip link set dev eth0 down" {
					failed = true
					if canceled {
						cancel()
					}
					return nil, host.ErrNative
				}
				return out, err
			}
			e, err := host.NewEngine(filepath.Join(f.dir, "journal"), f.native)
			if err != nil {
				t.Fatal(err)
			}
			q := hostRepairRequest()
			candidate := hostCandidate()
			q.Management = &candidate
			done := make(chan error, 1)
			go func() { _, err := e.Ensure(ctx, q, "rpc"); done <- err }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("apply failure must be reported")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("immediate restoration waited on its own non-reentrant lock")
			}
			if !failed {
				t.Fatal("selected native failure not reached")
			}
			k := f.kernel()
			if !k.Up || k.MAC != hostBefore().MAC || k.Addresses[hostCandidate().Addresses[0].Prefix] {
				t.Fatal("immediate rollback did not restore native state")
			}
			if err = host.CheckPending(filepath.Join(f.dir, "journal")); err != nil {
				t.Fatal("immediate verified rollback left fence pending", err)
			}
		})
	}
}
