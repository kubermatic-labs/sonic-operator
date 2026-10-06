//go:build integration

// SPDX-License-Identifier: Apache-2.0
package sonic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

func TestHostSavedAdmissionWriterProcess(t *testing.T) {
	path := os.Getenv("SONIC_HOST_SAVED_TEST_PATH")
	if path == "" {
		t.Skip("saved-file writer worker only")
	}
	target := path
	if os.Getenv("SONIC_HOST_SAVED_TEST_REPLACE") == "true" {
		target += ".replacement"
	}
	if err := os.WriteFile(target, []byte(os.Getenv("SONIC_HOST_SAVED_TEST_DATA")), 0600); err != nil {
		t.Fatal(err)
	}
	if target != path {
		if err := os.Rename(target, path); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHostSavedProofRevalidatedAfterOrdinarySave(t *testing.T) {
	for _, name := range []string{"no-save", "successful-save", "failed-truncate", "failed-partial", "replaced-host-state", "inplace-host-state"} {
		t.Run(name, func(t *testing.T) {
			f, rdb, _ := hostNetworkFixture(t)
			cfg := combinedFixture(t, f)
			f.agent.clientPool["APPL_DB"] = rdb
			if err := rdb.HSet(t.Context(), "PORT|Ethernet0", "admin_status", "down").Err(); err != nil {
				t.Fatal(err)
			}
			savedPath := f.file("/etc/sonic/config_db.json")
			saved, err := f.fullDB()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(savedPath, saved, 0600); err != nil {
				t.Fatal(err)
			}
			he, err := host.NewEngine(cfg.JournalDir, f.native)
			if err != nil {
				t.Fatal(err)
			}
			q := hostRepairRequest()
			if got, err := he.Ensure(t.Context(), q, "adopt"); err != nil || !got.Ready() {
				t.Fatalf("initial native proof: %+v %v", got, err)
			}
			claimPath := filepath.Join(cfg.JournalDir, "host.json")
			claim, _ := os.ReadFile(claimPath)
			identity, _ := os.Stat(claimPath)
			// A distinct writer instance shares the real journals and saved backing,
			// not configDirty or an in-process mutex with the host engine's agent.
			saves := 0
			setter := &SonicAgent{clientPool: f.agent.clientPool, journalDir: f.agent.journalDir,
				breakoutJournalDir: f.agent.breakoutJournalDir, networkJournalDir: f.agent.networkJournalDir,
				hostJournalDir: cfg.JournalDir, artifactStateDir: f.agent.artifactStateDir,
				readSavedPortConfig: func() ([]byte, error) { return os.ReadFile(savedPath) },
				saveConfig: func(context.Context) *agent.Status {
					saves++
					data := []byte{}
					if name == "successful-save" {
						var err error
						data, err = f.fullDB()
						if err != nil {
							return &agent.Status{Code: 500}
						}
					}
					if name == "failed-partial" {
						data = []byte(`{"MGMT_INTERFACE":`)
					}
					if err := os.WriteFile(savedPath, data, 0600); err != nil {
						return &agent.Status{Code: 500, Message: err.Error()}
					}
					if name != "successful-save" {
						return &agent.Status{Code: 500, Message: "injected failed whole-DB save"}
					}
					return nil
				},
			}
			barrier := &pausedHostProof{Backend: f.native, entered: make(chan struct{}), release: make(chan struct{})}
			he, err = host.NewEngine(cfg.JournalDir, barrier)
			if err != nil {
				t.Fatal(err)
			}
			type outcome struct {
				result host.Result
				err    error
			}
			done := make(chan outcome, 1)
			go func() { got, err := he.Ensure(t.Context(), q, "repeat"); done <- outcome{got, err} }()
			<-barrier.entered // Complete valid native/saved proof, still under host read exclusion.
			f.native.Run = func(context.Context, []string, []byte) ([]byte, error) {
				t.Error("final admission reran native process/watchdog proof")
				return nil, host.ErrNative
			}
			var setterErr *agent.Status
			if name == "replaced-host-state" || name == "inplace-host-state" {
				var db host.Database
				if err := json.Unmarshal(saved, &db); err != nil {
					t.Error(err)
				}
				db["MGMT_INTERFACE"]["eth0|10.0.0.11/24"]["gwaddr"] = "10.0.0.2"
				data, _ := json.Marshal(db)
				worker := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestHostSavedAdmissionWriterProcess$")
				worker.Env = append(os.Environ(), "SONIC_HOST_SAVED_TEST_PATH="+savedPath,
					"SONIC_HOST_SAVED_TEST_DATA="+string(data), fmt.Sprintf("SONIC_HOST_SAVED_TEST_REPLACE=%t", name == "replaced-host-state"))
				if output, err := worker.CombinedOutput(); err != nil {
					t.Errorf("saved writer worker: %v: %s", err, output)
				}
			} else {
				desired := agent.StatusUp
				if name == "no-save" {
					desired = agent.StatusDown
				}
				_, setterErr = setter.SetInterfaceAdminStatus(t.Context(), &agent.Interface{Name: "Ethernet0", AdminStatus: desired})
			}
			// Setter and any live Redis rollback finish before Ensure may admit.
			close(barrier.release)
			got := <-done
			positive := name == "no-save" || name == "successful-save"
			if positive {
				if setterErr != nil || got.err != nil || !got.result.Ready() {
					t.Fatalf("valid interleave rejected: setter=%v host=%+v %v", setterErr, got.result, got.err)
				}
			} else if got.err == nil || got.result.PersistenceVerified || got.result.Ready() {
				t.Errorf("stale saved proof survived %s: %+v %v", name, got.result, got.err)
			}
			if name == "failed-truncate" || name == "failed-partial" {
				if setterErr == nil || rdb.HGet(t.Context(), "PORT|Ethernet0", "admin_status").Val() != "down" {
					t.Error("setter failure or Redis rollback lost")
				}
			}
			wantSaves := 0
			if name == "successful-save" || name == "failed-truncate" || name == "failed-partial" {
				wantSaves = 1
			}
			if saves != wantSaves {
				t.Errorf("save calls=%d, want %d", saves, wantSaves)
			}
			after, _ := os.ReadFile(claimPath)
			afterIdentity, _ := os.Stat(claimPath)
			if !bytes.Equal(claim, after) || !os.SameFile(identity, afterIdentity) {
				t.Error("Ensure rewrote ownership on final proof invalidation")
			}
			if err := host.CheckPending(cfg.JournalDir); err != nil {
				t.Error(fmt.Errorf("unexpected host replay/Pending: %w", err))
			}
		})
	}
}
