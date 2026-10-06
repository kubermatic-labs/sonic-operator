//go:build integration

// SPDX-License-Identifier: Apache-2.0
package sonic

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ironcore-dev/sonic-operator/internal/agent/artifactstate"
	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

func TestStandaloneHostBreakoutRecoveryRetainsTypedPortExclusion(t *testing.T) {
	for _, reserved := range []bool{false, true} {
		for _, tc := range []struct {
			name, ownerPort         string
			collapse, noop, blocked bool
		}{
			{name: "affected-child", ownerPort: "Ethernet1", blocked: true},
			{name: "orphaned-absent-child", ownerPort: "Ethernet1", collapse: true, blocked: true},
			{name: "unrelated-port", ownerPort: "Ethernet4"},
			{name: "exact-noop", ownerPort: "Ethernet0", noop: true},
		} {
			for _, targetState := range []string{"native", "after"} {
				t.Run(fmt.Sprintf("%s/%s/reserved=%v", tc.name, targetState, reserved), func(t *testing.T) {
					f, rdb, _ := hostNetworkFixture(t)
					m := f.agent
					// Generate a genuine host Pending with the production engine/native
					// adapter, retain its bytes, then complete it before constructing the
					// historical conflicting breakout. No new intent is used in recovery.
					he, err := host.NewEngine(m.hostJournalDir, f.native)
					if err != nil {
						t.Fatal(err)
					}
					q := hostRepairRequest()
					candidate := hostCandidate()
					q.Management = &candidate
					if _, err := he.Ensure(t.Context(), q, "old-transport"); err != nil {
						t.Fatal(err)
					}
					expireHostTestIntent(t, f.dir)
					hostPath := filepath.Join(m.hostJournalDir, "host.json")
					hostPending, err := os.ReadFile(hostPath)
					if err != nil {
						t.Fatal(err)
					}
					if err := he.RecoverExpired(t.Context()); err != nil {
						t.Fatal(err)
					}

					bm, initial, _, _ := breakoutFixture(t)
					m.breakoutJournalDir = bm.breakoutJournalDir
					m.resolveBreakout = bm.resolveBreakout
					m.validateBreakoutConfig = bm.validateBreakoutConfig
					m.verifyBreakoutRuntime = bm.verifyBreakoutRuntime
					p, err := m.resolveBreakout(t.Context(), "Ethernet0", nil)
					if err != nil {
						t.Fatal(err)
					}
					replaceTarget := func(before, after vlanChangeDB) {
						for key := range before {
							if err := rdb.Del(t.Context(), key).Err(); err != nil {
								t.Fatal(err)
							}
						}
						for key, fields := range after {
							if err := rdb.HSet(t.Context(), key, fields).Err(); err != nil {
								t.Fatal(err)
							}
						}
					}
					if tc.collapse {
						_, after, err := breakoutTargets(*initial, p, *splitRequest())
						if err != nil {
							t.Fatal(err)
						}
						*initial = vlanAuthorityReplaceTarget(*initial, breakoutTarget(*initial, p), after)
					}
					for key, fields := range *initial {
						if strings.HasPrefix(key, "PORT|") || strings.HasPrefix(key, "BREAKOUT_CFG|") {
							replaceTarget(vlanChangeDB{key: nil}, vlanChangeDB{key: fields})
						}
					}
					request := splitRequest()
					if tc.collapse || tc.noop {
						request.Mode = p.DefaultMode
					}
					if tc.noop {
						request.AdoptOnly = true
					}
					cli, attributes, saves := 0, 0, 0
					m.runBreakout = func(ctx context.Context, _ *exec.Cmd) ([]byte, error) {
						cli++
						db, _, err := m.readBreakoutDB(ctx)
						if err != nil {
							return nil, err
						}
						native, _, err := breakoutTargets(db, p, *request)
						if err != nil {
							return nil, err
						}
						replaceTarget(breakoutTarget(db, p), native)
						return nil, nil
					}
					m.breakoutCAS = func(ctx context.Context, raw string, before, after vlanChangeDB) (bool, error) {
						attributes++
						return m.casVLANChange(ctx, raw, before, after)
					}
					save := m.saveConfig
					m.saveConfig = func(context.Context) *agent.Status { saves++; return &agent.Status{Code: 500} }
					m.readSavedPortConfig = func() ([]byte, error) { return os.ReadFile(f.file("/etc/sonic/config_db.json")) }
					result, st := m.ReconcilePortBreakout(t.Context(), request)
					if st == nil || result == nil || !result.Pending {
						t.Fatalf("breakout Pending not generated: %+v %+v", result, st)
					}
					j, err := m.lockBreakoutJournal(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					r, err := loadBreakoutRecord(j)
					j.close()
					if err != nil {
						t.Fatal(err)
					}
					if targetState == "native" {
						replaceTarget(r.After, r.Native)
					}
					db, _, err := m.vlanChangeSnapshot(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					if tc.collapse && db["PORT|"+tc.ownerPort] != nil {
						t.Fatal("orphaned child must be absent in current layout")
					}
					network, err := m.lockNetworkJournal(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					fields := vlanChangeDB{"PORT|" + tc.ownerPort: {"speed": "25000"}}
					err = storeNetworkJournal(network, &networkJournalState{Version: 1, Records: map[string]*networkRecord{
						"Port|" + tc.ownerPort: {Kind: "Port", OwnerID: "retained-deleted-port-owner", Fields: fields, Owned: fields, Fingerprint: vlanAuthorityHash(db), PortLayout: networkPortLayout(db, &networkPlan{Identity: "Port|" + tc.ownerPort})},
					}})
					network.close()
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(hostPath, hostPending, 0600); err != nil {
						t.Fatal(err)
					}
					// The shared strict host reader must recognize the archived record.
					if err := host.WithArtifactAgentRecoveryExclusion(t.Context(), m.hostJournalDir, func() error { return nil }); err != nil {
						t.Fatal("invalid host fixture", err)
					}
					m.artifactStateDir = filepath.Join(f.dir, "artifacts")
					if err := os.Mkdir(m.artifactStateDir, 0700); err != nil {
						t.Fatal(err)
					}
					if reserved {
						if err := artifactstate.Store(m.artifactStateDir, artifactstate.Reservation{Version: 1, Owner: "artifact", Token: strings.Repeat("a", 32), Manifest: strings.Repeat("b", 64), Phase: "Active"}); err != nil {
							t.Fatal(err)
						}
					}
					paths := []string{hostPath, filepath.Join(m.breakoutJournalDir, "breakout.json"), filepath.Join(m.networkJournalDir, "network.json"), f.file("/etc/sonic/config_db.json"), filepath.Join(m.artifactStateDir, "reservation.json")}
					before := make([][]byte, len(paths))
					for i, path := range paths {
						before[i], err = os.ReadFile(path)
						if err != nil && !(i == 4 && !reserved && os.IsNotExist(err)) {
							t.Fatal(err)
						}
					}
					beforeDB, err := f.fullDB()
					if err != nil {
						t.Fatal(err)
					}
					cli, attributes, saves = 0, 0, 0
					m.saveConfig = func(ctx context.Context) *agent.Status { saves++; return save(ctx) }
					cfg := host.RecoveryConfig{JournalDir: m.hostJournalDir, RedisAddress: rdb.Options().Addr, BreakoutJournalDir: m.breakoutJournalDir, NetworkJournalDir: m.networkJournalDir}
					he, err = host.NewRecoveryEngine(cfg, watchdogAssemblyFixture{SonicAgent: m, native: f.native})
					if err != nil {
						t.Fatal(err)
					}
					ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
					defer cancel()
					err = he.RecoverExpired(ctx)
					if tc.blocked {
						if err == nil || cli != 0 || attributes != 0 || saves != 0 {
							t.Errorf("typed ownership bypassed: err=%v CLI=%d attributes=%d saves=%d", err, cli, attributes, saves)
						}
						afterDB, _ := f.fullDB()
						if !bytes.Equal(beforeDB, afterDB) {
							t.Error("blocked recovery changed CONFIG_DB")
						}
						for i, path := range paths {
							after, _ := os.ReadFile(path)
							if !bytes.Equal(before[i], after) {
								t.Errorf("blocked recovery changed %s", path)
							}
						}
					} else {
						if err != nil || cli != 0 || saves == 0 {
							t.Fatalf("exact recorded recovery failed: err=%v CLI=%d saves=%d", err, cli, saves)
						}
						if tc.noop && attributes != 0 {
							t.Fatal("exact no-op wrote attributes")
						}
						if err := host.CheckPending(m.hostJournalDir); err != nil {
							t.Fatal("host recovery not completed", err)
						}
						j, err := m.lockBreakoutJournal(t.Context())
						if err != nil {
							t.Fatal(err)
						}
						final, err := loadBreakoutRecord(j)
						j.close()
						if err != nil || final.Pending || final.Request != r.Request {
							t.Fatal("recorded breakout not completed exactly", err)
						}
						for _, i := range []int{2, 4} {
							after, _ := os.ReadFile(paths[i])
							if !bytes.Equal(before[i], after) {
								t.Fatal("recovery changed foreign authority")
							}
						}
					}
				})
			}
		}
	}
}
