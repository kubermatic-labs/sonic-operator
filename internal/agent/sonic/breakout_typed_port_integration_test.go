//go:build integration

// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/redis/go-redis/v9"
	"github.com/vishvananda/netlink"
)

func TestBreakoutTypedPortOwnership(t *testing.T) {
	for _, tc := range []struct {
		name, port string
		orphan     bool
		absent     bool
		unrelated  bool
	}{
		{name: "surviving parent", port: "Ethernet0"},
		{name: "disappearing child", port: "Ethernet1"},
		{name: "orphaned child record", port: "Ethernet1", orphan: true},
		{name: "absent orphaned future child", port: "Ethernet1", orphan: true, absent: true},
		{name: "unrelated record", port: "Ethernet4", unrelated: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newVLANRedis(t)
			m, initial, _, _ := breakoutFixture(t)
			p, _ := m.resolveBreakout(t.Context(), "Ethernet0", nil)
			for name, fields := range p.Modes["4x25G[10G]"] {
				(*initial)["PORT|"+name] = maps.Clone(fields)
				(*initial)["PORT|"+name]["admin_status"] = "up"
				(*initial)["PORT|"+name]["mtu"] = "9100"
			}
			(*initial)["PORT|Ethernet4"]["mtu"] = "9100"
			(*initial)["BREAKOUT_CFG|Ethernet0"]["brkout_mode"] = "4x25G[10G]"
			m.clientPool = map[string]*redis.Client{"CONFIG_DB": db}
			for name, index := range map[string]int{"APPL_DB": 0, "ASIC_DB": 1, "COUNTERS_DB": 2} {
				opts := *db.Options()
				opts.DB = index
				rdb := redis.NewClient(&opts)
				t.Cleanup(func() { _ = rdb.Close() })
				m.clientPool[name] = rdb
			}
			m.breakoutSnapshot, m.breakoutCAS, m.verifyBreakoutRuntime = nil, nil, nil
			m.networkJournalDir = t.TempDir()
			if err := os.Chmod(m.networkJournalDir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(m.networkJournalDir, ".lock"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			for key, fields := range *initial {
				if err := db.HSet(t.Context(), key, fields).Err(); err != nil {
					t.Fatal(err)
				}
				if port, ok := strings.CutPrefix(key, "PORT|"); ok {
					oid, rid := "oid:0x100000000000"+port[8:], "oid:0xabc"+port[8:]
					for _, row := range []struct {
						db, key string
						fields  map[string]string
					}{
						{"APPL_DB", "PORT_TABLE:" + port, fields},
						{"COUNTERS_DB", "COUNTERS_PORT_NAME_MAP", map[string]string{port: oid}},
						{"ASIC_DB", "VIDTORID", map[string]string{oid: rid}},
						{"ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_PORT:" + oid, map[string]string{"SAI_PORT_ATTR_SPEED": fields["speed"], "SAI_PORT_ATTR_MTU": "9122"}},
					} {
						if err := m.clientPool[row.db].HSet(t.Context(), row.key, row.fields).Err(); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			m.clientPool["APPL_DB"].AddHook(&breakoutAPPLConsumer{rdb: db, appl: m.clientPool["APPL_DB"], platform: p})
			m.linkByName = func(name string) (netlink.Link, error) {
				if db.Exists(t.Context(), "PORT|"+name).Val() == 0 {
					return nil, netlink.LinkNotFoundError{}
				}
				return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}, nil
			}
			var saved []byte
			saves, calls := 0, 0
			m.saveConfig = func(ctx context.Context) *agent.Status {
				saves++
				current, _, err := m.readBreakoutDB(ctx)
				if err != nil {
					t.Fatal(err)
				}
				saved = portConfigJSON(t, current)
				return nil
			}
			m.readSavedPortConfig = func() ([]byte, error) { return saved, nil }
			ctx := context.WithValue(t.Context(), routingCommandRunnerKey{}, routingCommandRunner(func(cmd *exec.Cmd) ([]byte, error) {
				if !reflect.DeepEqual(cmd.Args, []string{"cat", "/etc/sonic/config_db.json"}) {
					t.Fatalf("unexpected command: %v", cmd.Args)
				}
				return saved, nil
			}))
			request := &agent.NetworkRequest{Kind: "Port", OwnerID: "typed-interface-uid", Spec: json.RawMessage(fmt.Sprintf(`{"nativeName":%q,"speed":%s,"mtu":9100}`, tc.port, (*initial)["PORT|"+tc.port]["speed"]))}
			if got, st := m.EnsureNetworkResource(ctx, request); st != nil || !got.ConfigurationVerified || !got.RuntimeVerified || !got.PersistenceVerified {
				t.Fatalf("typed adoption: %+v %+v", got, st)
			}
			if tc.orphan {
				// Controller deletion uses this successful no-pending recovery path;
				// durable Port ownership must remain protective without an API claim.
				if _, st := m.RecoverNetworkResource(ctx, request); st != nil {
					t.Fatal(st)
				}
			}
			mode, desired := "4x25G[10G]", "1x100G[40G]"
			if tc.absent {
				for name := range breakoutNames(p) {
					if err := db.Del(ctx, "PORT|"+name).Err(); err != nil {
						t.Fatal(err)
					}
				}
				if err := db.HSet(ctx, "PORT|Ethernet0", p.NativeModes["1x100G[40G]"]["Ethernet0"]).Err(); err != nil {
					t.Fatal(err)
				}
				mode, desired = desired, mode
				if err := db.HSet(ctx, "BREAKOUT_CFG|Ethernet0", "brkout_mode", mode).Err(); err != nil {
					t.Fatal(err)
				}
			}
			m.runBreakout = func(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
				calls++
				if !reflect.DeepEqual(cmd.Args, []string{"config", "interface", "breakout", "Ethernet0", desired, "-y"}) {
					t.Fatal(cmd.Args)
				}
				for name := range breakoutNames(p) {
					if err := db.Del(ctx, "PORT|"+name).Err(); err != nil {
						t.Fatal(err)
					}
				}
				for name, fields := range p.NativeModes[desired] {
					if err := db.HSet(ctx, "PORT|"+name, fields).Err(); err != nil {
						t.Fatal(err)
					}
				}
				return nil, db.HSet(ctx, "BREAKOUT_CFG|Ethernet0", "brkout_mode", desired).Err()
			}
			before, _, err := m.readBreakoutDB(ctx)
			if err != nil {
				t.Fatal(err)
			}
			journalPath := filepath.Join(m.networkJournalDir, "network.json")
			journal, err := os.ReadFile(journalPath)
			if err != nil {
				t.Fatal(err)
			}
			adopt := &agent.PortBreakoutRequest{Port: "Ethernet0", Mode: mode, ChildAdminState: "down", AdoptOnly: true}
			if got, st := m.ReconcilePortBreakout(ctx, adopt); st != nil || !got.PersistenceVerified || got.Pending || calls != 0 {
				t.Fatalf("equal-state adoption over confirmed Port records: %+v %+v calls=%d", got, st, calls)
			}
			// Pending no-op recovery must still use the exact recorded request,
			// even though it is compatible with the confirmed typed owner.
			// A healthy confirmed repeat is now read-only; actual saved drift
			// forces persistence repair and exercises the same Pending authority.
			savesBeforeRepeat := saves
			if got, st := m.ReconcilePortBreakout(ctx, adopt); st != nil || !got.PersistenceVerified || got.Pending || saves != savesBeforeRepeat {
				t.Fatalf("confirmed adoption repeated save: %+v %+v", got, st)
			}
			saved = []byte(`{"PORT":`)
			save := m.saveConfig
			m.saveConfig = func(context.Context) *agent.Status { return &agent.Status{Code: 500} }
			if got, st := m.ReconcilePortBreakout(ctx, adopt); st == nil || !got.Pending || calls != 0 {
				t.Fatalf("failed adoption save did not remain pending: %+v %+v", got, st)
			}
			changed := *adopt
			changed.AdoptOnly = false
			if got, st := m.ReconcilePortBreakout(ctx, &changed); st == nil || !got.Pending || calls != 0 {
				t.Fatalf("pending no-op accepted a different request: %+v %+v", got, st)
			}
			m.saveConfig = save
			if got, st := m.ReconcilePortBreakout(ctx, adopt); st != nil || got.Pending || !got.PersistenceVerified || calls != 0 {
				t.Fatalf("exact pending no-op recovery blocked: %+v %+v", got, st)
			}
			if after, _, err := m.readBreakoutDB(ctx); err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("matching adoption/recovery changed complete CONFIG_DB")
			}
			if !tc.absent {
				if got, st := m.SetInterfaceAdminStatus(ctx, &agent.Interface{Name: tc.port, AdminStatus: agent.StatusUp}); st != nil || !got.AdminPersistenceVerified {
					t.Fatalf("confirmed Port blocked ordinary admin: %+v %+v", got, st)
				}
			}
			savesBefore := saves
			if tc.orphan {
				// Reconstruct the writer from its persistent paths; no in-memory
				// ownership or surviving API declaration can supply this guard.
				m = &SonicAgent{networkJournalDir: m.networkJournalDir, breakoutJournalDir: m.breakoutJournalDir,
					clientPool: m.clientPool, resolveBreakout: m.resolveBreakout, validateBreakoutConfig: m.validateBreakoutConfig,
					linkByName: m.linkByName, runBreakout: m.runBreakout, saveConfig: m.saveConfig, readSavedPortConfig: m.readSavedPortConfig}
			}
			got, st := m.ReconcilePortBreakout(ctx, &agent.PortBreakoutRequest{Port: "Ethernet0", Mode: desired, ChildAdminState: "down"})
			if tc.unrelated {
				if st != nil || !got.PersistenceVerified || calls != 1 {
					t.Fatalf("unrelated Port record blocked transition: %+v %+v calls=%d", got, st, calls)
				}
			} else {
				if st == nil || got.Pending || calls != 0 || saves != savesBefore {
					t.Errorf("typed ownership allowed destructive transition: %+v %+v calls=%d saves=%d", got, st, calls, saves)
				}
				after, _, err := m.readBreakoutDB(ctx)
				if err != nil || !reflect.DeepEqual(before, after) {
					t.Error("blocked transition changed complete CONFIG_DB")
				}
			}
			if after, err := os.ReadFile(journalPath); err != nil || string(after) != string(journal) {
				t.Fatal("breakout rewrote or transferred confirmed/orphaned Port ownership")
			}
		})
	}
}
