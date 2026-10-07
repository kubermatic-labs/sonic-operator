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
	"testing/synctest"
	"time"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/vishvananda/netlink"
)

func breakoutFixture(t *testing.T) (*SonicAgent, *vlanChangeDB, *int, *int) {
	t.Helper()
	m, _, saves := newTestAgent(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	m.breakoutJournalDir = dir
	cap := &breakoutPlatform{Port: "Ethernet0", Lanes: "49,50,51,52", DefaultMode: "1x100G[40G]", Modes: map[string]vlanChangeDB{
		"1x100G[40G]": {"Ethernet0": {"lanes": "49,50,51,52", "speed": "100000", "alias": "Ethernet0", "index": "1", "subport": "0"}},
		"4x25G[10G]":  {},
	}}
	for i := range 4 {
		cap.Modes["4x25G[10G]"][fmt.Sprint("Ethernet", i)] = map[string]string{"lanes": fmt.Sprint(49 + i), "speed": "25000", "alias": fmt.Sprint("Ethernet", i), "index": "1", "subport": fmt.Sprint(i + 1)}
	}
	cap.NativeModes = map[string]vlanChangeDB{}
	for mode, ports := range cap.Modes {
		cap.NativeModes[mode] = cloneBreakoutDB(ports)
	}
	db := vlanChangeDB{
		"DEVICE_METADATA|localhost": {"platform": "test", "hwsku": "sku", "mac": "02:00:00:00:00:01"},
		"BREAKOUT_CFG|Ethernet0":    {"brkout_mode": "1x100G[40G]"},
		"PORT|Ethernet0":            {"lanes": "49,50,51,52", "speed": "100000", "alias": "my-port", "index": "1", "subport": "0", "admin_status": "up", "mtu": "9100", "description": "keep"},
		"PORT|Ethernet4":            {"lanes": "53,54,55,56", "speed": "100000", "admin_status": "up"},
	}
	m.resolveBreakout = func(context.Context, string, map[string]string) (*breakoutPlatform, error) { return cap, nil }
	m.validateBreakoutConfig = func(context.Context) error { return nil }
	m.breakoutSnapshot = func(context.Context) (vlanChangeDB, string, error) { return cloneBreakoutDB(db), "snapshot", nil }
	m.readSavedPortConfig = func() ([]byte, error) { return portConfigJSON(t, db), nil }
	m.breakoutCAS = func(_ context.Context, _ string, before, after vlanChangeDB) (bool, error) {
		for k, v := range before {
			if !reflect.DeepEqual(db[k], v) {
				return false, nil
			}
		}
		db = vlanAuthorityReplaceTarget(db, before, cloneBreakoutDB(after))
		return true, nil
	}
	m.verifyBreakoutRuntime = func(context.Context, *breakoutPlatform, vlanChangeDB) error { return nil }
	calls := 0
	m.runBreakout = func(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
		calls++
		want := []string{"config", "interface", "breakout", "Ethernet0", "4x25G[10G]", "-y"}
		if !reflect.DeepEqual(cmd.Args, want) || cmd.Stdin != nil || cmd.Dir == "" {
			t.Fatalf("unsafe command: %#v", cmd)
		}
		info, err := os.Stat(cmd.Dir)
		if err != nil || info.Mode().Perm() != 0700 {
			t.Fatalf("nonprivate command cwd: %v", err)
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 120*time.Second {
			t.Fatal("native command is not bounded")
		}
		data, err := os.ReadFile(filepath.Join(dir, "breakout.json"))
		if err != nil || !strings.Contains(string(data), `"pending":true`) {
			t.Fatal("CLI before durable intent")
		}
		for name := range cap.Modes["1x100G[40G]"] {
			delete(db, "PORT|"+name)
		}
		for name, fields := range cap.NativeModes["4x25G[10G]"] {
			db["PORT|"+name] = maps.Clone(fields)
		}
		db["BREAKOUT_CFG|Ethernet0"] = map[string]string{"brkout_mode": "4x25G[10G]"}
		return nil, nil
	}
	return m, &db, &calls, saves
}

func TestBreakoutExactNativeDefaults(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(fmt.Sprint("foreign=", foreign), func(t *testing.T) {
			m, db, calls, saves := breakoutFixture(t)
			p, _ := m.resolveBreakout(t.Context(), "Ethernet0", nil)
			for _, modes := range p.NativeModes {
				for _, f := range modes {
					f["admin_status"] = "down"
					f["dhcp_rate_limit"] = "300"
					f["role"] = "Ext"
				}
			}
			run := m.runBreakout
			m.runBreakout = func(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
				out, err := run(ctx, cmd)
				if foreign {
					(*db)["PORT|Ethernet1"]["role"] = "Int"
				}
				return out, err
			}
			got, s := m.ReconcilePortBreakout(t.Context(), splitRequest())
			if foreign {
				if s == nil || !got.Pending || *saves != 0 {
					t.Fatalf("foreign defaults accepted: %+v %+v", got, s)
				}
				return
			}
			if s != nil || !got.PersistenceVerified || *calls != 1 {
				t.Fatalf("native defaults wedged: %+v %+v", got, s)
			}
			for _, child := range got.Children {
				if (*db)["PORT|"+child.Name]["role"] != "Ext" {
					t.Fatal("modeled native default lost")
				}
			}
			// Defaults present on existing children must not prevent the next transition.
			if _, _, err := breakoutTargets(*db, p, agent.PortBreakoutRequest{Port: "Ethernet0", Mode: "1x100G[40G]", ChildAdminState: "down"}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBreakoutConfigurationVerificationIndependent(t *testing.T) {
	for _, tc := range []string{"runtime absent", "wrong lanes", "wrong speed", "wrong index", "wrong subport", "extra child", "unstable"} {
		t.Run(tc, func(t *testing.T) {
			m, db, _, _ := breakoutFixture(t)
			m.verifyBreakoutRuntime = func(context.Context, *breakoutPlatform, vlanChangeDB) error {
				if tc == "unstable" {
					(*db)["PORT|Ethernet0"]["speed"] = "1"
				}
				return fmt.Errorf("runtime absent")
			}
			switch tc {
			case "wrong lanes":
				(*db)["PORT|Ethernet0"]["lanes"] = "52,51,50,49"
			case "wrong speed":
				(*db)["PORT|Ethernet0"]["speed"] = "25000"
			case "wrong index":
				(*db)["PORT|Ethernet0"]["index"] = "99"
			case "wrong subport":
				(*db)["PORT|Ethernet0"]["subport"] = "8"
			case "extra child":
				(*db)["PORT|Ethernet1"] = map[string]string{"lanes": "50", "speed": "25000"}
			}
			got, s := m.GetPortBreakout(t.Context(), "Ethernet0")
			if s != nil || got.ConfigurationVerified != (tc == "runtime absent") || got.RuntimeVerified || got.PersistenceVerified {
				t.Fatalf("config evidence: %+v %+v", got, s)
			}
		})
	}
}

func cloneBreakoutDB(db vlanChangeDB) vlanChangeDB {
	out := vlanChangeDB{}
	for k, v := range db {
		out[k] = maps.Clone(v)
	}
	return out
}

func splitRequest() *agent.PortBreakoutRequest {
	return &agent.PortBreakoutRequest{Port: "Ethernet0", Mode: "4x25G[10G]", ChildAdminState: "down"}
}

func TestBreakoutSplitAndNoop(t *testing.T) {
	m, db, calls, saves := breakoutFixture(t)
	unrelated := maps.Clone((*db)["PORT|Ethernet4"])
	got, status := m.ReconcilePortBreakout(t.Context(), splitRequest())
	if status != nil || !got.RuntimeVerified || !got.PersistenceVerified || got.Pending || len(got.Children) != 4 {
		t.Fatalf("split: %+v %+v", got, status)
	}
	for _, child := range got.Children {
		wantAdmin := "down"
		if child.Name == "Ethernet0" {
			wantAdmin = "up"
		}
		if child.AdminState != wantAdmin || child.MTU != "9100" {
			t.Fatalf("recreated child attributes: %+v", child)
		}
	}
	if (*db)["PORT|Ethernet0"]["alias"] != "my-port" || (*db)["PORT|Ethernet0"]["description"] != "keep" || !reflect.DeepEqual(unrelated, (*db)["PORT|Ethernet4"]) {
		t.Fatal("attributes lost or unrelated port modified")
	}
	(*db)["PORT|Ethernet0"]["admin_status"] = "up"
	got, status = m.ReconcilePortBreakout(t.Context(), splitRequest())
	if status != nil || *calls != 1 || *saves != 1 || !got.ConfigurationVerified || !got.RuntimeVerified || !got.PersistenceVerified || (*db)["PORT|Ethernet0"]["admin_status"] != "up" {
		t.Fatalf("confirmed no-op must freshly verify without resave/reset: %+v %+v %d %d", got, status, *calls, *saves)
	}
}

func TestBreakoutPreservesSurvivingAdmin(t *testing.T) {
	for _, tc := range []struct{ old, requested string }{{"up", "down"}, {"down", "up"}, {"", "up"}} {
		t.Run(tc.old+" to "+tc.requested, func(t *testing.T) {
			m, db, _, _ := breakoutFixture(t)
			(*db)["PORT|Ethernet0"]["admin_status"] = tc.old
			if tc.old == "" {
				delete((*db)["PORT|Ethernet0"], "admin_status")
			}
			r := splitRequest()
			r.ChildAdminState = tc.requested
			got, s := m.ReconcilePortBreakout(t.Context(), r)
			if s != nil {
				t.Fatal(s)
			}
			for _, child := range got.Children {
				want := tc.requested
				if child.Name == "Ethernet0" {
					want = tc.old
					if want == "" {
						want = "down"
					}
				}
				if child.AdminState != want {
					t.Fatalf("%s admin %s want %s", child.Name, child.AdminState, want)
				}
			}
		})
	}
}

func TestBreakoutUnknownOutcomeNeverReplays(t *testing.T) {
	for _, state := range []string{"before", "partial", "native"} {
		t.Run(state, func(t *testing.T) {
			m, db, calls, saves := breakoutFixture(t)
			run := m.runBreakout
			m.runBreakout = func(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
				if state == "native" {
					_, _ = run(ctx, cmd)
				} else {
					*calls++
					if state == "partial" {
						delete(*db, "PORT|Ethernet0")
					}
				}
				return nil, context.DeadlineExceeded
			}
			for range 2 {
				got, status := m.ReconcilePortBreakout(t.Context(), splitRequest())
				if status == nil || got == nil || !got.Pending || got.PersistenceVerified {
					t.Fatalf("unknown accepted: %+v %+v", got, status)
				}
			}
			if *calls != 1 || *saves != 0 {
				t.Fatalf("replayed/saved unknown outcome: %d %d", *calls, *saves)
			}
			if s := m.SaveConfig(t.Context()); s == nil {
				t.Fatal("ordinary save bypassed pending breakout")
			}
		})
	}
}

func TestBreakoutSaveRecovery(t *testing.T) {
	m, _, calls, _ := breakoutFixture(t)
	m.saveConfig = func(context.Context) *agent.Status { return &agent.Status{Code: 500, Message: "failed"} }
	got, status := m.ReconcilePortBreakout(t.Context(), splitRequest())
	if status == nil || !got.Pending || !got.ConfigurationVerified || !got.RuntimeVerified {
		t.Fatalf("save failure: %+v %+v", got, status)
	}
	// Discard volatile state as on restart, retaining only configured dependencies.
	m.configDirty = false
	m.saveConfig = func(context.Context) *agent.Status { return nil }
	got, status = m.ReconcilePortBreakout(t.Context(), splitRequest())
	if status != nil || !got.ConfigurationVerified || !got.PersistenceVerified || got.Pending || *calls != 1 {
		t.Fatalf("recovery: %+v %+v calls %d", got, status, *calls)
	}
}

func TestBreakoutPreflight(t *testing.T) {
	for _, tc := range []struct{ name, key, field, value string }{
		{"VLAN", "VLAN_MEMBER|Vlan100|Ethernet0", "tagging_mode", "tagged"},
		{"LAG", "PORTCHANNEL_MEMBER|PortChannel1|Ethernet0", "NULL", "NULL"},
		{"routed", "INTERFACE|Ethernet0|10.0.0.1/24", "NULL", "NULL"},
		{"ACL", "ACL_TABLE|test", "ports", "Ethernet0,Ethernet4"},
		{"future child", "OTHER|Ethernet1", "x", "x"},
		{"unknown", "OTHER|test", "ports", "all"},
		{"legacy VLAN selector", "VLAN|Vlan100", "members@", "all"},
		{"opaque VLAN member", "VLAN_MEMBER|Vlan100|all", "tagging_mode", "tagged"},
		{"unknown LAG selector", "PORTCHANNEL|PortChannel1", "members", "all"},
		{"alias reference", "OTHER|test", "target", "my-port"},
		{"overlap", "PORT|Ethernet99", "lanes", "49"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, db, calls, saves := breakoutFixture(t)
			(*db)[tc.key] = map[string]string{tc.field: tc.value}
			if _, status := m.ReconcilePortBreakout(t.Context(), splitRequest()); status == nil {
				t.Fatal("dependency accepted")
			}
			if *calls != 0 || *saves != 0 {
				t.Fatal("preflight mutated")
			}
		})
	}
}

func TestBreakoutValidation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		request *agent.PortBreakoutRequest
	}{
		{"nil", nil}, {"abstract", &agent.PortBreakoutRequest{Port: "eth0-0", Mode: "4x25G[10G]", ChildAdminState: "down"}},
		{"mode not exact", &agent.PortBreakoutRequest{Port: "Ethernet0", Mode: "4x25G", ChildAdminState: "down"}},
		{"state", &agent.PortBreakoutRequest{Port: "Ethernet0", Mode: "4x25G[10G]", ChildAdminState: "Up"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _, calls, _ := breakoutFixture(t)
			if _, s := m.ReconcilePortBreakout(t.Context(), tc.request); s == nil || *calls != 0 {
				t.Fatal("invalid request accepted")
			}
		})
	}
	m, _, calls, _ := breakoutFixture(t)
	m.breakoutJournalDir = ""
	if _, s := m.ReconcilePortBreakout(t.Context(), splitRequest()); s == nil || *calls != 0 {
		t.Fatal("write without journal")
	}
}

func TestBreakoutResolverCommand(t *testing.T) {
	m := &SonicAgent{}
	m.runBreakout = func(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
		if len(cmd.Args) != 7 || cmd.Args[0] != "python3" || cmd.Args[1] != "-c" || !strings.Contains(cmd.Args[2], "from portconfig import get_child_ports") || !strings.Contains(cmd.Args[2], "get_child_ports(port, mode, platform_file)") || cmd.Stdin != nil {
			t.Fatalf("resolver command: %v", cmd.Args)
		}
		if !strings.Contains(cmd.Args[2], "ConfigMgmtDPB.__new__(ConfigMgmtDPB)") || !strings.Contains(cmd.Args[2], "loadDefConfig=False") || !strings.Contains(cmd.Args[2], "ConfigDBConnector.typed_to_raw(fields)") || strings.Contains(cmd.Args[2], "cm.writeConfigDB(") || strings.Contains(cmd.Args[2], "cm.breakOutPort(") {
			t.Fatal("resolver must calculate only the in-memory native addition diff")
		}
		return json.Marshal(breakoutPlatform{Port: "Ethernet0", Lanes: "49", DefaultMode: "1x25G", Modes: map[string]vlanChangeDB{"1x25G": {"Ethernet0": {"lanes": "49", "speed": "25000"}}}, NativeModes: map[string]vlanChangeDB{"1x25G": {"Ethernet0": {"lanes": "49", "speed": "25000"}}}})
	}
	if _, err := m.nativeBreakoutPlatform(t.Context(), "Ethernet0", map[string]string{"platform": "platform", "hwsku": "sku"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.nativeBreakoutPlatform(t.Context(), "Ethernet0", map[string]string{"platform": "../escape", "hwsku": "sku"}); err == nil {
		t.Fatal("unsafe metadata path accepted")
	}
}

func TestBreakoutMerge(t *testing.T) {
	m, db, calls, _ := breakoutFixture(t)
	if _, status := m.ReconcilePortBreakout(t.Context(), splitRequest()); status != nil {
		t.Fatal(status)
	}
	(*db)["PORT|Ethernet0"]["admin_status"] = "down"
	cap, _ := m.resolveBreakout(t.Context(), "Ethernet0", nil)
	m.runBreakout = func(_ context.Context, cmd *exec.Cmd) ([]byte, error) {
		*calls++
		if cmd.Args[4] != "1x100G[40G]" {
			t.Fatal(cmd.Args)
		}
		for name := range cap.Modes["4x25G[10G]"] {
			delete(*db, "PORT|"+name)
		}
		(*db)["PORT|Ethernet0"] = maps.Clone(cap.Modes["1x100G[40G]"]["Ethernet0"])
		(*db)["BREAKOUT_CFG|Ethernet0"] = map[string]string{"brkout_mode": "1x100G[40G]"}
		return nil, nil
	}
	got, status := m.ReconcilePortBreakout(t.Context(), &agent.PortBreakoutRequest{Port: "Ethernet0", Mode: "1x100G[40G]", ChildAdminState: "up"})
	if status != nil || len(got.Children) != 1 || got.Children[0].AdminState != "down" || got.Children[0].MTU != "9100" || *calls != 2 {
		t.Fatalf("merge: %+v %+v", got, status)
	}
}

func TestBreakoutRuntimeEvidence(t *testing.T) {
	for _, tc := range []string{"exact carrier down", "wrong lanes", "wrong speed", "missing APPL", "stale APPL", "stale kernel", "missing kernel", "foreign lanes", "unknown netlink error"} {
		t.Run(tc, func(t *testing.T) {
			m, dbs, _ := newTestAgent(t)
			p := &breakoutPlatform{Port: "Ethernet0", Lanes: "49,50", DefaultMode: "1x50G", Modes: map[string]vlanChangeDB{
				"1x50G": {"Ethernet0": {"lanes": "49,50", "speed": "50000"}},
				"2x25G": {"Ethernet0": {"lanes": "49", "speed": "25000"}, "Ethernet1": {"lanes": "50", "speed": "25000"}},
			}}
			target := vlanChangeDB{"PORT|Ethernet0": {"lanes": "49,50", "speed": "50000", "admin_status": "up", "mtu": "9100"}}
			dbs["APPL_DB"].hashes["PORT_TABLE:Ethernet0"] = maps.Clone(target["PORT|Ethernet0"])
			dbs["APPL_DB"].hashes["PORT_TABLE:Ethernet0"]["oper_status"] = "down"
			m.linkByName = func(name string) (netlink.Link, error) {
				if tc == "unknown netlink error" && name == "Ethernet1" {
					return nil, fmt.Errorf("permission denied")
				}
				if name == "Ethernet1" && tc != "stale kernel" || name == "Ethernet0" && tc == "missing kernel" {
					return nil, netlink.LinkNotFoundError{}
				}
				return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}, nil
			}
			switch tc {
			case "wrong lanes":
				dbs["APPL_DB"].hashes["PORT_TABLE:Ethernet0"]["lanes"] = "50,49"
			case "wrong speed":
				dbs["APPL_DB"].hashes["PORT_TABLE:Ethernet0"]["speed"] = "25000"
			case "missing APPL":
				delete(dbs["APPL_DB"].hashes, "PORT_TABLE:Ethernet0")
			case "stale APPL":
				dbs["APPL_DB"].hashes["PORT_TABLE:Ethernet1"] = map[string]string{"lanes": "50", "speed": "25000"}
			case "foreign lanes":
				dbs["APPL_DB"].hashes["PORT_TABLE:Ethernet99"] = map[string]string{"lanes": "49", "speed": "25000"}
			}
			err := m.checkBreakoutRuntime(t.Context(), p, target)
			if (err == nil) != (tc == "exact carrier down") {
				t.Fatalf("runtime check: %v", err)
			}
		})
	}
}

func TestBreakoutRecoveryForeignOrChangedRequest(t *testing.T) {
	for _, tc := range []string{"foreign target", "foreign unrelated", "changed mode", "changed admin", "platform changed"} {
		t.Run(tc, func(t *testing.T) {
			m, db, calls, _ := breakoutFixture(t)
			m.saveConfig = func(context.Context) *agent.Status { return &agent.Status{Code: 500} }
			if _, s := m.ReconcilePortBreakout(t.Context(), splitRequest()); s == nil {
				t.Fatal("expected pending save")
			}
			request := splitRequest()
			switch tc {
			case "foreign target":
				(*db)["PORT|Ethernet0"]["description"] = "foreign"
			case "foreign unrelated":
				(*db)["PORT|Ethernet4"]["admin_status"] = "down"
			case "changed mode":
				request.Mode = "1x100G[40G]"
			case "changed admin":
				request.ChildAdminState = "up"
			case "platform changed":
				p, _ := m.resolveBreakout(t.Context(), "Ethernet0", nil)
				p.Modes["4x25G[10G]"]["Ethernet0"]["alias"] = "different"
				p.NativeModes["4x25G[10G]"]["Ethernet0"]["alias"] = "different"
			}
			m.saveConfig = func(context.Context) *agent.Status { t.Fatal("unsafe save"); return nil }
			got, status := m.ReconcilePortBreakout(t.Context(), request)
			if status == nil || !got.Pending || *calls != 1 {
				t.Fatalf("foreign recovery: %+v %+v", got, status)
			}
		})
	}
}

func TestBreakoutJournalsBlockBothDirections(t *testing.T) {
	m, _, calls, saves := breakoutFixture(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	m.journalDir = dir
	j, err := m.lockVLANAuthorityJournal(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	request := agent.VLANAuthorityRequest{OwnerID: "owner", VLAN: &agent.VLAN{ID: 100}}
	r := &vlanAuthorityRecord{Version: 1, VLANID: 100, OwnerID: "owner", Pending: &vlanAuthorityPending{Request: request, Before: vlanChangeDB{}, After: vlanAuthorityDesired(&request), PreHash: strings.Repeat("a", 64), PostHash: strings.Repeat("b", 64)}}
	if err := j.store(r); err != nil {
		t.Fatal(err)
	}
	j.close()
	if _, s := m.ReconcilePortBreakout(t.Context(), splitRequest()); s == nil || *calls != 0 || *saves != 0 {
		t.Fatal("breakout bypassed pending authority")
	}
	j, err = m.lockVLANAuthorityJournal(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := j.remove(100); err != nil {
		t.Fatal(err)
	}
	j.close()
	m.runBreakout = func(context.Context, *exec.Cmd) ([]byte, error) { return nil, fmt.Errorf("unknown") }
	if _, s := m.ReconcilePortBreakout(t.Context(), splitRequest()); s == nil {
		t.Fatal("expected unknown")
	}
	if _, s := m.ReconcileVLANAuthority(t.Context(), &request); s == nil || !strings.Contains(s.Message, "pending breakout") {
		t.Fatalf("authority bypassed pending breakout: %+v", s)
	}
	if _, s := m.SetInterfaceAdminStatus(t.Context(), &agent.Interface{Name: "eth1-0", AdminStatus: agent.StatusDown}); s == nil || !strings.Contains(s.Message, "pending breakout") {
		t.Fatalf("setter bypassed pending breakout: %+v", s)
	}
}

func TestBreakoutJournalCorruptionAndDurability(t *testing.T) {
	for _, tc := range []string{"corrupt", "public", "symlink", "fsync failure", "unknown record"} {
		t.Run(tc, func(t *testing.T) {
			m, _, calls, saves := breakoutFixture(t)
			if _, s := m.ReconcilePortBreakout(t.Context(), splitRequest()); s != nil {
				t.Fatal(s)
			}
			path := filepath.Join(m.breakoutJournalDir, "breakout.json")
			switch tc {
			case "unknown record":
				if err := os.Rename(path, filepath.Join(m.breakoutJournalDir, "foreign.json")); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "public":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".original", path); err != nil {
					t.Fatal(err)
				}
			case "fsync failure":
				m.journalSync = func(*os.File) error { return fmt.Errorf("fsync failed") }
			}
			if _, s := m.ReconcilePortBreakout(t.Context(), splitRequest()); s == nil {
				t.Fatal("unsafe journal allowed writes")
			}
			if s := m.SaveConfig(t.Context()); s == nil {
				t.Fatal("unsafe journal allowed ordinary save")
			}
			if *calls != 1 || *saves != 1 {
				t.Fatal("mutation after corrupt journal")
			}
		})
	}
}

func TestBreakoutNativeClosedStdin(t *testing.T) {
	if os.Getenv("SONIC_BREAKOUT_STDIN_TEST") == "1" {
		var b [1]byte
		if n, _ := os.Stdin.Read(b[:]); n != 0 {
			os.Exit(2)
		}
		fmt.Print("closed")
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestBreakoutNativeClosedStdin$")
	cmd.Env = append(os.Environ(), "SONIC_BREAKOUT_STDIN_TEST=1")
	m := &SonicAgent{}
	out, err := m.executeBreakout(ctx, cmd)
	if err != nil || !strings.Contains(string(out), "closed") {
		t.Fatalf("stdin: %v %s", err, out)
	}
}

func TestBreakoutConvergenceDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m, _, calls, saves := breakoutFixture(t)
		checks := 0
		m.verifyBreakoutRuntime = func(context.Context, *breakoutPlatform, vlanChangeDB) error {
			checks++
			if checks == 1 {
				return nil
			}
			return fmt.Errorf("not converged")
		}
		start := time.Now()
		got, status := m.ReconcilePortBreakout(t.Context(), splitRequest())
		if status == nil || !got.Pending || !got.ConfigurationVerified || got.RuntimeVerified || *calls != 1 || *saves != 0 || time.Since(start) != 30*time.Second {
			t.Fatalf("convergence deadline: %+v %+v %s", got, status, time.Since(start))
		}
	})
}

func TestBreakoutSaveFailureMustNotClaimStaleConfiguration(t *testing.T) {
	m, db, _, _ := breakoutFixture(t)
	m.saveConfig = func(context.Context) *agent.Status {
		(*db)["PORT|Ethernet0"]["lanes"] = "99"
		return &agent.Status{Code: 500}
	}
	got, s := m.ReconcilePortBreakout(t.Context(), splitRequest())
	if s == nil || got.ConfigurationVerified || got.RuntimeVerified || got.PersistenceVerified {
		t.Fatalf("stale evidence: %+v %+v", got, s)
	}
}

func TestBreakoutExactDesiredAfterLostReply(t *testing.T) {
	m, db, calls, saves := breakoutFixture(t)
	cap, _ := m.resolveBreakout(t.Context(), "Ethernet0", nil)
	_, desired, err := breakoutTargets(*db, cap, *splitRequest())
	if err != nil {
		t.Fatal(err)
	}
	run := m.runBreakout
	m.runBreakout = func(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
		_, _ = run(ctx, cmd)
		for key, fields := range desired {
			(*db)[key] = maps.Clone(fields)
		}
		return nil, fmt.Errorf("lost reply")
	}
	if _, s := m.ReconcilePortBreakout(t.Context(), splitRequest()); s == nil {
		t.Fatal("lost reply should remain pending")
	}
	got, s := m.ReconcilePortBreakout(t.Context(), splitRequest())
	if s != nil || !got.PersistenceVerified || *calls != 1 || *saves != 1 {
		t.Fatalf("exact desired recovery: %+v %+v", got, s)
	}
}

func TestBreakoutSerializationThroughSave(t *testing.T) {
	m, _, _, _ := breakoutFixture(t)
	saving := make(chan struct{})
	release := make(chan struct{})
	done := make(chan *agent.Status, 1)
	m.saveConfig = func(context.Context) *agent.Status { close(saving); <-release; return nil }
	go func() { _, s := m.ReconcilePortBreakout(t.Context(), splitRequest()); done <- s }()
	<-saving
	if m.configMutex.TryLock() {
		m.configMutex.Unlock()
		t.Fatal("mutex released before save completed")
	}
	// Another backend process cannot bypass the filesystem lock either.
	other := &SonicAgent{breakoutJournalDir: m.breakoutJournalDir}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if j, err := other.lockBreakoutJournal(ctx); err == nil {
		j.close()
		t.Fatal("journal lock released before save completed")
	}
	close(release)
	if s := <-done; s != nil {
		t.Fatal(s)
	}
}

func TestBreakoutObservationDoesNotSave(t *testing.T) {
	m, db, _, saves := breakoutFixture(t)
	got, status := m.GetPortBreakout(t.Context(), "Ethernet0")
	if status != nil || !got.RuntimeVerified || got.PersistenceVerified || *saves != 0 {
		t.Fatalf("unrecorded observation: %+v %+v", got, status)
	}
	if _, s := m.ReconcilePortBreakout(t.Context(), splitRequest()); s != nil {
		t.Fatal(s)
	}
	got, status = m.GetPortBreakout(t.Context(), "Ethernet0")
	if status != nil || !got.PersistenceVerified || *saves != 1 {
		t.Fatalf("recorded observation: %+v %+v", got, status)
	}
	(*db)["PORT|Ethernet4"]["admin_status"] = "down"
	got, status = m.GetPortBreakout(t.Context(), "Ethernet0")
	if status != nil || got.PersistenceVerified || *saves != 1 {
		t.Fatalf("stale persistence observation: %+v %+v", got, status)
	}
}

func TestBreakoutObservationRechecksSnapshot(t *testing.T) {
	m, db, _, _ := breakoutFixture(t)
	if _, s := m.ReconcilePortBreakout(t.Context(), splitRequest()); s != nil {
		t.Fatal(s)
	}
	m.verifyBreakoutRuntime = func(context.Context, *breakoutPlatform, vlanChangeDB) error {
		(*db)["PORT|Ethernet0"]["speed"] = "10000"
		return nil
	}
	got, s := m.GetPortBreakout(t.Context(), "Ethernet0")
	if s == nil && (got.RuntimeVerified || got.PersistenceVerified) {
		t.Fatalf("stale snapshot verified: %+v", got)
	}
}

func TestBreakoutNativeCancellation(t *testing.T) {
	if os.Getenv("SONIC_BREAKOUT_SLEEP_TEST") == "1" {
		time.Sleep(time.Minute)
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestBreakoutNativeCancellation$")
	cmd.Env = append(os.Environ(), "SONIC_BREAKOUT_SLEEP_TEST=1")
	m := &SonicAgent{}
	if _, err := m.executeBreakout(ctx, cmd); err == nil || ctx.Err() == nil {
		t.Fatalf("native cancellation not enforced: %v", err)
	}
}

func TestBreakoutPendingWriteFailureDoesNotDispatch(t *testing.T) {
	m, _, calls, saves := breakoutFixture(t)
	syncs := 0
	m.journalSync = func(f *os.File) error {
		syncs++
		if syncs == 2 {
			return fmt.Errorf("intent directory fsync failed")
		}
		return f.Sync()
	}
	got, s := m.ReconcilePortBreakout(t.Context(), splitRequest())
	if s == nil || !got.Pending || *calls != 0 || *saves != 0 {
		t.Fatalf("intent failure dispatched: %+v %+v", got, s)
	}
	m.journalSync = nil
	got, s = m.ReconcilePortBreakout(t.Context(), splitRequest())
	if s == nil || !got.Pending || *calls != 0 || *saves != 0 {
		t.Fatalf("uncertain intent blindly dispatched on retry: %+v %+v", got, s)
	}
}

func TestBreakoutNativeBudgetAndWorkdirCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := &SonicAgent{}
		cwd := ""
		m.runBreakout = func(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
			cwd = cmd.Dir
			<-ctx.Done()
			return nil, ctx.Err()
		}
		start := time.Now()
		if err := m.nativeBreakout(t.Context(), "Ethernet0", "4x25G[10G]"); err == nil || time.Since(start) != 120*time.Second {
			t.Fatalf("native budget: %v %s", err, time.Since(start))
		}
		if _, err := os.Stat(cwd); !os.IsNotExist(err) {
			t.Fatalf("temporary cwd leaked: %v", err)
		}
	})
}

func TestBreakoutJournalConfiguration(t *testing.T) {
	m := &SonicAgent{}
	for _, dir := range []string{"", "relative"} {
		if err := m.ConfigureBreakoutJournal(dir); err == nil {
			t.Fatal("unsafe journal configured")
		}
	}
	dir := filepath.Join(t.TempDir(), "private")
	err := m.ConfigureBreakoutJournal(dir)
	if os.Geteuid() != 0 {
		if err == nil {
			t.Fatal("non-root journal configured")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ConfigureBreakoutJournal(dir); err != nil {
		t.Fatal(err)
	}
	if err := m.ConfigureBreakoutJournal(filepath.Join(t.TempDir(), "other")); err == nil {
		t.Fatal("journal path changed")
	}
	if err := m.ConfigureVLANAuthorityJournal(dir); err == nil {
		t.Fatal("shared journal directories accepted")
	}
}

func TestBreakoutPlatformValidation(t *testing.T) {
	for _, tc := range []string{"overlap", "missing lane", "foreign lane", "speed", "missing default", "child name"} {
		t.Run(tc, func(t *testing.T) {
			m, _, _, _ := breakoutFixture(t)
			p, _ := m.resolveBreakout(t.Context(), "Ethernet0", nil)
			switch tc {
			case "overlap":
				p.Modes["4x25G[10G]"]["Ethernet1"]["lanes"] = "49"
			case "missing lane":
				delete(p.Modes["4x25G[10G]"], "Ethernet1")
			case "foreign lane":
				p.Modes["4x25G[10G]"]["Ethernet1"]["lanes"] = "99"
			case "speed":
				p.Modes["4x25G[10G]"]["Ethernet1"]["speed"] = "0"
			case "missing default":
				p.DefaultMode = "1x40G"
			case "child name":
				p.Modes["4x25G[10G]"]["eth1"] = p.Modes["4x25G[10G]"]["Ethernet1"]
				delete(p.Modes["4x25G[10G]"], "Ethernet1")
			}
			if err := validateBreakoutPlatform(p); err == nil {
				t.Fatal("unsafe platform capability accepted")
			}
		})
	}
}
