//go:build integration

// SPDX-License-Identifier: Apache-2.0
package sonic

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/redis/go-redis/v9"
)

type hostKernel struct {
	MAC       string
	Up        bool
	Addresses map[string]bool
	Rules     map[string]bool
	Routes    map[string]bool
}
type hostWorkerConfig struct{ Dir, Addr, Username, Password, Crash, Mode string }
type hostDeviceFixture struct {
	t          *testing.T
	dir, crash string
	agent      *SonicAgent
	native     *host.Native
}

func hostBefore() host.Management {
	return host.Management{Interface: "eth0", MAC: "02:00:00:00:00:11", Addresses: []host.Address{{Prefix: "10.0.0.11/24", Gateway: "10.0.0.1"}}}
}
func hostCandidate() host.Management {
	return host.Management{Interface: "eth0", MAC: "02:00:00:00:00:99", Addresses: []host.Address{{Prefix: "10.0.1.99/24", Gateway: "10.0.1.1"}}}
}
func hostRoute(prefix, gateway string) string { return prefix + "|" + gateway }
func hostDigest(s string) string              { v := sha256.Sum256([]byte(s)); return hex.EncodeToString(v[:]) }
func (f *hostDeviceFixture) file(path string) string {
	return filepath.Join(f.dir, "files", strings.TrimPrefix(path, "/"))
}
func (f *hostDeviceFixture) write(path string, data []byte) error {
	p := f.file(path)
	if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		return e
	}
	return os.WriteFile(p, data, 0600)
}
func (f *hostDeviceFixture) kernel() hostKernel {
	var k hostKernel
	b, e := os.ReadFile(filepath.Join(f.dir, "kernel.json"))
	if e != nil || json.Unmarshal(b, &k) != nil {
		f.t.Fatal("kernel fixture unavailable")
	}
	return k
}
func (f *hostDeviceFixture) putKernel(k hostKernel) {
	b, _ := json.Marshal(k)
	if e := os.WriteFile(filepath.Join(f.dir, "kernel.json"), b, 0600); e != nil {
		f.t.Fatal(e)
	}
}
func (f *hostDeviceFixture) stop(phase string) {
	if f.crash == phase {
		os.Exit(86)
	}
}
func (f *hostDeviceFixture) fullDB() ([]byte, error) {
	db, _, e := f.agent.vlanChangeSnapshot(context.Background())
	if e != nil {
		return nil, e
	}
	out := host.Database{}
	for key, v := range db {
		table, row, ok := strings.Cut(key, "|")
		if !ok {
			continue
		}
		if out[table] == nil {
			out[table] = map[string]map[string]string{}
		}
		out[table][row] = v
	}
	return json.Marshal(out)
}
func (f *hostDeviceFixture) run(_ context.Context, args []string, input []byte) ([]byte, error) {
	if args[0] == "sonic-cfggen" {
		if len(args) == 3 {
			return f.fullDB()
		}
		var raw map[string]json.RawMessage
		if json.Unmarshal(input, &raw) != nil {
			return nil, host.ErrNative
		}
		return append([]byte("native-interfaces:"), raw["MGMT_INTERFACE"]...), nil
	}
	if args[0] == "ping" {
		return nil, nil
	}
	if args[0] == "systemctl" {
		if args[1] == "is-active" {
			return []byte("active"), nil
		}
		if args[1] == "is-enabled" {
			return []byte("enabled"), nil
		}
		return nil, nil
	}
	if args[0] != "ip" {
		return nil, host.ErrNative
	}
	k := f.kernel()
	a := args[1:]
	if a[0] == "-4" || a[0] == "-6" {
		a = a[1:]
	}
	if a[0] == "-j" {
		switch a[1] {
		case "address":
			var info []map[string]any
			for prefix := range k.Addresses {
				p, _ := netip.ParsePrefix(prefix)
				info = append(info, map[string]any{"local": p.Addr().String(), "prefixlen": p.Bits(), "scope": "global"})
			}
			flags := []string{}
			if k.Up {
				flags = append(flags, "UP")
			}
			return json.Marshal([]any{map[string]any{"ifname": "eth0", "address": k.MAC, "flags": flags, "addr_info": info}})
		case "rule":
			var rows []any
			for source := range k.Rules {
				rows = append(rows, map[string]any{"priority": 32765, "src": source, "table": "default"})
			}
			return json.Marshal(rows)
		case "route":
			var rows []any
			exact := ""
			for i, s := range a {
				if s == "exact" {
					exact = a[i+1]
				}
			}
			for route := range k.Routes {
				prefix, gw, _ := strings.Cut(route, "|")
				if exact != "" && prefix != exact {
					continue
				}
				row := map[string]any{"dst": prefix, "table": "default"}
				if gw != "" {
					row["gateway"] = gw
					row["metric"] = 201
				}
				rows = append(rows, row)
			}
			return json.Marshal(rows)
		}
		return nil, host.ErrNative
	}
	value := func(key string) string {
		for i, s := range a {
			if s == key && i+1 < len(a) {
				return a[i+1]
			}
		}
		return ""
	}
	phase := ""
	switch a[0] {
	case "link":
		if a[len(a)-1] == "down" {
			k.Up = false
			phase = "mac-down"
		} else if v := value("address"); v != "" {
			k.MAC = v
			phase = "mac-address"
		} else {
			k.Up = true
			phase = "mac-up"
		}
	case "address":
		if a[1] == "replace" {
			k.Addresses[a[2]] = true
			phase = "address-add"
		} else {
			delete(k.Addresses, a[2])
			phase = "address-delete"
		}
	case "rule":
		source := value("from")
		if a[1] == "add" {
			k.Rules[source] = true
			phase = "rule-add"
		} else {
			delete(k.Rules, source)
			phase = "rule-delete"
		}
	case "route":
		key := hostRoute(a[2], value("via"))
		if a[1] == "replace" {
			if a[2] == "default" {
				for r := range k.Routes {
					if strings.HasPrefix(r, "default|") {
						delete(k.Routes, r)
					}
				}
			}
			k.Routes[key] = true
			phase = "route-add"
		} else {
			delete(k.Routes, key)
			phase = "route-delete"
		}
	default:
		return nil, host.ErrNative
	}
	f.putKernel(k)
	f.stop(phase)
	return nil, nil
}
func openHostDeviceFixture(t *testing.T, dir string, rdb *redis.Client, crash string) *hostDeviceFixture {
	f := &hostDeviceFixture{t: t, dir: dir, crash: crash}
	m := &SonicAgent{clientPool: map[string]*redis.Client{"CONFIG_DB": rdb}, hostJournalDir: filepath.Join(dir, "journal")}
	f.agent = m
	m.saveConfig = func(context.Context) *agent.Status {
		b, e := f.fullDB()
		if e == nil {
			e = f.write("/etc/sonic/config_db.json", b)
		}
		if e != nil {
			return &agent.Status{Code: 500}
		}
		f.stop("save")
		return nil
	}
	n := m.NewHostNative()
	f.native = n
	n.Run = f.run
	n.ReadFile = func(path string) ([]byte, error) { return os.ReadFile(f.file(path)) }
	n.WriteFile = func(path string, b []byte, _ os.FileMode) error {
		if e := f.write(path, b); e != nil {
			return e
		}
		if path == "/etc/network/interfaces" {
			f.stop("interfaces-file")
		}
		if path == "/etc/sonic/sonic-operator-management.json" {
			f.stop("boot-file")
		}
		return nil
	}
	cas := n.CAS
	n.CAS = func(ctx context.Context, before, after host.Database) error {
		if e := cas(ctx, before, after); e != nil {
			return e
		}
		f.stop("rollback-cas")
		return nil
	}
	return f
}
func seedHostDeviceFixture(t *testing.T, rdb *redis.Client) *hostDeviceFixture {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	if e := os.Mkdir(filepath.Join(dir, "journal"), 0700); e != nil {
		t.Fatal(e)
	}
	f := openHostDeviceFixture(t, dir, rdb, "")
	m := hostCandidate()
	_ = rdb.HSet(t.Context(), "MGMT_INTERFACE|eth0|"+m.Addresses[0].Prefix, "gwaddr", m.Addresses[0].Gateway).Err()
	_ = rdb.HSet(t.Context(), "MGMT_INTERFACE|eth1|192.0.2.2/24", "gwaddr", "192.0.2.1").Err()
	_ = rdb.HSet(t.Context(), "PORT|Ethernet0", "unmanaged", "preserve").Err()
	f.putKernel(hostKernel{MAC: m.MAC, Up: true, Addresses: map[string]bool{m.Addresses[0].Prefix: true}, Rules: map[string]bool{"10.0.1.99": true}, Routes: map[string]bool{hostRoute("10.0.1.0/24", ""): true, hostRoute("default", "10.0.1.1"): true, hostRoute("203.0.113.0/24", ""): true}})
	profile, _ := json.Marshal(host.NativeProfile{ImageSHA256: hostDigest("image"), InterfacesSHA256: hostDigest("template"), ConsumerSHA256: map[string]string{"interfaces-generator": hostDigest("generator")}})
	for path, b := range map[string][]byte{"/etc/sonic/sonic-operator-host-profile.json": profile, "/etc/sonic/sonic_version.yml": []byte("image"), "/usr/share/sonic/templates/interfaces.j2": []byte("template"), "/usr/bin/interfaces-config.sh": []byte("generator"), "/etc/sonic/sonic-operator-management.json": []byte(`{"mac":"02:00:00:00:00:99"}`), "/etc/systemd/system/interfaces-config.service.d/90-sonic-operator-management.conf": []byte("[Service]\nExecStartPost=/usr/local/sbin/sonic-operator-host-recovery --apply-boot-mac\n")} {
		if e := f.write(path, b); e != nil {
			t.Fatal(e)
		}
	}
	b, _ := f.fullDB()
	_ = f.write("/etc/sonic/config_db.json", b)
	var db map[string]json.RawMessage
	_ = json.Unmarshal(b, &db)
	_ = f.write("/etc/network/interfaces", append([]byte("native-interfaces:"), db["MGMT_INTERFACE"]...))
	pending := map[string]any{"management": map[string]string{"owner": "uid", "target": "switch", "revision": "1"}, "pending": map[string]any{"id": "transaction", "claim": map[string]string{"owner": "uid", "target": "switch", "revision": "1"}, "before": host.Snapshot{Management: hostBefore(), ActiveMAC: hostBefore().MAC}, "candidate": m, "created": time.Now().Add(-2 * time.Minute), "deadline": time.Now().Add(-time.Minute), "connection": "old", "rollbackRequired": true}}
	b, _ = json.Marshal(pending)
	if e := os.WriteFile(filepath.Join(dir, "journal/host.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
	return f
}

func TestHostNativeRollbackCrashRestart(t *testing.T) {
	for _, phase := range []string{"rollback-cas", "interfaces-file", "boot-file", "mac-down", "mac-address", "mac-up", "address-add", "route-add", "rule-add", "address-delete", "rule-delete", "route-delete", "save"} {
		t.Run(phase, func(t *testing.T) {
			rdb := newVLANRedis(t)
			f := seedHostDeviceFixture(t, rdb)
			options := rdb.Options()
			cfg := hostWorkerConfig{Dir: f.dir, Addr: options.Addr, Username: options.Username, Password: options.Password, Crash: phase}
			b, _ := json.Marshal(cfg)
			path := filepath.Join(f.dir, "worker.json")
			if e := os.WriteFile(path, b, 0600); e != nil {
				t.Fatal(e)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestHostNativeCrashWorker$")
			cmd.Env = append(os.Environ(), "SONIC_HOST_CRASH_WORKER="+path)
			err := cmd.Run()
			if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 86 {
				t.Fatalf("worker did not crash at %s", phase)
			}
			f = openHostDeviceFixture(t, f.dir, rdb, "")
			e, err := host.NewEngine(filepath.Join(f.dir, "journal"), f.native)
			if err != nil {
				t.Fatal(err)
			}
			if err = e.RecoverExpired(t.Context()); err != nil {
				t.Fatalf("new watchdog cannot finish interrupted %s restoration: %v", phase, err)
			}
			k := f.kernel()
			if k.Addresses[hostCandidate().Addresses[0].Prefix] || k.Rules["10.0.1.99"] || k.Routes[hostRoute("10.0.1.0/24", "")] {
				t.Fatal("candidate cleanup scope was lost")
			}
			if !k.Routes[hostRoute("203.0.113.0/24", "")] || rdb.HGet(t.Context(), "PORT|Ethernet0", "unmanaged").Val() != "preserve" {
				t.Fatal("unowned state changed")
			}
			if err = host.CheckPending(filepath.Join(f.dir, "journal")); err != nil {
				t.Fatal("verified restoration retained fence")
			}
		})
	}
}
func TestHostNativeCrashWorker(t *testing.T) {
	path := os.Getenv("SONIC_HOST_CRASH_WORKER")
	if path == "" {
		t.Skip("worker only")
	}
	b, e := os.ReadFile(path)
	var cfg hostWorkerConfig
	if e != nil || json.Unmarshal(b, &cfg) != nil {
		t.Fatal("worker config invalid")
	}
	rdb := redis.NewClient(&redis.Options{Addr: cfg.Addr, Username: cfg.Username, Password: cfg.Password, DB: 4, MaxRetries: -1})
	defer rdb.Close()
	f := openHostDeviceFixture(t, cfg.Dir, rdb, cfg.Crash)
	engine, e := host.NewEngine(filepath.Join(cfg.Dir, "journal"), f.native)
	if e != nil {
		t.Fatal(e)
	}
	if cfg.Mode == "ensure" {
		_, e = engine.Ensure(t.Context(), hostRepairRequest(), "original-rpc")
	} else {
		e = engine.RecoverExpired(t.Context())
	}
	if e != nil {
		t.Fatal(e)
	}
	t.Fatal("selected crash phase not reached")
}

func TestHostGatewaylessUsesActualRedisFieldDeltas(t *testing.T) {
	rdb := newVLANRedis(t)
	f := seedHostDeviceFixture(t, rdb)
	_ = os.Remove(filepath.Join(f.dir, "journal/host.json"))
	n := f.native
	original, err := n.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var last host.Management
	for _, m := range []host.Management{{Interface: "eth0", Addresses: []host.Address{{Prefix: "10.0.1.99/24", Gateway: "10.0.1.1"}, {Prefix: "10.0.2.11/24"}}}, {Interface: "eth0", Addresses: []host.Address{{Prefix: "10.0.1.99/24"}}}} {
		// Drive the production native planner/field-delta CAS through activation.
		snapshot, err := n.Snapshot(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if err = n.ApplyManagement(t.Context(), snapshot, m); err != nil {
			t.Fatal(err)
		}
		live, err := n.Load(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range m.Addresses {
			if a.Gateway == "" && !reflect.DeepEqual(live["MGMT_INTERFACE"]["eth0|"+a.Prefix], map[string]string{"NULL": "NULL"}) {
				t.Fatal("gateway-less row was not persisted by real Redis CAS")
			}
		}
		if _, err = n.Snapshot(t.Context()); err != nil {
			t.Fatal("gateway-less adoption cannot decode native row")
		}
		last = m
	}
	if err = n.RestoreManagement(t.Context(), host.RecoveryScope{Before: original, Candidate: last}); err != nil {
		t.Fatal("gateway-less rollback failed")
	}
	live, err := n.Snapshot(t.Context())
	if err != nil || !reflect.DeepEqual(live, original) {
		t.Fatal("gateway removal rollback did not restore original native inputs")
	}
}
