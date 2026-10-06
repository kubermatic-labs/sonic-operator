//go:build integration

// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"maps"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/redis/go-redis/v9"
	"github.com/vishvananda/netlink"
)

// Explicit opt-in only. Execute the literal resolver on the approved switch;
// its ConfigMgmt object has no DB connection and computes only an in-memory diff.
func TestBreakoutInstalledResolverReadOnly(t *testing.T) {
	if os.Getenv("SONIC_BREAKOUT_READONLY_RESOLVER") != "1" {
		t.Skip("requires explicit read-only switch inspection opt-in")
	}
	m := &SonicAgent{}
	m.runBreakout = func(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
		if cmd.Args[0] != "python3" || cmd.Args[1] != "-c" || cmd.Args[2] != breakoutResolverPython {
			t.Fatal("only fixed resolver allowed")
		}
		argv := make([]string, len(cmd.Args))
		for i, arg := range cmd.Args {
			argv[i] = "'" + strings.ReplaceAll(arg, "'", "'\"'\"'") + "'"
		}
		return exec.CommandContext(ctx, "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "admin@192.0.2.10", strings.Join(argv, " ")).Output()
	}
	start := time.Now()
	p, err := m.nativeBreakoutPlatform(t.Context(), "Ethernet0", map[string]string{"platform": "x86_64-dell_z9100_c2538-r0", "hwsku": "Force10-Z9100"})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("installed resolver completed in %s; exact native additions: %v", time.Since(start), p.NativeModes)
}

// Native sequencing is injected; every CONFIG_DB read/CAS and APPL_DB check
// runs against disposable Redis. No test can connect to a switch or host DB.
func TestBreakoutRedisRecovery(t *testing.T) {
	rdb := newVLANRedis(t)
	m, initial, _, _ := breakoutFixture(t)
	p, _ := m.resolveBreakout(t.Context(), "Ethernet0", nil)
	appl := redis.NewClient(&redis.Options{Addr: rdb.Options().Addr, DB: 0, MaxRetries: -1, ContextTimeoutEnabled: true})
	t.Cleanup(func() { _ = appl.Close() })
	m.clientPool = map[string]*redis.Client{"CONFIG_DB": rdb, "APPL_DB": appl}
	m.breakoutSnapshot, m.breakoutCAS, m.verifyBreakoutRuntime = nil, nil, nil
	for key, fields := range *initial {
		if err := rdb.HSet(t.Context(), key, fields).Err(); err != nil {
			t.Fatal(err)
		}
	}
	if err := rdb.Set(t.Context(), "CONFIG_DB_INITIALIZED", "1", 0).Err(); err != nil {
		t.Fatal(err)
	}
	if err := appl.HSet(t.Context(), "PORT_TABLE:Ethernet0", (*initial)["PORT|Ethernet0"]).Err(); err != nil {
		t.Fatal(err)
	}
	split := false
	m.linkByName = func(name string) (netlink.Link, error) {
		if name != "Ethernet0" && !split {
			return nil, netlink.LinkNotFoundError{}
		}
		return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}, nil
	}
	nativeCalls := 0
	m.runBreakout = func(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
		nativeCalls++
		if !reflect.DeepEqual(cmd.Args, []string{"config", "interface", "breakout", "Ethernet0", "4x25G[10G]", "-y"}) {
			t.Fatal(cmd.Args)
		}
		if err := rdb.Del(ctx, "PORT|Ethernet0").Err(); err != nil {
			t.Fatal(err)
		}
		for name, fields := range p.Modes["4x25G[10G]"] {
			if err := rdb.HSet(ctx, "PORT|"+name, fields).Err(); err != nil {
				t.Fatal(err)
			}
		}
		if err := rdb.HSet(ctx, "BREAKOUT_CFG|Ethernet0", "brkout_mode", "4x25G[10G]").Err(); err != nil {
			t.Fatal(err)
		}
		split = true
		return nil, nil
	}
	// Simulate orchagent consuming the exact post-CAS PORTs on first APPL read.
	appl.AddHook(&breakoutAPPLConsumer{rdb: rdb, appl: appl, platform: p})
	m.saveConfig = func(context.Context) *agent.Status { return &agent.Status{Code: 500} }
	got, status := m.ReconcilePortBreakout(t.Context(), splitRequest())
	if status == nil || !got.RuntimeVerified || !got.Pending {
		t.Fatalf("save failure: %+v %+v", got, status)
	}
	// A new backend object must recover from the durable journal alone.
	restarted := &SonicAgent{clientPool: m.clientPool, breakoutJournalDir: m.breakoutJournalDir, resolveBreakout: m.resolveBreakout, linkByName: m.linkByName,
		runBreakout: func(context.Context, *exec.Cmd) ([]byte, error) {
			t.Fatal("native replay after restart")
			return nil, nil
		},
		saveConfig: func(context.Context) *agent.Status { return nil },
	}
	got, status = restarted.ReconcilePortBreakout(t.Context(), splitRequest())
	if status != nil || !got.PersistenceVerified || got.Pending || nativeCalls != 1 {
		t.Fatalf("restart recovery: %+v %+v", got, status)
	}
	for _, child := range got.Children {
		wantAdmin := "down"
		if child.Name == "Ethernet0" {
			wantAdmin = "up"
		}
		if child.AdminState != wantAdmin || child.MTU != "9100" {
			t.Fatalf("attributes: %+v", child)
		}
	}
	unrelated, err := rdb.HGetAll(t.Context(), "PORT|Ethernet4").Result()
	if err != nil || !maps.Equal(unrelated, (*initial)["PORT|Ethernet4"]) {
		t.Fatalf("unrelated change: %v %v", unrelated, err)
	}
	// A foreign write invalidates an old full-snapshot CAS without changing PORT.
	before, raw, err := restarted.readBreakoutDB(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := rdb.HSet(t.Context(), "PORT|Ethernet4", "admin_status", "down").Err(); err != nil {
		t.Fatal(err)
	}
	target := breakoutTarget(before, p)
	after := cloneBreakoutDB(target)
	after["PORT|Ethernet0"]["admin_status"] = "up"
	applied, err := restarted.restoreBreakoutAttributes(t.Context(), raw, target, after)
	if err != nil || applied {
		t.Fatalf("stale CAS: %v %v", applied, err)
	}
}

type breakoutAPPLConsumer struct {
	rdb, appl *redis.Client
	platform  *breakoutPlatform
}

func (h *breakoutAPPLConsumer) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h *breakoutAPPLConsumer) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}
func (h *breakoutAPPLConsumer) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if cmd.Name() == "keys" {
			for name := range breakoutNames(h.platform) {
				fields, err := h.rdb.HGetAll(ctx, "PORT|"+name).Result()
				if err != nil {
					return err
				}
				if err := h.appl.Del(ctx, "PORT_TABLE:"+name).Err(); err != nil {
					return err
				}
				if len(fields) != 0 {
					if err := h.appl.HSet(ctx, "PORT_TABLE:"+name, fields).Err(); err != nil {
						return err
					}
				}
			}
		}
		return next(ctx, cmd)
	}
}
