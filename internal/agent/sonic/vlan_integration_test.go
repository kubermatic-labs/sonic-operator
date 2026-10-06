//go:build integration

// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agenterrors "github.com/ironcore-dev/sonic-operator/internal/agent/errors"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/redis/go-redis/v9"
)

type vlanRedisHook struct {
	before func(context.Context)
	after  func() error
}

func (h *vlanRedisHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h *vlanRedisHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}
func (h *vlanRedisHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if cmd.Name() == "eval" && h.before != nil {
			h.before(ctx)
		}
		err := next(ctx, cmd)
		if cmd.Name() == "eval" && err == nil && h.after != nil {
			return h.after()
		}
		return err
	}
}

// Use a disposable real Redis so the atomicity tests exercise Redis itself,
// not a Go reimplementation of Lua or WATCH semantics. Never use a host DB.
func newVLANRedis(t *testing.T) *redis.Client {
	t.Helper()
	if server := os.Getenv("SONIC_TEST_REDIS_SERVER"); server != "" {
		return newLocalNetworkRedis(t, server)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "run", "--rm", "-d", "-p", "127.0.0.1::6379", "redis:7-alpine", "redis-server", "--save", "", "--appendonly", "no").CombinedOutput()
	if err != nil {
		t.Fatalf("start disposable Redis (integration tests require Docker): %v: %s", err, out)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(ctx, "docker", "stop", id).CombinedOutput(); err != nil {
			t.Errorf("stop Redis %s: %v: %s", id, err, out)
		}
	})
	out, err = exec.CommandContext(ctx, "docker", "port", id, "6379/tcp").CombinedOutput()
	if err != nil {
		t.Fatalf("Redis port: %v: %s", err, out)
	}
	rdb := redis.NewClient(&redis.Options{Addr: strings.TrimSpace(string(out)), DB: 4, MaxRetries: -1, ContextTimeoutEnabled: true})
	t.Cleanup(func() { _ = rdb.Close() })
	for rdb.Ping(ctx).Err() != nil {
		if ctx.Err() != nil {
			t.Fatal("Redis did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return rdb
}

func TestVLANRedisBackend(t *testing.T) {
	rdb := newVLANRedis(t)
	newAgent := func(t *testing.T) (*SonicAgent, *atomic.Int32) {
		t.Helper()
		count := &atomic.Int32{}
		return &SonicAgent{clientPool: map[string]*redis.Client{"CONFIG_DB": rdb}, saveConfig: func(context.Context) *agent.Status { count.Add(1); return nil }}, count
	}
	seed := func(t *testing.T, values map[string]map[string]string) {
		t.Helper()
		if err := rdb.FlushDB(t.Context()).Err(); err != nil {
			t.Fatal(err)
		}
		for key, fields := range values {
			if err := rdb.HSet(t.Context(), key, fields).Err(); err != nil {
				t.Fatal(err)
			}
		}
	}
	snapshot := func(t *testing.T) map[string]string {
		t.Helper()
		keys, err := rdb.Keys(t.Context(), "*").Result()
		if err != nil {
			t.Fatal(err)
		}
		result := map[string]string{}
		for _, key := range keys {
			value, err := rdb.Dump(t.Context(), key).Result()
			if err != nil {
				t.Fatal(err)
			}
			result[key] = value
		}
		return result
	}
	member := func(name, mode string) agent.VLANMember {
		return agent.VLANMember{InterfaceName: name, TaggingMode: mode}
	}

	t.Run("observe existing VLAN100 and missing VLAN", func(t *testing.T) {
		seed(t, map[string]map[string]string{
			"VLAN|Vlan100":                    {"vlanid": "100", "mtu": "9100", "members@": "Ethernet0,Ethernet129"},
			"VLAN_MEMBER|Vlan100|Ethernet129": {"tagging_mode": "untagged", "extra": "keep"},
			"VLAN_MEMBER|Vlan100|Ethernet0":   {"tagging_mode": "untagged"},
			"VLAN_MEMBER|Vlan1000|Ethernet4":  {"tagging_mode": "tagged"},
		})
		m, saves := newAgent(t)
		before := snapshot(t)
		want := &agent.VLAN{ID: 100, Members: []agent.VLANMember{member("Ethernet0", "untagged"), member("Ethernet129", "untagged")}}
		got, status := m.GetVLAN(t.Context(), 100)
		if status != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("got=%+v status=%v want=%+v", got, status, want)
		}
		got, status = m.GetVLAN(t.Context(), 200)
		if got != nil || status == nil || status.Code != agenterrors.NOT_FOUND {
			t.Fatalf("missing: got=%+v status=%v", got, status)
		}
		if saves.Load() != 0 || !reflect.DeepEqual(before, snapshot(t)) {
			t.Fatal("observation mutated configuration")
		}
	})

	t.Run("create and additive ensure preserve all existing fields", func(t *testing.T) {
		seed(t, map[string]map[string]string{"PORT|Ethernet0": {"alias": "keep"}, "PORT|Ethernet129": {"admin_status": "up"}})
		m, saves := newAgent(t)
		input := &agent.VLAN{ID: 100, Members: []agent.VLANMember{member("Ethernet0", "untagged")}}
		if got, status := m.EnsureVLAN(t.Context(), input); status != nil || !reflect.DeepEqual(got, input) {
			t.Fatalf("create: got=%+v status=%v", got, status)
		}
		if err := rdb.HSet(t.Context(), "VLAN|Vlan100", "mtu", "9100", "members@", "Ethernet0").Err(); err != nil {
			t.Fatal(err)
		}
		if err := rdb.HSet(t.Context(), "VLAN_MEMBER|Vlan100|Ethernet0", "extra", "keep").Err(); err != nil {
			t.Fatal(err)
		}
		before := snapshot(t)
		input.Members = []agent.VLANMember{member("Ethernet129", "tagged")}
		got, status := m.EnsureVLAN(t.Context(), input)
		want := &agent.VLAN{ID: 100, Members: []agent.VLANMember{member("Ethernet0", "untagged"), member("Ethernet129", "tagged")}}
		if status != nil || !reflect.DeepEqual(got, want) || saves.Load() != 2 {
			t.Fatalf("add: got=%+v status=%v saves=%d", got, status, saves.Load())
		}
		after := snapshot(t)
		for key, value := range before {
			if after[key] != value {
				t.Errorf("existing key changed: %s", key)
			}
		}
		if len(after) != len(before)+1 {
			t.Fatalf("unexpected keys: %v", after)
		}
		if _, status := m.EnsureVLAN(t.Context(), &agent.VLAN{ID: 100}); status != nil {
			t.Fatal(status)
		}
		if !reflect.DeepEqual(after, snapshot(t)) || saves.Load() != 3 {
			t.Fatal("no-op must preserve Redis and confirm persistence")
		}
	})

	for _, tc := range []struct {
		name, key, mode string
		fields          map[string]string
	}{
		{name: "unknown port", key: "PORT|Ethernet4", fields: map[string]string{"alias": "other"}, mode: "tagged"},
		{name: "LAG member", key: "PORTCHANNEL_MEMBER|PortChannel1|Ethernet0", fields: map[string]string{"NULL": "NULL"}, mode: "tagged"},
		{name: "routed bare", key: "INTERFACE|Ethernet0", fields: map[string]string{"NULL": "NULL"}, mode: "tagged"},
		{name: "routed IPv4", key: "INTERFACE|Ethernet0|192.0.2.1/24", fields: map[string]string{"NULL": "NULL"}, mode: "tagged"},
		{name: "routed IPv6", key: "INTERFACE|Ethernet0|2001:db8::1/64", fields: map[string]string{"NULL": "NULL"}, mode: "untagged"},
		{name: "second untagged", key: "VLAN_MEMBER|Vlan200|Ethernet0", fields: map[string]string{"tagging_mode": "untagged"}, mode: "untagged"},
		{name: "orphan untagged", key: "VLAN_MEMBER|Vlan4095|Ethernet0", fields: map[string]string{"tagging_mode": "untagged"}, mode: "untagged"},
		{name: "tagging conflict", key: "VLAN_MEMBER|Vlan100|Ethernet0", fields: map[string]string{"tagging_mode": "untagged"}, mode: "tagged"},
		{name: "missing existing mode", key: "VLAN_MEMBER|Vlan100|Ethernet0", fields: map[string]string{"extra": "keep"}, mode: "tagged"},
		{name: "inconsistent vlanid", key: "VLAN|Vlan100", fields: map[string]string{"vlanid": "200"}, mode: "tagged"},
	} {
		t.Run("reject "+tc.name+" without partial writes", func(t *testing.T) {
			values := map[string]map[string]string{"PORT|Ethernet0": {"alias": "keep"}, "PORT|Ethernet129": {"alias": "keep"}}
			if tc.name == "unknown port" {
				delete(values, "PORT|Ethernet0")
			}
			values[tc.key] = tc.fields
			seed(t, values)
			m, saves := newAgent(t)
			before := snapshot(t)
			input := &agent.VLAN{ID: 100, Members: []agent.VLANMember{member("Ethernet129", "tagged"), member("Ethernet0", tc.mode)}}
			got, status := m.EnsureVLAN(t.Context(), input)
			if got != nil || status == nil || status.Code == 0 {
				t.Fatalf("got=%+v status=%v", got, status)
			}
			if saves.Load() != 0 || !reflect.DeepEqual(before, snapshot(t)) || m.configDirty {
				t.Fatal("rejection partially mutated configuration")
			}
		})
	}

	t.Run("save failure keeps applied configuration and retries after restart", func(t *testing.T) {
		seed(t, map[string]map[string]string{"PORT|Ethernet0": {"alias": "keep"}})
		m, _ := newAgent(t)
		input := &agent.VLAN{ID: 100, Members: []agent.VLANMember{member("Ethernet0", "untagged")}}
		m.saveConfig = func(context.Context) *agent.Status {
			return agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, "D-Bus reply lost")
		}
		_, status := m.EnsureVLAN(t.Context(), input)
		if status == nil || !strings.Contains(status.Message, "uncertain") || !m.configDirty {
			t.Fatalf("status=%v dirty=%v", status, m.configDirty)
		}
		got, status := m.GetVLAN(t.Context(), 100)
		if status != nil || !reflect.DeepEqual(got, input) {
			t.Fatalf("applied configuration rolled back: %+v %v", got, status)
		}
		before := snapshot(t)
		if _, status := m.EnsureVLAN(t.Context(), input); status == nil {
			t.Fatal("dirty no-op concealed save failure")
		}
		m, saves := newAgent(t)
		if _, status := m.EnsureVLAN(t.Context(), input); status != nil || saves.Load() != 1 || m.configDirty {
			t.Fatalf("restart retry: status=%v saves=%d dirty=%v", status, saves.Load(), m.configDirty)
		}
		if !reflect.DeepEqual(before, snapshot(t)) {
			t.Fatal("persistence retry changed Redis")
		}
	})

	t.Run("concurrent untagged additions across agent instances", func(t *testing.T) {
		seed(t, map[string]map[string]string{"PORT|Ethernet0": {"alias": "keep"}})
		const count = 20
		var wg sync.WaitGroup
		var successes atomic.Int32
		start := make(chan struct{})
		for i := range count {
			m, _ := newAgent(t)
			wg.Go(func() {
				<-start
				_, status := m.EnsureVLAN(t.Context(), &agent.VLAN{ID: uint32(i + 1), Members: []agent.VLANMember{member("Ethernet0", "untagged")}})
				if status == nil {
					successes.Add(1)
				}
			})
		}
		close(start)
		wg.Wait()
		if successes.Load() != 1 {
			t.Fatalf("successful untagged additions=%d, want 1", successes.Load())
		}
		keys, err := rdb.Keys(t.Context(), "VLAN_MEMBER|*|Ethernet0").Result()
		if err != nil || len(keys) != 1 {
			t.Fatalf("members=%v err=%v", keys, err)
		}
		keys, err = rdb.Keys(t.Context(), "VLAN|*").Result()
		if err != nil || len(keys) != 1 {
			t.Fatalf("rejected requests left VLANs: %v err=%v", keys, err)
		}
	})

	t.Run("IDs at bounds and multiple tagged VLANs", func(t *testing.T) {
		seed(t, map[string]map[string]string{"PORT|Ethernet0": {"alias": "keep"}})
		m, _ := newAgent(t)
		for _, id := range []uint32{1, 4094} {
			input := &agent.VLAN{ID: id, Members: []agent.VLANMember{member("Ethernet0", "tagged")}}
			if got, status := m.EnsureVLAN(t.Context(), input); status != nil || !reflect.DeepEqual(got, input) {
				t.Fatalf("id=%d got=%+v status=%v", id, got, status)
			}
		}
	})

	t.Run("wrong Redis type does not cause partial application", func(t *testing.T) {
		seed(t, map[string]map[string]string{"PORT|Ethernet0": {"alias": "keep"}, "PORT|Ethernet129": {"alias": "keep"}})
		if err := rdb.Set(t.Context(), "VLAN_MEMBER|Vlan100|Ethernet0", "not-a-hash", 0).Err(); err != nil {
			t.Fatal(err)
		}
		m, saves := newAgent(t)
		before := snapshot(t)
		_, status := m.EnsureVLAN(t.Context(), &agent.VLAN{ID: 100, Members: []agent.VLANMember{member("Ethernet129", "tagged"), member("Ethernet0", "tagged")}})
		if status == nil || saves.Load() != 0 || !reflect.DeepEqual(before, snapshot(t)) {
			t.Fatalf("partial write: status=%v saves=%d", status, saves.Load())
		}
	})

	t.Run("empty VLAN", func(t *testing.T) {
		seed(t, nil)
		m, _ := newAgent(t)
		got, status := m.EnsureVLAN(t.Context(), &agent.VLAN{ID: 100})
		if status != nil || got == nil || got.ID != 100 || len(got.Members) != 0 {
			t.Fatalf("got=%+v status=%v", got, status)
		}
		if value := rdb.HGet(t.Context(), "VLAN|Vlan100", "vlanid").Val(); value != fmt.Sprint(100) {
			t.Fatalf("vlanid=%q", value)
		}
	})

	for _, key := range []string{"PORTCHANNEL_MEMBER|PortChannel9|Ethernet0", "INTERFACE|Ethernet0", "INTERFACE|Ethernet0|192.0.2.1/24", "VLAN_MEMBER|Vlan200|Ethernet0"} {
		t.Run("external writer creates phantom "+key, func(t *testing.T) {
			seed(t, map[string]map[string]string{"PORT|Ethernet0": {"alias": "keep"}})
			m, saves := newAgent(t)
			client := redis.NewClient(rdb.Options())
			t.Cleanup(func() { _ = client.Close() })
			client.AddHook(&vlanRedisHook{before: func(ctx context.Context) {
				if err := rdb.HSet(ctx, key, "tagging_mode", "untagged").Err(); err != nil {
					t.Fatal(err)
				}
			}})
			m.clientPool["CONFIG_DB"] = client
			_, status := m.EnsureVLAN(t.Context(), &agent.VLAN{ID: 100, Members: []agent.VLANMember{member("Ethernet0", "untagged")}})
			if status == nil || saves.Load() != 0 {
				t.Fatalf("phantom ignored: status=%v saves=%d", status, saves.Load())
			}
			if n := rdb.Exists(t.Context(), "VLAN|Vlan100", "VLAN_MEMBER|Vlan100|Ethernet0").Val(); n != 0 {
				t.Fatal("unsafe partial configuration")
			}
		})
	}

	t.Run("lost Redis reply retries persistence without rolling back", func(t *testing.T) {
		seed(t, map[string]map[string]string{"PORT|Ethernet0": {"alias": "keep"}})
		m, saves := newAgent(t)
		client := redis.NewClient(rdb.Options())
		t.Cleanup(func() { _ = client.Close() })
		var calls atomic.Int32
		client.AddHook(&vlanRedisHook{after: func() error {
			if calls.Add(1) == 1 {
				return &net.OpError{Op: "read", Net: "tcp", Err: fmt.Errorf("reply lost after apply")}
			}
			return nil
		}})
		m.clientPool["CONFIG_DB"] = client
		input := &agent.VLAN{ID: 100, Members: []agent.VLANMember{member("Ethernet0", "tagged")}}
		_, status := m.EnsureVLAN(t.Context(), input)
		if status == nil || !strings.Contains(status.Message, "uncertain") || !m.configDirty || saves.Load() != 0 {
			t.Fatalf("lost reply status=%v dirty=%v saves=%d", status, m.configDirty, saves.Load())
		}
		if rdb.HGet(t.Context(), "VLAN_MEMBER|Vlan100|Ethernet0", "tagging_mode").Val() != "tagged" {
			t.Fatal("known-applied member removed")
		}
		before := snapshot(t)
		if _, status := m.EnsureVLAN(t.Context(), input); status != nil || saves.Load() != 1 || m.configDirty {
			t.Fatalf("retry status=%v dirty=%v saves=%d", status, m.configDirty, saves.Load())
		}
		if !reflect.DeepEqual(before, snapshot(t)) {
			t.Fatal("retry changed configuration")
		}
	})

	t.Run("canceled save and shared dirty state", func(t *testing.T) {
		seed(t, map[string]map[string]string{"PORT|Ethernet0": {"alias": "keep"}})
		m, _ := newAgent(t)
		input := &agent.VLAN{ID: 100, Members: []agent.VLANMember{member("Ethernet0", "untagged")}}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		m.saveConfig = func(context.Context) *agent.Status {
			cancel()
			return agenterrors.NewErrorStatus(agenterrors.SERVER_ERROR, "context canceled after save")
		}
		if _, status := m.EnsureVLAN(ctx, input); status == nil || !m.configDirty {
			t.Fatalf("status=%v dirty=%v", status, m.configDirty)
		}
		got, status := m.GetVLAN(t.Context(), 100)
		if status != nil || !reflect.DeepEqual(got, input) {
			t.Fatalf("canceled save rolled back VLAN: got=%+v status=%v", got, status)
		}
		var calls atomic.Int32
		m.saveConfig = func(context.Context) *agent.Status { calls.Add(1); return nil }
		if _, status := m.EnsureVLAN(t.Context(), input); status != nil || calls.Load() != 1 || m.configDirty {
			t.Fatalf("retry status=%v calls=%d dirty=%v", status, calls.Load(), m.configDirty)
		}
		m.configDirty = true // A previous non-VLAN setter's persistence failed.
		if _, status := m.EnsureVLAN(t.Context(), input); status != nil || calls.Load() != 2 || m.configDirty {
			t.Fatalf("shared dirty status=%v calls=%d dirty=%v", status, calls.Load(), m.configDirty)
		}
	})

	t.Run("concurrent same-agent additions and persistence are serialized", func(t *testing.T) {
		values := map[string]map[string]string{}
		const count = 20
		for i := range count {
			values[fmt.Sprintf("PORT|Ethernet%d", i)] = map[string]string{"alias": "keep"}
		}
		seed(t, values)
		m, _ := newAgent(t)
		var active, saves atomic.Int32
		m.saveConfig = func(context.Context) *agent.Status {
			if active.Add(1) != 1 {
				t.Error("concurrent SaveConfig calls")
			}
			saves.Add(1)
			active.Add(-1)
			return nil
		}
		var wg sync.WaitGroup
		for i := range count {
			wg.Go(func() {
				_, status := m.EnsureVLAN(t.Context(), &agent.VLAN{ID: 100, Members: []agent.VLANMember{member(fmt.Sprintf("Ethernet%d", i), "tagged")}})
				if status != nil {
					t.Error(status)
				}
			})
		}
		wg.Wait()
		got, status := m.GetVLAN(t.Context(), 100)
		if status != nil || got == nil || len(got.Members) != count || saves.Load() != count {
			t.Fatalf("got=%+v status=%v saves=%d", got, status, saves.Load())
		}
	})
}
