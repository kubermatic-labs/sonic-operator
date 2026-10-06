//go:build integration

// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/redis/go-redis/v9"
)

type failedAdminRollback struct{ fail bool }

func (h *failedAdminRollback) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h *failedAdminRollback) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}
func (h *failedAdminRollback) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if h.fail && cmd.Name() == "hset" {
			return fmt.Errorf("rollback unavailable")
		}
		return next(ctx, cmd)
	}
}

func TestAdminPersistenceRedisRestartRecovery(t *testing.T) {
	rdb := newVLANRedis(t)
	if err := rdb.HSet(t.Context(), "PORT|Ethernet0", "admin_status", "down", "alias", "keep").Err(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config_db.json")
	if err := os.WriteFile(path, []byte(`{"PORT":{"Ethernet0":{"admin_status":"down","alias":"keep"}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	hook := &failedAdminRollback{}
	rdb.AddHook(hook)
	read := func() ([]byte, error) { return os.ReadFile(path) }
	m := &SonicAgent{clientPool: map[string]*redis.Client{"CONFIG_DB": rdb, "APPL_DB": rdb}, readSavedPortConfig: read,
		saveConfig: func(context.Context) *agent.Status { hook.fail = true; return &agent.Status{Code: 500} },
	}
	r := &agent.Interface{Name: "Ethernet0", AdminStatus: agent.StatusUp}
	if _, st := m.SetInterfaceAdminStatus(t.Context(), r); st == nil {
		t.Fatal("failed save accepted")
	}
	if current := rdb.HGet(t.Context(), "PORT|Ethernet0", "admin_status").Val(); current != "up" {
		t.Fatal("expected desired live state after failed rollback")
	}
	hook.fail = false
	restarted := &SonicAgent{clientPool: m.clientPool, readSavedPortConfig: read, saveConfig: m.saveConfig}
	if _, st := restarted.SetInterfaceAdminStatus(t.Context(), r); st == nil {
		t.Fatal("restart accepted unsaved matching Redis")
	}
	restarted.saveConfig = func(ctx context.Context) *agent.Status {
		fields, err := rdb.HGetAll(ctx, "PORT|Ethernet0").Result()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, portConfigJSON(t, vlanChangeDB{"PORT|Ethernet0": fields}), 0600); err != nil {
			t.Fatal(err)
		}
		return nil
	}
	got, st := restarted.SetInterfaceAdminStatus(t.Context(), r)
	if st != nil || !got.AdminPersistenceVerified || got.AliasName != "keep" {
		t.Fatalf("recovery failed: %+v %+v", got, st)
	}
}
