//go:build integration

// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"reflect"
	"testing"

	"github.com/redis/go-redis/v9"
)

func TestVLANAuthorityInitializationMarker(t *testing.T) {
	t.Parallel()
	db := newVLANRedis(t)
	authoritySeed(t, db)
	if err := db.Set(t.Context(), "CONFIG_DB_INITIALIZED", "1", 0).Err(); err != nil {
		t.Fatal(err)
	}
	m, saves := authorityAgent(t, db, "")
	r := authorityRequest()
	authorityApprove(t, m, r)
	got := authorityOK(t, m, r)
	if !reflect.DeepEqual(got.VLAN, r.VLAN) || saves.Load() != 1 {
		t.Fatalf("reconcile=%+v saves=%d", got, saves.Load())
	}
	if value, err := db.Get(t.Context(), "CONFIG_DB_INITIALIZED").Result(); err != nil || value != "1" {
		t.Fatalf("marker=%q err=%v", value, err)
	}
	if ttl, err := db.Do(t.Context(), "PTTL", "CONFIG_DB_INITIALIZED").Int64(); err != nil || ttl != -1 {
		t.Fatalf("marker PTTL=%d err=%v", ttl, err)
	}
}

func TestVLANAuthorityInitializationMarkerRejectUnsafe(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		command []any
	}{
		{"zero", []any{"SET", "CONFIG_DB_INITIALIZED", "0"}},
		{"noncanonical value", []any{"SET", "CONFIG_DB_INITIALIZED", "01"}},
		{"hash sentinel collision", []any{"HSET", "CONFIG_DB_INITIALIZED", "__sonic_string__", "1"}},
		{"list", []any{"RPUSH", "CONFIG_DB_INITIALIZED", "1"}},
		{"expiration", []any{"SET", "CONFIG_DB_INITIALIZED", "1", "PX", "3600000"}},
		{"unrelated string", []any{"SET", "SECRET|opaque", "never-expose-this-secret"}},
		{"marker prefix", []any{"SET", "CONFIG_DB_INITIALIZED_EXTRA", "1"}},
		{"marker case", []any{"SET", "config_db_initialized", "1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			db := newVLANRedis(t)
			authoritySeed(t, db)
			m := &SonicAgent{clientPool: map[string]*redis.Client{"CONFIG_DB": db}}
			_, raw, err := m.vlanChangeSnapshot(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if err := db.Do(t.Context(), tc.command...).Err(); err != nil {
				t.Fatal(err)
			}
			if snapshot, exposed, err := m.vlanChangeSnapshot(t.Context()); err == nil || snapshot != nil || exposed != "" {
				t.Fatalf("unsafe snapshot=%v raw=%q err=%v", snapshot, exposed, err)
			}
			applied, err := m.casVLANChange(t.Context(), raw, nil, vlanChangeDB{"VLAN|Vlan200": {"vlanid": "200"}})
			if err == nil || applied {
				t.Fatalf("unsafe CAS applied=%v err=%v", applied, err)
			}
			if exists, err := db.Exists(t.Context(), "VLAN|Vlan200").Result(); err != nil || exists != 0 {
				t.Fatalf("rejected CAS wrote target: exists=%d err=%v", exists, err)
			}
		})
	}
}

func TestVLANAuthorityInitializationMarkerCAS(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		command []any
	}{
		{"unchanged", nil},
		{"changed value", []any{"SET", "CONFIG_DB_INITIALIZED", "0"}},
		{"changed type", []any{"EVAL", "redis.call('DEL', KEYS[1]); return redis.call('HSET', KEYS[1], '__sonic_string__', '1')", 1, "CONFIG_DB_INITIALIZED"}},
		{"added expiration", []any{"PEXPIRE", "CONFIG_DB_INITIALIZED", "3600000"}},
		{"removed", []any{"DEL", "CONFIG_DB_INITIALIZED"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			db := newVLANRedis(t)
			authoritySeed(t, db)
			if err := db.Set(t.Context(), "CONFIG_DB_INITIALIZED", "1", 0).Err(); err != nil {
				t.Fatal(err)
			}
			m := &SonicAgent{clientPool: map[string]*redis.Client{"CONFIG_DB": db}}
			snapshot, raw, err := m.vlanChangeSnapshot(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if tc.command != nil {
				if err := db.Do(t.Context(), tc.command...).Err(); err != nil {
					t.Fatal(err)
				}
			}
			from := vlanChangeTarget(snapshot, 100)
			applied, err := m.casVLANChange(t.Context(), raw, from, vlanAuthorityDesired(authorityRequest()))
			if tc.command == nil {
				if err != nil || !applied {
					t.Fatalf("stable marker CAS applied=%v err=%v", applied, err)
				}
				return
			}
			if applied {
				t.Fatal("CAS accepted changed marker")
			}
			for key, fields := range from {
				got, err := db.HGetAll(t.Context(), key).Result()
				if err != nil || !reflect.DeepEqual(got, fields) {
					t.Fatalf("rejected CAS changed %s: fields=%v err=%v", key, got, err)
				}
			}
			if exists, err := db.Exists(t.Context(), "VLAN_MEMBER|Vlan100|Ethernet8").Result(); err != nil || exists != 0 {
				t.Fatalf("rejected CAS added member: exists=%d err=%v", exists, err)
			}
		})
	}
}
