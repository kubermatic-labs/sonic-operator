//go:build integration

// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestVLANAuthorityAPPLObservation(t *testing.T) {
	db := newVLANRedis(t)
	opts := *db.Options()
	opts.DB = 0
	app := redis.NewClient(&opts)
	t.Cleanup(func() { _ = app.Close() })
	m := &SonicAgent{clientPool: map[string]*redis.Client{"APPL_DB": app}}
	target := vlanChangeDB{"VLAN|Vlan100": {"vlanid": "100"}, "VLAN_MEMBER|Vlan100|Ethernet0": {"tagging_mode": "untagged"}}
	for _, name := range []string{"missing parent", "missing member", "wrong mode", "extra member", "wrong type", "wrong parent type", "converged", "deleted", "stale deleted member", "stale deleted parent"} {
		t.Run(name, func(t *testing.T) {
			if err := app.FlushDB(t.Context()).Err(); err != nil {
				t.Fatal(err)
			}
			want := target
			if err := app.HSet(t.Context(), "VLAN_TABLE:Vlan100", "mtu", "9100", "admin_status", "up").Err(); err != nil {
				t.Fatal(err)
			}
			if err := app.HSet(t.Context(), "VLAN_MEMBER_TABLE:Vlan100:Ethernet0", "tagging_mode", "untagged").Err(); err != nil {
				t.Fatal(err)
			}
			var err error
			switch name {
			case "missing parent":
				err = app.Del(t.Context(), "VLAN_TABLE:Vlan100").Err()
			case "missing member":
				err = app.Del(t.Context(), "VLAN_MEMBER_TABLE:Vlan100:Ethernet0").Err()
			case "wrong mode":
				err = app.HSet(t.Context(), "VLAN_MEMBER_TABLE:Vlan100:Ethernet0", "tagging_mode", "tagged").Err()
			case "extra member":
				err = app.HSet(t.Context(), "VLAN_MEMBER_TABLE:Vlan100:Ethernet4", "tagging_mode", "tagged").Err()
			case "wrong type":
				err = app.Set(t.Context(), "VLAN_MEMBER_TABLE:Vlan100:Ethernet0", "opaque", 0).Err()
			case "wrong parent type":
				err = app.Set(t.Context(), "VLAN_TABLE:Vlan100", "opaque", 0).Err()
			case "deleted":
				want = vlanChangeDB{}
				err = app.FlushDB(t.Context()).Err()
			case "stale deleted member":
				want = vlanChangeDB{}
				err = app.Del(t.Context(), "VLAN_TABLE:Vlan100").Err()
			case "stale deleted parent":
				want = vlanChangeDB{}
				err = app.Del(t.Context(), "VLAN_MEMBER_TABLE:Vlan100:Ethernet0").Err()
			}
			if err != nil {
				t.Fatal(err)
			}
			// A similarly named VLAN must not enter this target's membership.
			if err := app.HSet(t.Context(), "VLAN_MEMBER_TABLE:Vlan1000:Ethernet0", "tagging_mode", "tagged").Err(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			err = m.checkVLANAuthorityRuntime(ctx, 100, want)
			if (err == nil) != (name == "converged" || name == "deleted") {
				t.Fatalf("verification: %v", err)
			}
		})
	}
}

func TestVLANAuthorityLostStagedReplyRecovery(t *testing.T) {
	for _, name := range []string{"removal", "add"} {
		t.Run(name, func(t *testing.T) {
			db := newVLANRedis(t)
			authoritySeed(t, db)
			m, saves := authorityAgent(t, db, "")
			r := authorityRequest()
			authorityApprove(t, m, r)
			client := redis.NewClient(db.Options())
			t.Cleanup(func() { _ = client.Close() })
			calls := 0
			client.AddHook(&authorityRedisHook{after: func() error {
				calls++
				if (name == "removal" && calls == 1) || (name == "add" && calls == 2) {
					return errors.New("lost staged reply")
				}
				return nil
			}})
			m.clientPool["CONFIG_DB"] = client
			got, status := m.ReconcileVLANAuthority(t.Context(), r)
			if status == nil || got.PersistenceVerified || saves.Load() != 0 {
				t.Fatalf("lost reply accepted: %+v %v", got, status)
			}
			restarted, saves := authorityAgent(t, db, m.journalDir)
			replays := 0
			resume := redis.NewClient(db.Options())
			t.Cleanup(func() { _ = resume.Close() })
			resume.AddHook(&authorityRedisHook{before: func(context.Context) { replays++ }})
			restarted.clientPool["CONFIG_DB"] = resume
			authorityOK(t, restarted, r)
			want := 0
			if name == "removal" {
				want = 1
			}
			if replays != want || saves.Load() != 1 {
				t.Fatalf("CAS replays=%d want=%d saves=%d", replays, want, saves.Load())
			}
		})
	}
}

func TestVLANAuthorityStaleConfirmedAPPL(t *testing.T) {
	db := newVLANRedis(t)
	authoritySeed(t, db)
	m, saves := authorityAgent(t, db, "")
	r := authorityRequest()
	authorityApprove(t, m, r)
	authorityOK(t, m, r)
	app := m.clientPool["APPL_DB"]
	if err := app.HSet(t.Context(), "VLAN_MEMBER_TABLE:Vlan100:Ethernet4", "tagging_mode", "tagged").Err(); err != nil {
		t.Fatal(err)
	}
	got, status := m.GetVLANAuthority(t.Context(), 100)
	if status != nil || got.RuntimeVerified || got.PersistenceVerified {
		t.Fatalf("false confirmed read: %+v %v", got, status)
	}
	got, status = m.ReconcileVLANAuthority(t.Context(), r)
	if status == nil || got.RuntimeVerified || got.PersistenceVerified || saves.Load() != 1 {
		t.Fatalf("false noop: %+v %v", got, status)
	}
	// Supported cleanup is an explicit owned Delete, not hidden live repair.
	r.Delete = true
	authorityOK(t, m, r)
	if saves.Load() != 2 {
		t.Fatal("delete not saved")
	}
}
