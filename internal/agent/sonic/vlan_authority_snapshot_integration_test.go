//go:build integration

// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"maps"
	"reflect"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/redis/go-redis/v9"
)

func authorityMetadataSeed(t *testing.T, db *redis.Client) vlanChangeDB {
	t.Helper()
	fixture := vlanAuthorityMetadataFixture()
	for key, fields := range fixture {
		if err := db.HSet(t.Context(), key, fields).Err(); err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}

func TestVLANAuthorityMetadataLifecycle(t *testing.T) {
	t.Parallel()
	db := newVLANRedis(t)
	fixture := authorityMetadataSeed(t, db)
	m, saves := authorityAgent(t, db, "")
	r := &agent.VLANAuthorityRequest{OwnerID: "new", VLAN: &agent.VLAN{ID: 100}}
	for i, step := range []struct {
		name    string
		members []agent.VLANMember
		delete  bool
	}{
		{"create", []agent.VLANMember{{InterfaceName: "Ethernet0", TaggingMode: "untagged"}, {InterfaceName: "Ethernet4", TaggingMode: "tagged"}}, false},
		{"migrate", []agent.VLANMember{{InterfaceName: "Ethernet0", TaggingMode: "tagged"}, {InterfaceName: "Ethernet4", TaggingMode: "untagged"}}, false},
		{"prune", []agent.VLANMember{{InterfaceName: "Ethernet4", TaggingMode: "untagged"}}, false},
		{"delete", nil, true},
	} {
		// These are successive revisions of one owned VLAN, not independent tests.
		r.VLAN.Members, r.Delete = step.members, step.delete
		got := authorityOK(t, m, r)
		if (!step.delete && !reflect.DeepEqual(got.VLAN, r.VLAN)) || (step.delete && got.VLAN != nil) {
			t.Fatalf("%s: result=%+v", step.name, got)
		}
		want := maps.Clone(fixture)
		maps.Copy(want, vlanAuthorityDesired(r))
		snapshot, _, err := m.vlanChangeSnapshot(t.Context())
		if err != nil || !reflect.DeepEqual(snapshot, want) {
			t.Fatalf("%s: snapshot=%v want=%v err=%v", step.name, snapshot, want, err)
		}
		if saves.Load() != int32(i+1) {
			t.Fatalf("%s: saves=%d", step.name, saves.Load())
		}
	}
}

func TestVLANAuthorityMetadataRejectUnsafe(t *testing.T) {
	t.Parallel()
	for _, tc := range vlanAuthorityUnsafeMetadataCases() {
		t.Run(tc.name, func(t *testing.T) {
			db := newVLANRedis(t)
			authorityMetadataSeed(t, db)
			if err := db.Del(t.Context(), tc.key).Err(); err != nil {
				t.Fatal(err)
			}
			if err := db.HSet(t.Context(), tc.key, tc.fields).Err(); err != nil {
				t.Fatal(err)
			}
			m, saves := authorityAgent(t, db, "")
			before, _, err := m.vlanChangeSnapshot(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			r := &agent.VLANAuthorityRequest{OwnerID: "new", VLAN: &agent.VLAN{ID: 100, Members: []agent.VLANMember{{InterfaceName: "Ethernet0", TaggingMode: "untagged"}}}}
			if _, status := m.ReconcileVLANAuthority(t.Context(), r); status == nil {
				t.Fatal("unsafe write accepted")
			}
			after, _, err := m.vlanChangeSnapshot(t.Context())
			if err != nil || !reflect.DeepEqual(before, after) || saves.Load() != 0 {
				t.Fatalf("refused operation changed CONFIG_DB or saved: before=%v after=%v saves=%d err=%v", before, after, saves.Load(), err)
			}
		})
	}
}

func TestVLANAuthorityMetadataCAS(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		command []any
	}{
		{"SAI level", []any{"HSET", "LOGGER|SAI_API_VLAN", "LOGLEVEL", "SAI_LOG_LEVEL_DEBUG"}},
		{"daemon output", []any{"HSET", "LOGGER|vlanmgrd", "LOGOUTPUT", "STDERR"}},
		{"manual refresh changed", []any{"HSET", "LOGGER|xcvrd", "require_manual_refresh", "false"}},
		{"manual refresh removed", []any{"HDEL", "LOGGER|CmisManagerTask", "require_manual_refresh"}},
		{"manual refresh added", []any{"HSET", "LOGGER|vlanmgrd", "require_manual_refresh", "true"}},
		{"breakout mode", []any{"HSET", "BREAKOUT_CFG|Ethernet0", "brkout_mode", "4x25G"}},
		{"other breakout mode", []any{"HSET", "BREAKOUT_CFG|Ethernet4", "brkout_mode", "1x40G"}},
		{"removed logger", []any{"DEL", "LOGGER|SAI_API_VLAN"}},
		{"removed breakout", []any{"DEL", "BREAKOUT_CFG|Ethernet4"}},
		{"added logger", []any{"HSET", "LOGGER|orchagent", "LOGLEVEL", "NOTICE"}},
		{"added breakout", []any{"HSET", "BREAKOUT_CFG|Ethernet8", "brkout_mode", "1x100G"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			db := newVLANRedis(t)
			authorityMetadataSeed(t, db)
			m, saves := authorityAgent(t, db, "")
			r := &agent.VLANAuthorityRequest{OwnerID: "new", VLAN: &agent.VLAN{ID: 100, Members: []agent.VLANMember{{InterfaceName: "Ethernet0", TaggingMode: "untagged"}}}}
			authorityOK(t, m, r)
			before, raw, err := m.vlanChangeSnapshot(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if err := db.Do(t.Context(), tc.command...).Err(); err != nil {
				t.Fatal(err)
			}
			changed, _, err := m.vlanChangeSnapshot(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if vlanAuthorityHash(before) == vlanAuthorityHash(changed) || vlanAuthorityDigest(before, 100) == vlanAuthorityDigest(changed, 100) {
				t.Fatal("metadata change omitted from fingerprint or adoption digest")
			}
			got, status := m.GetVLANAuthority(t.Context(), 100)
			if status != nil || !got.RuntimeVerified || got.PersistenceVerified {
				t.Fatalf("metadata drift: result=%+v status=%v", got, status)
			}
			r.Delete = true
			applied, err := m.casVLANChange(t.Context(), raw, vlanChangeTarget(before, 100), vlanAuthorityDesired(r))
			if err != nil || applied {
				t.Fatalf("stale CAS: applied=%v err=%v", applied, err)
			}
			after, _, err := m.vlanChangeSnapshot(t.Context())
			if err != nil || !reflect.DeepEqual(after, changed) || saves.Load() != 1 {
				t.Fatalf("rejected CAS changed CONFIG_DB: after=%v want=%v saves=%d err=%v", after, changed, saves.Load(), err)
			}
		})
	}
}
