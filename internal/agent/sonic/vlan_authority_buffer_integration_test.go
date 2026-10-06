//go:build integration

// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/redis/go-redis/v9"
)

func authorityBufferSeed(t *testing.T, db *redis.Client) vlanChangeDB {
	t.Helper()
	fixture := vlanAuthorityBufferFixture()
	for key, fields := range fixture {
		if err := db.HSet(t.Context(), key, fields).Err(); err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}

func TestVLANAuthorityBufferLifecycle(t *testing.T) {
	t.Parallel()
	db := newVLANRedis(t)
	fixture := authorityBufferSeed(t, db)
	m, saves := authorityAgent(t, db, "")
	r := &agent.VLANAuthorityRequest{OwnerID: "existing-vlan-cr-uid", VLAN: vlanChangeView(fixture, 100)}
	// Equal native state still requires explicit adoption approval.
	if _, status := m.ReconcileVLANAuthority(t.Context(), r); status == nil {
		t.Fatal("unapproved existing-state adoption accepted")
	}
	authorityApprove(t, m, r)
	authorityOK(t, m, r)
	before := vlanChangeTarget(fixture, 100)
	assertSnapshot := func(step string) {
		t.Helper()
		want := vlanAuthorityReplaceTarget(fixture, before, vlanAuthorityDesired(r))
		got, _, err := m.vlanChangeSnapshot(t.Context())
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("%s changed unrelated configuration or missed desired state: err=%v got=%v want=%v", step, err, got, want)
		}
	}
	assertSnapshot("exact adoption")
	if saves.Load() != 1 {
		t.Fatalf("adoption saves=%d", saves.Load())
	}
	// Restart retains ownership and confirms equal state without another save.
	m, saves = authorityAgent(t, db, m.journalDir)
	r.AdoptionDigest = ""
	authorityOK(t, m, r)
	if saves.Load() != 0 {
		t.Fatal("confirmed equal state saved again")
	}
	// Prove actual ongoing enforcement: repair drift despite independent QoS.
	if err := db.Del(t.Context(), "VLAN_MEMBER|Vlan100|Ethernet8").Err(); err != nil {
		t.Fatal(err)
	}
	observed, status := m.GetVLANAuthority(t.Context(), 100)
	if status != nil || observed.RuntimeVerified || observed.PersistenceVerified {
		t.Fatalf("drift reported verified: %+v status=%v", observed, status)
	}
	authorityOK(t, m, r)
	assertSnapshot("membership repair")
	// The existing staged writer must still enforce retags and pruning.
	for i := range r.VLAN.Members {
		if r.VLAN.Members[i].InterfaceName == "Ethernet8" {
			r.VLAN.Members[i].TaggingMode = "tagged"
		}
	}
	authorityOK(t, m, r)
	assertSnapshot("retag")
	r.VLAN.Members = []agent.VLANMember{{InterfaceName: "Ethernet120", TaggingMode: "untagged"}}
	authorityOK(t, m, r)
	assertSnapshot("prune")
	r.Delete = true
	authorityOK(t, m, r)
	assertSnapshot("delete")
	if saves.Load() != 4 {
		t.Fatalf("repair/retag/prune/delete saves=%d", saves.Load())
	}
	files, err := os.ReadDir(m.journalDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		data, err := os.ReadFile(filepath.Join(m.journalDir, file.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, unrelated := range []string{"BUFFER_", "PORT_QOS_MAP", "TC_TO_PRIORITY_GROUP_MAP", "PROVISIONING_LOSSY"} {
			if strings.Contains(string(data), unrelated) {
				t.Fatal("unrelated raw configuration journaled")
			}
		}
	}
}

func TestVLANAuthorityBufferRejectUnsafeLifecycle(t *testing.T) {
	t.Parallel()
	for _, tc := range vlanAuthorityUnsafeBufferCases() {
		t.Run(tc.name, func(t *testing.T) {
			db := newVLANRedis(t)
			fixture := authorityBufferSeed(t, db)
			// Replace, rather than merge, so missing mandatory fields are tested.
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
			r := &agent.VLANAuthorityRequest{OwnerID: "existing-vlan-cr-uid", VLAN: vlanChangeView(fixture, 100)}
			authorityApprove(t, m, r)
			// Also reject destructive membership pruning of a referenced old port.
			for _, prune := range []bool{false, true} {
				if prune {
					r.VLAN.Members = nil
				}
				if _, status := m.ReconcileVLANAuthority(t.Context(), r); status == nil {
					t.Fatal("unsafe adoption/prune accepted")
				}
			}
			after, _, err := m.vlanChangeSnapshot(t.Context())
			if err != nil || !reflect.DeepEqual(before, after) || saves.Load() != 0 {
				t.Fatalf("refused operation wrote CONFIG_DB or saved: err=%v saves=%d", err, saves.Load())
			}
			if _, err := os.Stat(filepath.Join(m.journalDir, vlanAuthorityFile(100))); !os.IsNotExist(err) {
				t.Fatalf("refused operation created owner/pending journal: %v", err)
			}
		})
	}
}

func TestVLANAuthorityBufferCAS(t *testing.T) {
	t.Parallel()
	for _, key := range []string{"BUFFER_PG|Ethernet8|0", "BUFFER_QUEUE|Ethernet8|0-2", "PORT_QOS_MAP|Ethernet8", "BUFFER_PROFILE|ingress_lossy_profile", "BUFFER_POOL|ingress_lossless_pool", "TC_TO_PRIORITY_GROUP_MAP|PROVISIONING_LOSSY"} {
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			db := newVLANRedis(t)
			fixture := authorityBufferSeed(t, db)
			m, saves := authorityAgent(t, db, "")
			r := &agent.VLANAuthorityRequest{OwnerID: "existing-vlan-cr-uid", VLAN: vlanChangeView(fixture, 100)}
			authorityApprove(t, m, r)
			authorityOK(t, m, r)
			before, raw, err := m.vlanChangeSnapshot(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if err := db.Del(t.Context(), key).Err(); err != nil {
				t.Fatal(err)
			}
			changed := maps.Clone(before)
			delete(changed, key)
			r.Delete = true
			applied, err := m.casVLANChange(t.Context(), raw, vlanChangeTarget(before, 100), vlanAuthorityDesired(r))
			if err != nil || applied {
				t.Fatalf("stale buffer snapshot CAS: applied=%v err=%v", applied, err)
			}
			after, _, err := m.vlanChangeSnapshot(t.Context())
			if err != nil || !reflect.DeepEqual(after, changed) || saves.Load() != 1 {
				t.Fatal("rejected CAS changed configuration or saved")
			}
		})
	}
}
