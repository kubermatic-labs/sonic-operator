// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

// A legacy writer may already have prepared a destructive transition over a
// confirmed Port. Upgrading must retain that pending record without modifying
// the target, replaying the CLI or advancing persistence through the conflict.
func TestBreakoutPendingTransitionTypedOwnership(t *testing.T) {
	m, db, calls, saves := breakoutFixture(t)
	m.saveConfig = func(context.Context) *agent.Status { *saves++; return &agent.Status{Code: 500} }
	request := splitRequest()
	if got, st := m.ReconcilePortBreakout(t.Context(), request); st == nil || !got.Pending || *calls != 1 {
		t.Fatalf("legacy pending fixture: %+v %+v", got, st)
	}
	m.networkJournalDir = t.TempDir()
	if err := os.Chmod(m.networkJournalDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.networkJournalDir, ".lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	j, err := m.lockNetworkJournal(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	err = storeNetworkJournal(j, &networkJournalState{Version: 1, Records: map[string]*networkRecord{
		"Port|Ethernet1": {Kind: "Port", OwnerID: "retained-owner", Fields: vlanChangeDB{"PORT|Ethernet1": {"speed": "25000"}},
			Fingerprint: vlanAuthorityHash(*db), PortLayout: networkPortLayout(*db, &networkPlan{Identity: "Port|Ethernet1"})},
	}})
	j.close()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(m.breakoutJournalDir, "breakout.json")
	beforeJournal, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	before := cloneBreakoutDB(*db)
	savesBefore := *saves
	m.saveConfig = func(context.Context) *agent.Status { *saves++; return nil }
	got, st := m.ReconcilePortBreakout(t.Context(), request)
	if st == nil || !got.Pending || !strings.Contains(got.Message, "typed ownership") || *calls != 1 || *saves != savesBefore {
		t.Errorf("pending destructive transition advanced through typed conflict: %+v %+v calls=%d saves=%d", got, st, *calls, *saves)
	}
	afterJournal, err := os.ReadFile(path)
	if err != nil || string(beforeJournal) != string(afterJournal) || !reflect.DeepEqual(before, *db) {
		t.Fatal("blocked recovery changed pending journal or complete CONFIG_DB")
	}
}
