// SPDX-License-Identifier: Apache-2.0
package sonic

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
)

func TestHostAdapterRejectsUnallowlistedDatabaseChanges(t *testing.T) {
	before := host.Database{"MGMT_INTERFACE": {"eth0|10.0.0.11/24": {"gwaddr": "10.0.0.1"}}}
	for _, after := range []host.Database{{"PORT": {"Ethernet0": {"admin_status": "down"}}}, {"MGMT_PORT": {"eth0": {"admin_status": "down"}}}, {"MGMT_INTERFACE": {"eth1|10.0.0.99/24": {"gwaddr": "10.0.0.1"}}}} {
		if _, _, err := hostChanges(before, after); err == nil {
			t.Fatal("unallowlisted write accepted")
		}
	}
}

func TestHostPendingBlocksOrdinaryConfigSaves(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	if err := os.WriteFile(filepath.Join(dir, "host.json"), []byte(`{"pending":{"id":"pending"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	m := &SonicAgent{}
	if err := m.ConfigureHostJournal(dir); err != nil {
		t.Fatal(err)
	}
	unlock, st := m.lockOrdinaryConfig(context.Background(), 0)
	if unlock != nil {
		unlock()
	}
	if st == nil || st.Code == 0 {
		t.Fatal("ordinary writer can strand management rollback behind new network work")
	}
}

func TestHostJournalRejectsNestedDependencyOrArtifactRoots(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "host")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, m := range []*SonicAgent{{networkJournalDir: root}, {artifactStateDir: root}, {breakoutJournalDir: filepath.Join(dir, "child")}} {
		if err := m.ConfigureHostJournal(dir); err == nil {
			t.Fatal("nested state ownership accepted")
		}
	}
}
