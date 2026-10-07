// SPDX-License-Identifier: Apache-2.0
package sonic

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"golang.org/x/sys/unix"
)

func TestArtifactFenceSerializesAndRejectsPendingNetworkRecovery(t *testing.T) {
	m := &SonicAgent{journalDir: t.TempDir(), breakoutJournalDir: t.TempDir(), networkJournalDir: t.TempDir()}
	f := &ArtifactWriterFence{agent: m}
	called := false
	for _, dir := range []string{m.journalDir, m.breakoutJournalDir, m.networkJournalDir} {
		if err := os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ".lock"), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.WithMutation(t.Context(), func() error {
		called = true
		for _, dir := range []string{m.journalDir, m.breakoutJournalDir, m.networkJournalDir} {
			lock, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_RDWR, 0600)
			if err != nil {
				t.Fatal(err)
			}
			err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB)
			_ = lock.Close()
			if err == nil {
				t.Fatal("cooperating writer journal was not locked")
			}
		}
		return nil
	}); err != nil || !called {
		t.Fatalf("artifact fence: %v", err)
	}
	journal, err := m.lockNetworkJournal(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	fields := vlanChangeDB{"VRF|VrfTest": {"NULL": "NULL"}}
	state := &networkJournalState{Version: 1, Records: map[string]*networkRecord{"VRF|VrfTest": {Kind: "VRF", OwnerID: "uid-1", Pending: &networkPending{Request: agent.NetworkRequest{Kind: "VRF", OwnerID: "uid-1", Spec: json.RawMessage(`{"name":"VrfTest"}`)}, Activation: "Prepared", Before: vlanChangeDB{}, After: fields, Owned: fields, PreHash: strings.Repeat("a", 64), PostHash: strings.Repeat("b", 64)}}}}
	if err := storeNetworkJournal(journal, state); err != nil {
		t.Fatal(err)
	}
	journal.close()
	called = false
	if err := f.WithMutation(t.Context(), func() error { called = true; return nil }); err == nil || called {
		t.Fatal("artifact activation bypassed durable network recovery")
	}
}

func TestArtifactFenceWaitHonorsCancellation(t *testing.T) {
	m := &SonicAgent{}
	m.configMutex.Lock()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- (&ArtifactWriterFence{agent: m}).WithMutation(ctx, func() error { t.Error("canceled queued action executed"); return nil })
	}()
	cancel()
	select {
	case err := <-done:
		m.configMutex.Unlock()
		if err == nil {
			t.Fatal("canceled wait accepted")
		}
	case <-time.After(100 * time.Millisecond):
		m.configMutex.Unlock()
		<-done
		t.Fatal("artifact writer lock ignored cancellation")
	}
}
