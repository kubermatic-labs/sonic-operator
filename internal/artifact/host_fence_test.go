// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ironcore-dev/sonic-operator/internal/agent/artifactstate"
)

func TestArtifactMutationsRespectManagementRecoveryFence(t *testing.T) {
	e, root := testEngine(t)
	n := &Native{Engine: e}
	_ = os.MkdirAll(filepath.Join(root, "etc/sonic"), 0700)
	_ = os.MkdirAll(filepath.Join(root, "host/sonic-operator-host-journal"), 0700)
	_ = os.WriteFile(filepath.Join(root, "etc/sonic/sonic-operator-host-recovery.json"), []byte(`{"journalDir":"/host/sonic-operator-host-journal","redisAddress":"127.0.0.1:6379"}`), 0600)
	journal := filepath.Join(root, "host/sonic-operator-host-journal/host.json")
	_ = os.WriteFile(journal, []byte(`{"pending":{"id":"management-operation"}}`), 0600)
	called := false
	action := func() error { called = true; return nil }
	if err := n.WithHostFence(t.Context(), action); err == nil || called {
		t.Fatal("artifact mutation invalidated pending management recovery")
	}
	_ = os.WriteFile(journal, []byte(`{"pending":null}`), 0600)
	if err := n.WithHostFence(t.Context(), action); err != nil || !called {
		t.Fatalf("cleared management fence not released: %v", err)
	}
	_ = os.WriteFile(journal, []byte(`{"futureUnknownRecord":true}`), 0600)
	called = false
	if err := n.WithHostFence(t.Context(), action); err == nil || called {
		t.Fatal("unknown host record treated as safe")
	}
	_ = os.WriteFile(journal, []byte(`{"pending":{"id":"active"},"pending":null}`), 0600)
	called = false
	if err := n.WithHostFence(t.Context(), action); err == nil || called {
		t.Fatal("duplicate JSON keys bypassed management recovery fence")
	}
}

func TestHostFenceStrictNestedRecordAndLostConfiguration(t *testing.T) {
	e, root := testEngine(t)
	n := &Native{Engine: e}
	dir := filepath.Join(root, "host/sonic-operator-host-journal")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "etc/sonic"), 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, "etc/sonic/sonic-operator-host-recovery.json")
	if err := os.WriteFile(config, []byte(`{"journalDir":"/host/sonic-operator-host-journal","redisAddress":"127.0.0.1:6379"}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`null`, `{"management":{"owner":"uid","target":"switch","revision":"1","unknown":true}}`, `{"pending":{"id":"not-a-transaction"}}`} {
		if err := os.WriteFile(filepath.Join(dir, "host.json"), []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		called := false
		err := n.WithHostFence(t.Context(), func() error { called = true; return nil })
		if err == nil || called || errors.Is(err, artifactstate.ErrForeignPending) {
			t.Fatalf("invalid record authorized action/fallback: %v called=%v", err, called)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "host.json"), []byte(`{"management":{"owner":"uid","target":"switch","revision":"1"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(config); err != nil {
		t.Fatal(err)
	}
	if err := n.WithHostFence(t.Context(), func() error { t.Error("lost config bypassed claimed host store"); return nil }); err == nil {
		t.Fatal("lost host configuration accepted")
	}
}
