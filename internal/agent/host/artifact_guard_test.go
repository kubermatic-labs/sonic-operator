// SPDX-License-Identifier: Apache-2.0
package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ironcore-dev/sonic-operator/internal/agent/artifactstate"
)

func TestArtifactGuardUsesRealPendingWithoutRewriting(t *testing.T) {
	e, f, _ := newTestEngine(t)
	q := managementRequest()
	q.Management.Addresses[0].Prefix = "10.0.0.99/24"
	f.activeMAC = "02:00:00:00:00:77"
	if _, err := e.Ensure(t.Context(), q, "connection"); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(e.dir, "host.json")
	before, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := WithArtifactExclusion(t.Context(), e.dir, func() error { t.Error("pending ignored"); return nil }); !errors.Is(err, artifactstate.ErrForeignPending) {
		t.Fatal(err)
	}
	if err := WithArtifactAgentRecoveryExclusion(t.Context(), e.dir, func() error {
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
		defer cancel()
		if _, err := e.Get(ctx, q, "new"); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("artifact guard did not hold host flock: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(file)
	if !bytes.Equal(before, after) {
		t.Fatal("artifact reader rewrote host recovery authority")
	}
}

func TestArtifactGuardMACAuthorityMatchesNativeRecovery(t *testing.T) {
	for _, tc := range []struct {
		name, field, value             string
		missing, valid, omittedDesired bool
	}{
		{name: "valid", valid: true},
		{name: "historical-observed-absent", field: "observedActiveMAC", missing: true, valid: true},
		{name: "omitted-desired-mac", valid: true, omittedDesired: true},
		{name: "before-absent", field: "activeMAC", missing: true},
		{name: "before-empty", field: "activeMAC"},
		{name: "before-multicast", field: "activeMAC", value: "01:00:00:00:00:01"},
		{name: "before-zero", field: "activeMAC", value: "00:00:00:00:00:00"},
		{name: "before-uppercase", field: "activeMAC", value: "02:AA:00:00:00:11"},
		{name: "before-hyphenated", field: "activeMAC", value: "02-aa-00-00-00-11"},
		{name: "observed-multicast", field: "observedActiveMAC", value: "01:00:00:00:00:01"},
		{name: "observed-zero", field: "observedActiveMAC", value: "00:00:00:00:00:00"},
		{name: "observed-uppercase", field: "observedActiveMAC", value: "02:AA:00:00:00:77"},
		{name: "observed-hyphenated", field: "observedActiveMAC", value: "02-aa-00-00-00-77"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, f, _ := newTestEngine(t)
			q := managementRequest()
			q.Management.Addresses[0].Prefix = "10.0.0.99/24"
			if tc.omittedDesired {
				f.state.MAC, q.Management.MAC = "", ""
			}
			if _, err := e.Ensure(t.Context(), q, "transport"); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(e.dir, "host.json")
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var envelope map[string]any
			if err := json.Unmarshal(raw, &envelope); err != nil {
				t.Fatal(err)
			}
			pending := envelope["pending"].(map[string]any)
			if tc.field != "" {
				object := pending
				if tc.field == "activeMAC" {
					object = pending["before"].(map[string]any)
				}
				if tc.missing {
					delete(object, tc.field)
				} else {
					object[tc.field] = tc.value
				}
			}
			raw, err = json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(file, raw, 0600); err != nil {
				t.Fatal(err)
			}
			var r record
			if err := StrictDecode(raw, &r); err != nil {
				t.Fatal(err)
			}
			// Exercise Native's real pre-mutation validation. A valid scope reaches
			// the native IO boundary; invalid authority must never reach it.
			boundary := errors.New("native mutation boundary")
			mutations := 0
			n := &Native{WithMutation: func(context.Context, func() error) error { mutations++; return boundary }}
			nativeErr := n.RestoreManagement(t.Context(), RecoveryScope{Before: r.Pending.Before, Candidate: r.Pending.Candidate, ObservedActiveMAC: r.Pending.ObservedActiveMAC})
			if tc.valid {
				if !errors.Is(nativeErr, boundary) || mutations != 1 {
					t.Fatalf("compatible native recovery rejected: %v", nativeErr)
				}
			} else if !errors.Is(nativeErr, ErrInvalid) || mutations != 0 {
				t.Errorf("invalid native authority reached mutation: %v calls=%d", nativeErr, mutations)
			}
			for name, guard := range map[string]func(context.Context, string, func() error) error{"ordinary": WithArtifactExclusion, "agent-recovery": WithArtifactAgentRecoveryExclusion} {
				called := false
				err := guard(t.Context(), e.dir, func() error { called = true; return nil })
				if tc.valid {
					if name == "ordinary" {
						if !errors.Is(err, artifactstate.ErrForeignPending) || called {
							t.Errorf("valid Pending not fenced: %v", err)
						}
					} else if err != nil || !called {
						t.Errorf("valid recovery rejected: %v", err)
					}
				} else if !errors.Is(err, ErrStorage) || errors.Is(err, artifactstate.ErrForeignPending) || called {
					t.Errorf("%s granted authority for invalid MAC: %v called=%v", name, err, called)
				}
			}
			after, err := os.ReadFile(file)
			if err != nil || !bytes.Equal(raw, after) {
				t.Fatal("MAC validation rewrote recovery journal", err)
			}
		})
	}
}
