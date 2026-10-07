// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ironcore-dev/sonic-operator/internal/agent/artifactstate"
)

func TestAppliedBootRuntimeRequalifiesIncarnation(t *testing.T) {
	for _, change := range []string{"unchanged", "reboot", "pmon-recreation", "pmon-regeneration", "old-marker"} {
		t.Run(change, func(t *testing.T) {
			h := newGenerationFixture(t)
			defer func() { h.e.Close() }()
			token := h.confirmInitial()
			manifest := h.loaded
			h.boot = "boot-2"
			h.finalHealthPending = true
			if err := h.e.RestoreBoot(); err != nil {
				t.Fatal(err)
			}
			if err := h.e.Tick(time.Now()); err == nil {
				t.Fatal("expected final health to remain pending")
			}
			j, err := h.e.load()
			if err != nil || !j.BootRuntimeApplied {
				t.Fatalf("runtime not durably applied: %+v %v", j, err)
			}
			calls, restarts := h.packageCalls, h.daemonRestarts
			if change == "reboot" || change == "pmon-recreation" {
				h.incarnation = "container-2"
			}
			if change != "unchanged" {
				h.configured = ""
				h.loaded = ""
			}
			if change == "old-marker" {
				j.BootRuntimeIdentity = ""
				if err := h.e.save(j); err != nil {
					t.Fatal(err)
				}
			}
			var restoredPath string
			if change == "reboot" {
				h.boot = "boot-3"
				for _, f := range j.Active.Files {
					if f.Slot == "AgentBinary" {
						restoredPath = filepath.Join(h.root, f.Path)
						if err := os.WriteFile(restoredPath, []byte("boot replaced input"), f.Mode); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			h.reopen()
			h.finalHealthPending = false
			if err := h.e.RestoreBoot(); err != nil {
				t.Fatal(err)
			}
			if err := h.e.Tick(time.Now()); err != nil {
				t.Fatalf("runtime progress from prior incarnation blocked recovery: %v", err)
			}
			j, err = h.e.load()
			if err != nil || j.Phase != "Confirmed" || j.Active.Token != token || j.Active.BootID != h.boot || h.loaded != manifest {
				t.Fatalf("confirmed authority not restored: %+v %v", j, err)
			}
			if change == "unchanged" {
				if h.packageCalls != calls || h.daemonRestarts != restarts {
					t.Fatal("unchanged incarnation unnecessarily reactivated")
				}
			} else if h.packageCalls <= calls || h.daemonRestarts <= restarts {
				t.Fatal("regenerated runtime was not reapplied")
			}
			if restoredPath != "" {
				for _, f := range j.Active.Files {
					if f.Slot == "AgentBinary" {
						b, err := os.ReadFile(restoredPath)
						if err != nil || Digest(b) != f.Hash {
							t.Fatal("second boot did not restore confirmed input")
						}
					}
				}
			}
			if err := artifactstate.CheckPending(h.e.reservationDir()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLegacyPartialPackageReceiptResumesOriginalAuthority(t *testing.T) {
	for _, outcome := range []string{"continue", "timeout", "invalid-payload", "incomplete-payload", "missing-payloads"} {
		t.Run(outcome, func(t *testing.T) {
			timeout := outcome == "timeout"
			h := newGenerationFixture(t)
			defer func() { h.e.Close() }()
			now := time.Now()
			wheel, modules := syntheticWheelSources(t, "", " next-version")
			for i, f := range h.bundle.Files {
				if f.Slot == "PlatformWheel" {
					h.bundle.Files[i].Data = wheel
					h.bundle.Files[i].SHA256 = Digest(wheel)
				}
				for _, m := range modules {
					if f.Slot == m.Slot {
						h.bundle.Files[i] = m
					}
				}
			}
			result, err := h.e.Ensure(h.bundle, now)
			if err != nil {
				t.Fatal(err)
			}
			h.boot = "boot-1"
			if err := h.e.Tick(now); err != nil {
				t.Fatal(err)
			}
			j, err := h.e.load()
			if err != nil || j.Phase != "Activating" {
				t.Fatalf("not activating: %+v %v", j, err)
			}
			if err := h.n.preparePackages(context.Background(), j); err != nil {
				t.Fatal(err)
			}
			original := append([]packageRecovery(nil), j.Packages...)
			// Construct the accepted prior-format fixed payloads and apply only host.
			for i, entry := range j.Packages {
				var before, candidate packageSnapshot
				for _, which := range []string{"before", "candidate"} {
					raw, err := h.e.readPackagePayload(j, entry, which)
					if err != nil {
						t.Fatal(err)
					}
					if err := h.e.atomic(h.e.packagePath(j, entry.Target, which), raw, 0600); err != nil {
						t.Fatal(err)
					}
					hash := entry.Before
					if which == "candidate" {
						hash = entry.Candidate
						_ = json.Unmarshal(raw, &candidate)
					} else {
						_ = json.Unmarshal(raw, &before)
					}
					if err := h.e.root.Remove(h.e.packagePath(j, entry.Target, which, hash)); err != nil {
						t.Fatal(err)
					}
				}
				if entry.Target == "host" {
					packet, _ := json.Marshal(map[string]any{"target": "host", "token": j.Token, "mode": "apply", "before": before, "candidate": candidate})
					if _, err := h.n.packageCommand(context.Background(), "host", packet); err != nil {
						t.Fatal(err)
					}
					receiptPath := filepath.Join(h.root, "package-state", "host", j.Token, "authority.json")
					raw, err := os.ReadFile(receiptPath)
					if err != nil {
						t.Fatal(err)
					}
					var receipt map[string]any
					_ = json.Unmarshal(raw, &receipt)
					delete(receipt, "observed")
					raw, _ = json.Marshal(receipt)
					if err := os.WriteFile(receiptPath, raw, 0600); err != nil {
						t.Fatal(err)
					}
				}
				j.Packages[i].Observed = ""
			}
			raw, _ := json.Marshal(j)
			var legacy map[string]any
			_ = json.Unmarshal(raw, &legacy)
			delete(legacy, "packagesPrepared")
			raw, _ = json.Marshal(legacy)
			if err := h.e.atomic(filepath.Join(h.e.state, "journal.json"), raw, 0600); err != nil {
				t.Fatal(err)
			}
			invalid := outcome == "invalid-payload" || outcome == "incomplete-payload" || outcome == "missing-payloads"
			if outcome == "invalid-payload" {
				if err := h.e.atomic(h.e.packagePath(j, "host", "before"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if outcome == "incomplete-payload" {
				if err := h.e.root.Remove(h.e.packagePath(j, "pmon", "candidate")); err != nil {
					t.Fatal(err)
				}
			}
			if outcome == "missing-payloads" {
				for _, entry := range j.Packages {
					for _, which := range []string{"before", "candidate"} {
						if err := h.e.root.Remove(h.e.packagePath(j, entry.Target, which)); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			calls := h.packageCalls
			if invalid {
				h.e.Close()
				reopened, err := Open(h.root, "/host/artifacts", h.policy, func() error { return nil }, func() error { return nil })
				if err == nil {
					reopened.Close()
					t.Fatal("invalid legacy authority accepted")
				}
				got, err := os.ReadFile(filepath.Join(h.root, h.e.state, "journal.json"))
				if err != nil || !bytes.Equal(raw, got) || h.packageCalls != calls {
					t.Fatal("rejected migration modified recovery state")
				}
				return
			}
			h.reopen()
			h.failSnapshot = "host"
			at := now
			if timeout {
				at = now.Add(6 * time.Minute)
			}
			if err := h.e.Tick(at); err != nil {
				t.Fatal(err)
			}
			if !timeout {
				if _, err := h.e.Confirm(h.bundle, result.Token, at); err != nil {
					t.Fatalf("legacy partial activation did not converge: %v", err)
				}
			}
			j, err = h.e.load()
			expected := "Confirmed"
			if timeout {
				expected = "RolledBack"
			}
			if err != nil || j.Phase != expected {
				t.Fatalf("legacy partial recovery stuck: %+v %v", j, err)
			}
			for i, entry := range j.Packages {
				if entry.Before != original[i].Before || entry.Candidate != original[i].Candidate || entry.Observed != "" {
					t.Fatal("legacy pair/observation authority replaced")
				}
				which := "candidate"
				if timeout {
					which = "before"
				}
				data, err := h.e.readPackagePayload(j, entry, which)
				if err != nil {
					t.Fatal(err)
				}
				var expected packageSnapshot
				if err := Decode(data, &expected); err != nil {
					t.Fatal(err)
				}
				for name, file := range expected.Entries {
					got, err := os.ReadFile(filepath.Join(h.packageRoot(entry.Target), name))
					if err != nil || !bytes.Equal(got, file.Data) {
						t.Fatalf("%s/%s did not restore %s bytes", entry.Target, name, which)
					}
				}
			}
			if err := artifactstate.CheckPending(h.e.reservationDir()); err != nil {
				t.Fatal(err)
			}
		})
	}
}
