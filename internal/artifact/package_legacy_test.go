// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLegacyInheritedPackagePairStillPreparesObservation(t *testing.T) {
	h := newGenerationFixture(t)
	defer func() { h.e.Close() }()
	h.confirmInitial()
	p := filepath.Join(h.packageRoot("pmon"), "sonic_platform/chassis.py")
	if err := os.WriteFile(p, []byte("# owned drift\n"), 0644); err != nil {
		t.Fatal(err)
	}
	h.bundle.Generation++
	now := time.Now()
	r, err := h.e.Ensure(h.bundle, now)
	if err != nil {
		t.Fatal(err)
	}
	j, err := h.e.load()
	if err != nil || j.PackagesPrepared {
		t.Fatalf("expected inherited pair: %+v %v", j, err)
	}
	// a5ce38b omitted a false marker even for inherited digest-addressed pairs.
	raw, _ := json.Marshal(j)
	var legacy map[string]any
	if err := json.Unmarshal(raw, &legacy); err != nil {
		t.Fatal(err)
	}
	delete(legacy, "packagesPrepared")
	raw, _ = json.Marshal(legacy)
	if err := h.e.atomic(filepath.Join(h.e.state, "journal.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	h.reopen()
	h.boot = "repair-boot"
	if err := h.e.Tick(now); err != nil {
		t.Fatal(err)
	}
	if err := h.e.Tick(now); err != nil {
		t.Fatal(err)
	}
	if _, err := h.e.Confirm(h.bundle, r.Token, now); err != nil {
		t.Fatal(err)
	}
	j, err = h.e.load()
	if err != nil || !j.PackagesPrepared {
		t.Fatalf("inherited pair was not prepared: %+v %v", j, err)
	}
	for _, entry := range j.Packages {
		if entry.Target == "pmon" && (entry.Observed == "" || entry.Observed == entry.Before) {
			t.Fatal("legacy inheritance lost the independent drift observation")
		}
	}
}
