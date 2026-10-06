// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Optional protected read-only capture qualification. Raw native configuration
// stays outside Git and is never printed, even when a parser rejects it.
func TestTraditionalBGPRecordedNativeEvidence(t *testing.T) {
	dir := os.Getenv("SONIC_TRADITIONAL_EVIDENCE_DIR")
	if dir == "" {
		t.Skip("protected native evidence not configured")
	}
	load := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(dir, name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var result struct {
			Returncode int    `json:"returncode"`
			Stdout     string `json:"stdout"`
		}
		if json.Unmarshal(data, &result) != nil || result.Returncode != 0 {
			t.Fatal("invalid native capture envelope")
		}
		return []byte(result.Stdout)
	}
	s := routingBGPSpec{VRF: "default", LocalASN: 65100, RouterID: "10.1.0.1", Prefixes: []string{"10.1.0.1/32"}}
	if strings.TrimSpace(string(load("verified-bundle"))) != traditionalBundleDigest {
		t.Fatal("recorded bundle is not qualified")
	}
	if strings.TrimSpace(string(load("host-qualification"))) != traditionalHostDigest {
		t.Fatal("recorded host activation path is not qualified")
	}
	for _, source := range []string{"live", "saved", "candidate"} {
		t.Run(source, func(t *testing.T) {
			var configs map[string]string
			if json.Unmarshal(load("verified-"+source), &configs) != nil {
				t.Fatal("invalid recorded render")
			}
			if matched, err := traditionalPolicy(configs, s, false); err != nil || !matched {
				t.Fatalf("native %s render policy mismatch: %v", source, err)
			}
			if err := traditionalPreflightPolicy(configs, string(load("running")), s); err != nil {
				t.Fatalf("native unmanaged-state preservation mismatch: %v", err)
			}
		})
	}
	if matched, err := traditionalPolicy(map[string]string{"running": string(load("running"))}, s, true); err != nil || !matched {
		t.Fatalf("recorded running policy mismatch: %v", err)
	}
	db, err := traditionalSavedDB(load("configdb"))
	if err != nil {
		t.Fatal(err)
	}
	if err := traditionalInputs(db, s); err != nil {
		t.Fatal(err)
	}
}
