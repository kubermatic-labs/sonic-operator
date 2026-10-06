// SPDX-License-Identifier: Apache-2.0
package host

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

func TestNTPsecHostnameRejectedBeforeAnyNativeOperation(t *testing.T) {
	calls := 0
	n := &Native{Run: func(context.Context, []string, []byte) ([]byte, error) { calls++; return nil, ErrNative }, CAS: func(context.Context, Database, Database) error { calls++; return nil }}
	if err := n.validateSystem(t.Context(), System{NTP: &NTP{Servers: []string{"ntp.example.org"}}}, NativeProfile{NTPBackend: "ntpsec"}, Database{}); err != ErrInvalid {
		t.Fatal("unsupported hostname did not fail image preflight")
	}
	if calls != 0 {
		t.Fatal("unsupported hostname reached a native operation")
	}
}
func TestNTPsecHostnameCannotReachCASFilesOrRestart(t *testing.T) {
	f := newSystemFixture(t)
	var p NativeProfile
	_ = json.Unmarshal(f.files[profileFile], &p)
	p.NTPBackend = "ntpsec"
	f.files[profileFile], _ = json.Marshal(p)
	writes := 0
	f.n.CAS = func(context.Context, Database, Database) error { writes++; return nil }
	f.n.WriteFile = func(string, []byte, os.FileMode) error { writes++; return nil }
	q := f.request(SNMP{Location: "public"})
	q.System.NTP = &NTP{Servers: []string{"ntp.example.org"}}
	if err := f.n.Validate(t.Context(), q); err != ErrInvalid {
		t.Fatal("image-specific preflight accepted hostname")
	}
	if err := f.n.ApplySystem(t.Context(), q); err != ErrInvalid {
		t.Fatal("direct native writer accepted unsupported hostname")
	}
	if writes != 0 || f.restarts != 0 {
		t.Fatal("unsupported declaration mutated native state")
	}
}

func TestHostJSONRequiresCanonicalStructFieldNames(t *testing.T) {
	for _, input := range []string{`{"owner":"one","Owner":"two"}`, `{"management":{"interface":"eth0","Addresses":[]}}`} {
		var q Request
		if StrictDecode([]byte(input), &q) == nil {
			t.Fatal("case alias accepted")
		}
	}
	var p NativeProfile
	if err := StrictDecode([]byte(`{"consumerSHA256":{"Key":"one","key":"two"}}`), &p); err != nil {
		t.Fatal("legitimate map keys must remain case-sensitive")
	}
}
