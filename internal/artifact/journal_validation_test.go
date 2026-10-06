// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUnknownJournalPhaseVersionAndDuplicateKeysStayBlocked(t *testing.T) {
	e, root := testEngine(t)
	if _, err := e.Ensure(testBundle(), time.Now()); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, "host/artifacts/journal.json")
	raw, _ := os.ReadFile(p)
	cases := [][]byte{bytes.Replace(raw, []byte(`"phase":"Staged"`), []byte(`"phase":"unknown"`), 1), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":99`), 1), append([]byte(`{"phase":"Confirmed",`), raw[1:]...)}
	for _, bad := range cases {
		if err := os.WriteFile(p, bad, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := e.load(); err == nil {
			t.Fatal("ambiguous/unknown journal was trusted")
		}
	}
}
