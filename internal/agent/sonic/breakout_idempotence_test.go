// SPDX-License-Identifier: Apache-2.0
package sonic

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

func TestConfirmedBreakoutRepeatDoesNotSaveOrJournal(t *testing.T) {
	for _, adopt := range []bool{true, false} {
		t.Run(fmt.Sprint("adopt=", adopt), func(t *testing.T) {
			m, _, calls, saves := populatedBreakoutFixture(t)
			q := splitRequest()
			q.AdoptOnly = adopt
			if got, st := m.ReconcilePortBreakout(t.Context(), q); st != nil || got.Pending || *saves != 1 {
				t.Fatalf("first adoption must persist: %+v %+v saves=%d", got, st, *saves)
			}
			path := filepath.Join(m.breakoutJournalDir, "breakout.json")
			before, _ := os.Stat(path)
			body, _ := os.ReadFile(path)
			for range 2 {
				got, st := m.ReconcilePortBreakout(t.Context(), q)
				if st != nil || got.Pending || !got.PersistenceVerified || !got.RuntimeVerified || !got.ConfigurationVerified || *saves != 1 || *calls != 0 {
					t.Fatalf("confirmed repeat recreated transaction: %+v %+v saves=%d calls=%d", got, st, *saves, *calls)
				}
			}
			after, _ := os.Stat(path)
			latest, _ := os.ReadFile(path)
			if !os.SameFile(before, after) || !bytes.Equal(body, latest) {
				t.Fatal("confirmed repeat rewrote journal")
			}
		})
	}
}

func TestConfirmedBreakoutRepeatRequiresFreshEvidence(t *testing.T) {
	for _, name := range []string{"saved", "truncated saved", "runtime", "native", "request", "platform", "admin", "native success", "drift during saved read"} {
		t.Run(name, func(t *testing.T) {
			m, db, _, saves := populatedBreakoutFixture(t)
			q := splitRequest()
			q.AdoptOnly = true
			if _, st := m.ReconcilePortBreakout(t.Context(), q); st != nil {
				t.Fatal(st)
			}
			switch name {
			case "saved":
				m.readSavedPortConfig = func() ([]byte, error) { return []byte(`{"PORT":{}}`), nil }
			case "truncated saved":
				m.readSavedPortConfig = func() ([]byte, error) { return []byte(`{"PORT":`), nil }
			case "runtime":
				m.verifyBreakoutRuntime = func(context.Context, *breakoutPlatform, vlanChangeDB) error { return fmt.Errorf("runtime drift") }
			case "native":
				m.validateBreakoutConfig = func(context.Context) error { return fmt.Errorf("native schema drift") }
			case "request":
				q.ChildAdminState = "up"
			case "platform":
				(*db)["DEVICE_METADATA|localhost"]["mac"] = "02:00:00:00:00:ff"
			case "admin":
				(*db)["PORT|Ethernet1"]["admin_status"] = "up"
			case "native success":
				j, err := m.lockBreakoutJournal(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				r, err := loadBreakoutRecord(j)
				if err != nil {
					t.Fatal(err)
				}
				r.NativeSucceeded = false
				if err := storeBreakoutRecord(j, r); err != nil {
					t.Fatal(err)
				}
				j.close()
			case "drift during saved read":
				saved := portConfigJSON(t, *db)
				m.readSavedPortConfig = func() ([]byte, error) { (*db)["PORT|Ethernet1"]["admin_status"] = "up"; return saved, nil }
			}
			// If fallback reaches persistence it must retain durable Pending on failure.
			m.saveConfig = func(context.Context) *agent.Status { *saves++; return &agent.Status{Code: 500} }
			got, st := m.ReconcilePortBreakout(t.Context(), q)
			if st == nil || (got != nil && got.PersistenceVerified) {
				t.Fatalf("%s accepted stale proof: %+v %+v", name, got, st)
			}
		})
	}
}
