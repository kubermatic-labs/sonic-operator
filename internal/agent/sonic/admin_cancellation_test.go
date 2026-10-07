// SPDX-License-Identifier: Apache-2.0
package sonic

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

func TestAdminCanceledWaitReturnsBeforeHolderWithoutLateWrites(t *testing.T) {
	for _, name := range []string{"config mutex", "journal flock"} {
		t.Run(name, func(t *testing.T) {
			m, dbs, saves := newTestAgent(t)
			config := dbs["CONFIG_DB"]
			config.hashes["PORT|Ethernet0"] = map[string]string{"admin_status": "down"}
			m.readSavedPortConfig = func() ([]byte, error) { return []byte(`{"PORT":{"Ethernet0":{"admin_status":"down"}}}`), nil }
			var release func()
			if name == "config mutex" {
				m.configMutex.Lock()
				release = m.configMutex.Unlock
			} else {
				m.journalDir = t.TempDir()
				if err := os.Chmod(m.journalDir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(m.journalDir, ".lock"), nil, 0600); err != nil {
					t.Fatal(err)
				}
				j, err := m.lockVLANAuthorityJournal(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				release = j.close
			}
			ctx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
			defer cancel()
			done := make(chan *agent.Status, 1)
			go func() {
				_, st := m.SetInterfaceAdminStatus(ctx, &agent.Interface{Name: "Ethernet0", AdminStatus: agent.StatusUp})
				done <- st
			}()
			select {
			case st := <-done:
				release()
				if st == nil {
					t.Fatal("canceled setter succeeded")
				}
			case <-time.After(300 * time.Millisecond):
				release()
				<-done
				t.Fatal("expired admin waiter remained blocked behind holder")
			}
			if !m.configMutex.TryLock() {
				t.Fatal("admin left config mutex held")
			}
			m.configMutex.Unlock()
			if config.hashes["PORT|Ethernet0"]["admin_status"] != "down" || *saves != 0 {
				t.Fatal("canceled waiter performed late Redis/native writes")
			}
		})
	}
}
