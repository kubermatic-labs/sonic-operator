// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

func TestAdminPersistenceRetryAfterRestart(t *testing.T) {
	t.Parallel()
	m, dbs, saves := newTestAgent(t)
	config := dbs["CONFIG_DB"]
	config.hashes["PORT|Ethernet0"] = map[string]string{"admin_status": "down", "alias": "keep"}
	saved := portConfigJSON(t, config.hashes)
	m.readSavedPortConfig = func() ([]byte, error) { return saved, nil }
	m.saveConfig = func(context.Context) *agent.Status {
		*saves++
		config.fail["hset"] = fmt.Errorf("rollback unavailable")
		return &agent.Status{Code: 500, Message: "save failed"}
	}
	request := &agent.Interface{Name: "Ethernet0", AdminStatus: agent.StatusUp}
	if _, status := m.SetInterfaceAdminStatus(t.Context(), request); status == nil {
		t.Fatal("expected failed save and rollback")
	}
	if config.hashes["PORT|Ethernet0"]["admin_status"] != "up" {
		t.Fatal("test did not leave desired value in Redis")
	}
	// Restart loses configDirty. Matching Redis is not proof of persistence.
	m.configDirty = false
	delete(config.fail, "hset")
	if _, status := m.SetInterfaceAdminStatus(t.Context(), request); status == nil {
		t.Fatal("failed save accepted because Redis matches after restart")
	}
	if *saves != 2 {
		t.Fatalf("save attempts = %d, want 2", *saves)
	}
}

func portConfigJSON(t *testing.T, db map[string]map[string]string) []byte {
	t.Helper()
	tables := map[string]map[string]map[string]string{}
	for key, fields := range db {
		table, name, ok := strings.Cut(key, "|")
		if !ok || (table != "PORT" && table != "BREAKOUT_CFG") {
			continue
		}
		if tables[table] == nil {
			tables[table] = map[string]map[string]string{}
		}
		tables[table][name] = fields
	}
	data, err := json.Marshal(tables)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestAdminPersistenceEvidence(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"adopt equal unsaved", "already saved", "save reply without persistence", "live drift during save", "unreadable saved file", "wrong native identity"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m, dbs, saves := newTestAgent(t)
			config := dbs["CONFIG_DB"]
			config.hashes["PORT|Ethernet0"] = map[string]string{"admin_status": "up", "alias": "keep"}
			saved := []byte(`{"PORT":{"Ethernet0":{"admin_status":"down"}}}`)
			if name == "already saved" {
				saved = portConfigJSON(t, config.hashes)
			}
			m.readSavedPortConfig = func() ([]byte, error) {
				if name == "unreadable saved file" {
					return nil, fmt.Errorf("unreadable")
				}
				return saved, nil
			}
			m.saveConfig = func(context.Context) *agent.Status {
				*saves++
				if name != "save reply without persistence" {
					saved = portConfigJSON(t, config.hashes)
				}
				if name == "live drift during save" {
					config.hashes["PORT|Ethernet0"]["admin_status"] = "down"
				}
				return &agent.Status{Code: 0}
			}
			request := &agent.Interface{Name: "Ethernet0", AdminStatus: agent.StatusUp}
			if name == "wrong native identity" {
				request.NativeName = "Ethernet4"
			}
			got, status := m.SetInterfaceAdminStatus(t.Context(), request)
			wantOK := name == "adopt equal unsaved" || name == "already saved"
			if wantOK {
				if status != nil || got == nil || !got.AdminPersistenceVerified {
					t.Fatalf("missing persistence evidence: %+v %+v", got, status)
				}
			} else if status == nil {
				t.Fatalf("unverified state accepted: %+v", got)
			}
			wantSaves := 1
			if name == "already saved" || name == "wrong native identity" {
				wantSaves = 0
			}
			if *saves != wantSaves || len(config.writes) != 0 {
				t.Fatalf("saves/writes=%d/%v", *saves, config.writes)
			}
		})
	}
}

func TestSavedPortConfigParsing(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, data string
		valid      bool
	}{
		{"port and unrelated list", `{"PORT":{"Ethernet0":{"admin_status":"up"}},"OTHER":{"secret":[1,2]}}`, true},
		{"invalid JSON", `{`, false},
		{"null file", `null`, false},
		{"null table", `{"PORT":null}`, false},
		{"invalid port fields", `{"PORT":{"Ethernet0":{"admin_status":42}}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &SonicAgent{readSavedPortConfig: func() ([]byte, error) { return []byte(tc.data), nil }}
			got, err := m.savedPortConfig()
			if (err == nil) != tc.valid {
				t.Fatalf("result %v, error %v", got, err)
			}
			if tc.valid && got["PORT|Ethernet0"]["admin_status"] != "up" {
				t.Fatal(got)
			}
		})
	}
}

func TestAdminPersistenceConcurrentReadbackDrift(t *testing.T) {
	m, dbs, _ := newTestAgent(t)
	config := dbs["CONFIG_DB"]
	config.hashes["PORT|Ethernet0"] = map[string]string{"admin_status": "up"}
	saved := portConfigJSON(t, config.hashes)
	reads := 0
	m.readSavedPortConfig = func() ([]byte, error) {
		reads++
		if reads == 2 {
			config.hashes["PORT|Ethernet0"]["admin_status"] = "down"
		}
		return saved, nil
	}
	if got, status := m.SetInterfaceAdminStatus(t.Context(), &agent.Interface{Name: "Ethernet0", AdminStatus: agent.StatusUp}); status == nil {
		t.Fatalf("concurrent live drift accepted during saved read: %+v", got)
	}
}
