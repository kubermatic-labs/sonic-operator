// SPDX-License-Identifier: Apache-2.0
package host

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestNativeSavedAdmissionChecksManagedTablesWithoutProcesses(t *testing.T) {
	for _, kind := range []string{"Management", "NTP", "SNMP", "NTP-SNMP"} {
		t.Run(kind, func(t *testing.T) {
			q := managementRequest()
			if kind != "Management" {
				q.Kind, q.Management, q.RollbackSeconds = "System", nil, 0
				q.System = &System{}
				if kind != "SNMP" {
					q.System.NTP = &NTP{Servers: []string{"192.0.2.1"}}
				}
				if kind != "NTP" {
					q.System.SNMP = &SNMP{Location: "rack", Contact: "ops team", Community: "private-test"}
				}
			}
			db := Database{}
			var err error
			if q.Management != nil {
				db, err = managementDatabase(db, *q.Management)
			} else {
				db, err = systemDatabase(db, *q.System)
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, change := range []string{"exact", "unrelated-save", "saved-host-drift", "live-host-drift", "truncated", "duplicate", "null", "canceled"} {
				t.Run(change, func(t *testing.T) {
					live, saved := cloneDB(db), cloneDB(db)
					table := "MGMT_INTERFACE"
					if kind != "Management" {
						table = systemTables(*q.System)[0]
					}
					switch change {
					case "unrelated-save":
						saved["PORT"] = map[string]map[string]string{"Ethernet0": {"admin_status": "up"}}
					case "saved-host-drift":
						saved[table] = map[string]map[string]string{"foreign": {"changed": "yes"}}
					case "live-host-drift":
						live[table] = map[string]map[string]string{"foreign": {"changed": "yes"}}
					}
					data, _ := json.Marshal(saved)
					switch change {
					case "truncated":
						data = []byte(`{"PORT":`)
					case "duplicate":
						data = append([]byte(`{"PORT":{},"PORT":{},`), data[1:]...)
					case "null":
						data = []byte("null")
					}
					path := filepath.Join(t.TempDir(), "config_db.json")
					if err := os.WriteFile(path, data, 0600); err != nil {
						t.Fatal(err)
					}
					n := &Native{Load: func(context.Context) (Database, error) { return live, nil }, ReadFile: func(p string) ([]byte, error) {
						if p != "/etc/sonic/config_db.json" {
							t.Errorf("unexpected final read: %s", p)
						}
						return readSavedConfigFile(path)
					}, Run: func(context.Context, []string, []byte) ([]byte, error) {
						t.Error("process in final saved admission")
						return nil, ErrNative
					}}
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					if change == "canceled" {
						cancel()
					}
					err := n.VerifySaved(ctx, q)
					if wantOK := change == "exact" || change == "unrelated-save"; (err == nil) != wantOK {
						t.Fatalf("saved admission: %v", err)
					}
				})
			}
		})
	}
}

func TestSavedAdmissionFileSecurityAndBound(t *testing.T) {
	for _, name := range []string{"regular", "symlink", "directory", "fifo", "writable", "oversized", "replacement", "inplace"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "saved")
			if err := os.WriteFile(path, []byte(`{"PORT":{}}`), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := readSavedConfigFile(path); err != nil {
				t.Fatal(err)
			}
			wantOK := false
			switch name {
			case "regular":
				wantOK = true
			case "symlink":
				if err := os.Rename(path, path+".target"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".target", path); err != nil {
					t.Fatal(err)
				}
			case "directory", "fifo":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if name == "directory" {
					if err := os.Mkdir(path, 0700); err != nil {
						t.Fatal(err)
					}
				} else if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err := os.Chmod(path, 0666); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				if err := os.Truncate(path, savedConfigLimit+1); err != nil {
					t.Fatal(err)
				}
			case "replacement", "inplace":
				wantOK = true
				target := path
				if name == "replacement" {
					target += ".new"
				}
				if err := os.WriteFile(target, []byte(`{"PORT":{"Ethernet0":{}}}`), 0600); err != nil {
					t.Fatal(err)
				}
				if target != path {
					if err := os.Rename(target, path); err != nil {
						t.Fatal(err)
					}
				}
			}
			got, err := readSavedConfigFile(path)
			if (err == nil) != wantOK {
				t.Fatalf("secure read: %v", err)
			}
			if (name == "replacement" || name == "inplace") && string(got) != `{"PORT":{"Ethernet0":{}}}` {
				t.Fatal("read reused earlier saved contents")
			}
		})
	}
}
