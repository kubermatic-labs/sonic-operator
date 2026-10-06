// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

func TestVLANAuthorityValidation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		request *agent.VLANAuthorityRequest
	}{
		{"nil", nil}, {"no VLAN", &agent.VLANAuthorityRequest{OwnerID: "owner"}},
		{"no owner", &agent.VLANAuthorityRequest{VLAN: &agent.VLAN{ID: 100}}},
		{"bad ID", &agent.VLANAuthorityRequest{OwnerID: "owner", VLAN: &agent.VLAN{ID: 4095}}},
		{"bad digest", &agent.VLANAuthorityRequest{OwnerID: "owner", VLAN: &agent.VLAN{ID: 100}, AdoptionDigest: "ABC"}},
		{"non Ethernet", &agent.VLANAuthorityRequest{OwnerID: "owner", VLAN: &agent.VLAN{ID: 100, Members: []agent.VLANMember{{InterfaceName: "eth1", TaggingMode: "tagged"}}}}},
		{"bad mode", &agent.VLANAuthorityRequest{OwnerID: "owner", VLAN: &agent.VLAN{ID: 100, Members: []agent.VLANMember{{InterfaceName: "Ethernet0", TaggingMode: "bad"}}}}},
		{"duplicate", &agent.VLANAuthorityRequest{OwnerID: "owner", VLAN: &agent.VLAN{ID: 100, Members: []agent.VLANMember{{InterfaceName: "Ethernet0", TaggingMode: "tagged"}, {InterfaceName: "Ethernet0", TaggingMode: "untagged"}}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateVLANAuthority(tc.request); err == nil {
				t.Fatal("accepted invalid request")
			}
		})
	}
}

func TestVLANAuthorityJournalSafety(t *testing.T) {
	for _, name := range []string{"symlink record", "hardlink record", "public record", "corrupt record", "foreign identity", "unknown field", "symlink lock", "public directory", "checksum tampering"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			lock := filepath.Join(dir, ".lock")
			if err := os.WriteFile(lock, nil, 0600); err != nil {
				t.Fatal(err)
			}
			m := &SonicAgent{journalDir: dir}
			j, err := m.lockVLANAuthorityJournal(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			r := &vlanAuthorityRecord{Version: 1, VLANID: 100, OwnerID: "owner", Confirmed: vlanChangeDB{}, Fingerprint: strings.Repeat("a", 64)}
			if err := j.store(r); err != nil {
				t.Fatal(err)
			}
			j.close()
			path := filepath.Join(dir, vlanAuthorityFile(100))
			switch name {
			case "symlink record", "symlink lock":
				if name == "symlink lock" {
					path = lock
				}
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".original", path); err != nil {
					t.Fatal(err)
				}
			case "hardlink record":
				if err := os.Link(path, path+".link"); err != nil {
					t.Fatal(err)
				}
			case "public record":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "public directory":
				if err := os.Chmod(dir, 0755); err != nil {
					t.Fatal(err)
				}
			case "corrupt record":
				if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			default:
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				text := string(data)
				switch name {
				case "foreign identity":
					text = strings.Replace(text, `"vlan_id":100`, `"vlan_id":200`, 1)
				case "unknown field":
					text = strings.Replace(text, `"version":1`, `"unknown":true,"version":1`, 1)
				case "checksum tampering":
					text = strings.Replace(text, `"owner_id":"owner"`, `"owner_id":"attacker"`, 1)
				}
				if err := os.WriteFile(path, []byte(text), 0600); err != nil {
					t.Fatal(err)
				}
			}
			j, err = m.lockVLANAuthorityJournal(t.Context())
			if err == nil {
				defer j.close()
				_, err = j.load(100)
			}
			if err == nil {
				t.Fatal("unsafe journal accepted")
			}
		})
	}
}

func TestVLANAuthorityProcessLock(t *testing.T) {
	if dir := os.Getenv("SONIC_AUTHORITY_LOCK_CHILD"); dir != "" {
		m := &SonicAgent{journalDir: dir}
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		if j, err := m.lockVLANAuthorityJournal(ctx); err == nil {
			j.close()
			t.Fatal("child bypassed lock")
		}
		fmt.Println("child lock timed out")
		return
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	m := &SonicAgent{journalDir: dir}
	j, err := m.lockVLANAuthorityJournal(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestVLANAuthorityProcessLock$")
	cmd.Env = append(os.Environ(), "SONIC_AUTHORITY_LOCK_CHILD="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "child lock timed out") {
		t.Fatalf("child lock: %v %s", err, out)
	}
}

func TestVLANAuthorityJournalConfiguration(t *testing.T) {
	m := &SonicAgent{}
	if err := m.ConfigureVLANAuthorityJournal(""); err == nil {
		t.Fatal("implicit journal accepted")
	}
	if err := m.ConfigureVLANAuthorityJournal("relative"); err == nil {
		t.Fatal("relative journal accepted")
	}
	dir := filepath.Join(t.TempDir(), "journal")
	err := m.ConfigureVLANAuthorityJournal(dir)
	if os.Geteuid() != 0 {
		if err == nil || m.journalDir != "" {
			t.Fatal("nonroot startup opted in")
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatal("nonroot startup created files")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ConfigureVLANAuthorityJournal(filepath.Join(t.TempDir(), "other")); err == nil {
		t.Fatal("journal reconfiguration accepted")
	}
}
