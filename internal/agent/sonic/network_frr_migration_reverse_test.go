// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

func (f *frrMigrationFixture) separatedFiles() map[string]string {
	if f.separatedCandidate != nil {
		return f.separatedCandidate
	}
	common := "hostname leaf-03\npassword zebra\nenable password zebra\nlog syslog informational\nlog facility local4\n"
	return map[string]string{
		"bgpd.conf":    common + "agentx\n",
		"zebra.conf":   common + "zebra nexthop kernel enable\nno fpm use-next-hop-groups\nfpm address 127.0.0.1\nzebra nexthop-group keep 1\nip nht resolve-via-default\nipv6 nht resolve-via-default\n",
		"staticd.conf": common,
	}
}

func TestFRRMigrationSeparatedCandidates(t *testing.T) {
	for _, name := range []string{"bgpd.conf", "zebra.conf", "staticd.conf"} {
		t.Run(name, func(t *testing.T) {
			for _, directive := range []string{"ip route 0.0.0.0/0 192.0.2.1", "router bgp 65000", "no ip forwarding", "route-map POLICY permit 10", "no zebra nexthop kernel enable"} {
				f := newFRRMigrationFixture()
				files := f.separatedFiles()
				files[name] += directive + "\n"
				data, _ := json.Marshal(files)
				if frrMigrationValidateCandidate(data, "leaf-03", "Traditional") == nil {
					t.Fatalf("accepted %s", directive)
				}
			}
		})
	}
	f := newFRRMigrationFixture()
	data, _ := json.Marshal(f.separatedFiles())
	if err := frrMigrationValidateCandidate(data, "leaf-03", "Traditional"); err != nil {
		t.Fatal(err)
	}
	e := frrMigrationEvidence{CandidateHash: strings.Repeat("a", 64)}
	db := frrMigrationTestDB()
	if frrMigrationDigest(db, e, "Unified") == frrMigrationDigest(db, e, "Traditional") {
		t.Fatal("digest lacks direction binding")
	}
}

func TestFRRMigrationReversePlanIdentity(t *testing.T) {
	r := &agent.NetworkRequest{Kind: "FRRMigration", OwnerID: "same-uid", Spec: json.RawMessage(`{"mode":"Traditional"}`)}
	id, err := networkIdentity(r)
	if err != nil || id != frrMigrationIdentity {
		t.Fatalf("reverse identity %q: %v", id, err)
	}
	p, err := planNetworkResource(frrMigrationPost(frrMigrationTestDB()), r)
	if err != nil {
		t.Fatal(err)
	}
	want := vlanChangeDB{"DEVICE_METADATA|localhost": {"frr_mgmt_framework_config": "false", "docker_routing_config_mode": "separated"}}
	if !reflect.DeepEqual(p.Desired, want) || validateNetworkFields(r.Kind, want) != nil {
		t.Fatalf("reverse desired: %v", p.Desired)
	}
}

func TestFRRMigrationStorageRetry(t *testing.T) {
	journal := t.TempDir()
	if err := frrMigrationPrepareStorage(journal); err != nil {
		t.Fatal(err)
	}
	root, err := frrMigrationStorageRoot(filepath.Join(journal, "frr-migration"))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	name := "backup-" + strings.Repeat("a", 64) + ".json"
	// Interrupted write: only a private, unselected temporary file exists.
	if err := os.WriteFile(filepath.Join(root.Name(), name+".tmp"), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := frrMigrationPrepareStorage(journal); err != nil {
		t.Fatal(err)
	}
	if err := frrMigrationImmutableFile(root, name, []byte("complete")); err != nil {
		t.Fatal(err)
	}
	if err := frrMigrationImmutableFile(root, name, []byte("complete")); err != nil {
		t.Fatal(err)
	}
	if err := frrMigrationImmutableFile(root, name, []byte("different")); err == nil {
		t.Fatal("immutable backup clobbered")
	}
	data, err := frrMigrationReadFile(root, name, 1024)
	if err != nil || string(data) != "complete" {
		t.Fatalf("backup changed %q %v", data, err)
	}
	// Unsafe temporary entries stay fail closed.
	if err := os.Symlink(filepath.Join(root.Name(), name), filepath.Join(root.Name(), name+".tmp")); err != nil {
		t.Fatal(err)
	}
	if err := frrMigrationImmutableFile(root, "launch-"+strings.Repeat("a", 64)+".json", []byte("receipt")); err != nil {
		t.Fatal(err)
	}
	if err := frrMigrationPrepareStorage(journal); err == nil {
		t.Fatal("symlink accepted")
	}
}
