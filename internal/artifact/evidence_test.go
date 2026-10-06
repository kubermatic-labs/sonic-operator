// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Raw host evidence is never checked into the repository. This optional offline
// qualification exercises production validation against the protected capture.
func TestCore001ReadOnlyEvidence(t *testing.T) {
	name := os.Getenv("SONIC_ARTIFACT_NATIVE_EVIDENCE")
	if name == "" {
		t.Skip("protected native capture not supplied")
	}
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	type distribution struct {
		Root  string            `json:"root"`
		Files map[string]string `json:"files"`
	}
	var evidence struct {
		Files            map[string]struct{ Expected, Current, SourceBase64 string } `json:"files"`
		HostDistribution distribution                                                `json:"hostDistribution"`
		Commands         map[string]struct {
			Stdout string `json:"stdout"`
		} `json:"commands"`
	}
	if err := json.Unmarshal(raw, &evidence); err != nil {
		t.Fatal(err)
	}
	var files []File
	for _, slot := range []string{"PlatformJSON", "HWSKUJSON", "PortConfig", "SAIProfile", "BroadcomConfig", "PlatformWheel", "PlatformInit", "PlatformChassis", "PlatformComponent", "PlatformEEPROM", "PlatformFan", "PlatformFanDrawer", "PlatformAPI", "PlatformPSU", "PlatformSFP", "PlatformThermal"} {
		f, ok := evidence.Files[strings.TrimPrefix(coreDestination(slot), "/")]
		if !ok {
			t.Fatalf("missing %s", slot)
		}
		data, err := base64.StdEncoding.DecodeString(f.SourceBase64)
		if err != nil {
			t.Fatal(err)
		}
		if f.Expected != f.Current || Digest(data) != f.Expected {
			t.Fatalf("existing/source mismatch: %s", slot)
		}
		files = append(files, File{Slot: slot, SHA256: f.Expected, Data: data})
	}
	if err := validateCandidates(files); err != nil {
		t.Fatal(err)
	}
	var members map[string][]byte
	for _, f := range files {
		if f.Slot == "PlatformWheel" {
			members, err = wheelMembers(f.Data)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	check := func(d distribution, root string) {
		t.Helper()
		filtered := map[string]string{}
		for name, hash := range d.Files {
			if strings.HasSuffix(name, ".py") || strings.HasSuffix(name, "/METADATA") || strings.HasSuffix(name, "/WHEEL") || strings.HasSuffix(name, "/top_level.txt") {
				filtered[name] = hash
			}
		}
		d.Files = filtered
		raw, _ := json.Marshal(d)
		if err := verifyPackageHashes(raw, root, members); err != nil {
			t.Fatal(err)
		}
	}
	check(evidence.HostDistribution, "/usr/local/lib/python3.13/dist-packages")
	found := false
	for command, result := range evidence.Commands {
		if strings.HasPrefix(command, "docker exec pmon python3 -B -c import hashlib") {
			var d distribution
			if err := json.Unmarshal([]byte(result.Stdout), &d); err != nil {
				t.Fatal(err)
			}
			check(d, "/usr/local/lib/python3.11/dist-packages")
			found = true
		}
	}
	if !found {
		t.Fatal("pmon installed distribution evidence missing")
	}
}

func TestPublishedSupervisorUnitMatchesGeneratedBaseline(t *testing.T) {
	raw, err := os.ReadFile("../../config/agent/sonic-operator-artifact-supervisor.service")
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != SupervisorUnit {
		t.Fatal("published supervisor unit differs from immutable protocol generator")
	}
}
