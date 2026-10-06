// SPDX-License-Identifier: Apache-2.0
package releasebundle

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
	"github.com/ironcore-dev/sonic-operator/internal/agent/releaseinfo"
	"github.com/ironcore-dev/sonic-operator/internal/artifact"
)

func TestSourceInputExplicitNativeEnvironment(t *testing.T) {
	var input SwitchInput
	if err := artifact.Decode([]byte(`{"switch":"leaf-02","importedMACEnvironment":"sonic-dpu-none-v1"}`), &input); err != nil {
		t.Fatal("explicit source recipe rejected", err)
	}
}

func TestSourceEnvironmentReaderFloorAndProfileHash(t *testing.T) {
	raw, err := os.ReadFile("../../config/agent/profiles/202511.1217682-4784cca11.json")
	if err != nil {
		t.Fatal(err)
	}
	base, err := host.ValidateNativeProfile(raw)
	if err != nil {
		t.Fatal(err)
	}
	i := releaseinfo.Current()
	i.SourceCommit = strings.Repeat("a", 40)
	for _, change := range []string{"valid", "legacy", "unknown", "no-hook", "old-reader", "old-fallback"} {
		t.Run(change, func(t *testing.T) {
			p := base
			p.ConsumerSHA256 = map[string]string{}
			for k, v := range base.ConsumerSHA256 {
				p.ConsumerSHA256[k] = v
			}
			r := Release{Builds: map[string]Binary{"watchdog": {Info: i}}, AgentBuilds: map[string]artifact.ReleaseBuild{strings.Repeat("b", 64): i}}
			recipe := host.ImportedMACEnvironmentNone
			p.LegacyMACHooks = []host.LegacyMACHook{{Kind: "management-mac-shell", BaseMAC: "00:00:5e:00:53:01", MAC: "02:00:5e:00:53:01", Addresses: []host.Address{{Prefix: "10.0.0.22/24", Gateway: "10.0.0.1"}}, HelperSHA256: host.ImportedHelperSHA256("management-mac-shell"), HookSHA256: artifact.Digest(host.ImportedMACUnit("management-mac-shell"))}}
			p.ConsumerSHA256["imported-shell"] = strings.Repeat("c", 64)
			legacy := i
			legacy.Capabilities = slices.DeleteFunc(slices.Clone(i.Capabilities), func(s string) bool { return s == releaseinfo.ImportedMACUnit })
			switch change {
			case "legacy":
				p = base
				recipe = ""
			case "unknown":
				recipe = "allow-extra-dropins"
			case "no-hook":
				p = base
			case "old-reader":
				r.Builds["watchdog"] = Binary{Info: legacy}
			case "old-fallback":
				r.AgentBuilds[strings.Repeat("b", 64)] = legacy
			}
			err := sourceImportedEnvironment(&p, recipe, r)
			if change != "valid" && change != "legacy" {
				if err == nil {
					t.Fatal("unqualified recipe accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := JSON(p)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := host.ValidateNativeProfile(encoded)
			if err != nil || decoded.ImportedMACEnvironment != recipe {
				t.Fatal("profile round trip lost recipe", err)
			}
			baseline, _ := JSON(base)
			if change == "legacy" && artifact.Digest(encoded) != artifact.Digest(baseline) {
				t.Fatal("no-hook profile serialization changed")
			}
			if change == "valid" {
				without := p
				without.ImportedMACEnvironment = ""
				old, _ := JSON(without)
				if artifact.Digest(encoded) == artifact.Digest(old) {
					t.Fatal("profile identity omitted recipe")
				}
				ref, cms, err := ChunkSource("HostProfile", encoded)
				if err != nil || ValidateChunks(ref, cms) != nil || ref.SHA256 != artifact.Digest(encoded) {
					t.Fatal("chunk metadata lost profile binding", err)
				}
			}
		})
	}
}

func TestSourceBinaryReplacementRetainsInspectedBytes(t *testing.T) {
	fixture := os.Getenv("SONIC_TEST_RELEASE_AGENT")
	if fixture == "" {
		t.Skip("set SONIC_TEST_RELEASE_AGENT to an actual clean floor-compatible Linux release agent")
	}
	original, err := ReadBounded(fixture, 96<<20)
	if err != nil {
		t.Fatal(err)
	}
	git, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "agent")
	replacement := filepath.Join(dir, "replacement")
	if err := os.WriteFile(path, original, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(replacement, append(append([]byte(nil), original...), []byte("concurrent-rebuild")...), 0755); err != nil {
		t.Fatal(err)
	}
	// InspectBinary checks ancestry after reading ELF/build metadata. Replace the
	// path at precisely that boundary, without altering the inspected byte buffer.
	wrapper := []byte("#!/bin/sh\nif [ \"$3\" = merge-base ] && [ -f \"$RELEASE_TEST_REPLACEMENT\" ]; then\n /bin/mv \"$RELEASE_TEST_REPLACEMENT\" \"$RELEASE_TEST_TARGET\" || exit 1\nfi\nexec \"$RELEASE_TEST_GIT\" \"$@\"\n")
	if err := os.WriteFile(filepath.Join(dir, "git"), wrapper, 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RELEASE_TEST_GIT", git)
	t.Setenv("RELEASE_TEST_TARGET", path)
	t.Setenv("RELEASE_TEST_REPLACEMENT", replacement)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	build, payload, err := readInspectedBinary(repo, path, "agent")
	if err != nil {
		t.Fatal(err)
	}
	current, err := ReadBounded(path, 96<<20)
	if err != nil || artifact.Digest(current) == artifact.Digest(original) {
		t.Fatal("replacement boundary did not execute", err)
	}
	source, objects, err := ChunkSource("AgentBinary", payload)
	if err != nil {
		t.Fatal(err)
	}
	if source.SHA256 != build.SHA256 || int64(source.Size) != build.Size || source.SHA256 != artifact.Digest(original) {
		t.Fatal("published payload changed after inspection")
	}
	if err := ValidateChunks(source, objects); err != nil {
		t.Fatal(err)
	}
}
