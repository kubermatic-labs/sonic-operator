// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
	"github.com/ironcore-dev/sonic-operator/internal/agent/releaseinfo"
)

func importedEnvironmentBootstrap(t *testing.T) *HostRecoveryBootstrap {
	h := hostBootstrapFixture(t)
	var p host.NativeProfile
	_ = json.Unmarshal(h.Profile, &p)
	p.ImportedMACEnvironment = host.ImportedMACEnvironmentNone
	p.LegacyMACHooks = []host.LegacyMACHook{{Kind: "management-mac-shell", BaseMAC: "00:00:5e:00:53:01", MAC: "02:00:5e:00:53:01", Addresses: []host.Address{{Prefix: "10.0.0.22/24", Gateway: "10.0.0.1"}}, HookSHA256: Digest(host.ImportedMACUnit("management-mac-shell")), HelperSHA256: host.ImportedHelperSHA256("management-mac-shell")}}
	p.ConsumerSHA256["imported-shell"] = Digest([]byte("interpreter"))
	h.Profile, _ = json.Marshal(p)
	h.ProfileSHA256 = Digest(h.Profile)
	dir := os.Getenv("SONIC_TEST_MAC_FIXTURE_DIR")
	if dir == "" {
		t.Skip("set SONIC_TEST_MAC_FIXTURE_DIR to the captured MAC helper scripts")
	}
	helper, err := os.ReadFile(filepath.Join(dir, "set-management-mac.sh"))
	if err != nil {
		t.Fatal(err)
	}
	source := []byte("[Service]\nExecStartPost=/usr/local/sbin/set-management-mac\n")
	h.MACHooks = []MACHookBootstrap{{Kind: "management-mac-shell", Helper: helper, HelperSHA256: Digest(helper), SourceHook: source, SourceHookSHA256: Digest(source)}}
	return h
}

func TestImportedEnvironmentRequiresCapableWatchdog(t *testing.T) {
	h := importedEnvironmentBootstrap(t)
	h.Binary = append(h.Binary, []byte(releaseinfo.LegacyMarker)...)
	h.BinarySHA256 = Digest(h.Binary)
	if err := h.Validate(true); err == nil {
		t.Fatal("legacy binary accepted with new profile")
	}
	h.Binary = append(h.Binary, []byte(releaseinfo.Marker)...)
	h.BinarySHA256 = Digest(h.Binary)
	if err := h.Validate(true); err != nil {
		t.Fatal("capable watchdog rejected", err)
	}
}

func TestImportedEnvironmentRequiresCapableFallbackPolicy(t *testing.T) {
	b, _ := bootstrapFixture(t)
	b.Bootstrap.Supervisor = append(b.Bootstrap.Supervisor, []byte(releaseinfo.Marker)...)
	b.Bootstrap.SupervisorSHA256 = Digest(b.Bootstrap.Supervisor)
	h := importedEnvironmentBootstrap(t)
	h.Binary = append(h.Binary, []byte(releaseinfo.Marker)...)
	h.BinarySHA256 = Digest(h.Binary)
	b.Bootstrap.HostRecovery = h
	i := releaseinfo.Current()
	i.SourceCommit = strings.Repeat("a", 40)
	legacy := i
	legacy.Capabilities = slices.DeleteFunc(slices.Clone(i.Capabilities), func(s string) bool { return s == releaseinfo.ImportedMACUnit })
	p := Policy{AgentBuilds: map[string]ReleaseBuild{strings.Repeat("b", 64): i, strings.Repeat("c", 64): legacy}}
	b.Bootstrap.Policy, _ = json.Marshal(p)
	b.Bootstrap.PolicySHA256 = Digest(b.Bootstrap.Policy)
	if err := b.Bootstrap.Validate(true); err == nil {
		t.Fatal("legacy fallback accepted for new immutable profile")
	}
	p.AgentBuilds[strings.Repeat("c", 64)] = i
	b.Bootstrap.Policy, _ = json.Marshal(p)
	b.Bootstrap.PolicySHA256 = Digest(b.Bootstrap.Policy)
	if err := b.Bootstrap.Validate(true); err != nil {
		t.Fatal("capable fallback policy rejected", err)
	}
}

func TestImportedSupervisorReaderFloor(t *testing.T) {
	for _, tc := range []struct {
		name, profile, supervisor      string
		newPolicy, mixedPolicy, reject bool
	}{
		{"environment-old-supervisor", "environment", releaseinfo.LegacyMarker, true, false, true},
		{"environment-capable", "environment", releaseinfo.Marker, true, false, false},
		{"no-hook-new-policy-old-supervisor", "no-hook", releaseinfo.LegacyMarker, true, false, true},
		{"no-hook-new-policy-capable", "no-hook", releaseinfo.Marker, true, false, false},
		{"no-host-new-policy-old-supervisor", "", releaseinfo.LegacyMarker, true, false, true},
		{"no-host-new-policy-capable", "", releaseinfo.Marker, true, false, false},
		{"no-hook-mixed-policy-old-supervisor", "no-hook", releaseinfo.LegacyMarker, true, true, true},
		{"no-hook-missing-declaration", "no-hook", "", true, false, true},
		{"wholly-legacy-no-hook", "no-hook", releaseinfo.LegacyMarker, false, false, false},
		{"wholly-legacy-retained-hook", "retained-hook", releaseinfo.LegacyMarker, false, false, false},
		{"legacy-policy-capable-supervisor", "no-hook", releaseinfo.Marker, false, false, false},
		{"wholly-legacy-no-host", "", releaseinfo.LegacyMarker, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, root := bootstrapFixture(t)
			b.Bootstrap.Supervisor = append(b.Bootstrap.Supervisor, []byte(tc.supervisor)...)
			b.Bootstrap.SupervisorSHA256 = Digest(b.Bootstrap.Supervisor)
			if tc.profile != "" {
				h := hostBootstrapFixture(t)
				marker := releaseinfo.LegacyMarker
				if tc.profile == "environment" || tc.profile == "retained-hook" {
					h = importedEnvironmentBootstrap(t)
					marker = releaseinfo.Marker
					if tc.profile == "retained-hook" {
						var p host.NativeProfile
						if err := json.Unmarshal(h.Profile, &p); err != nil {
							t.Fatal(err)
						}
						p.ImportedMACEnvironment = ""
						h.Profile, _ = json.Marshal(p)
						h.ProfileSHA256 = Digest(h.Profile)
						marker = releaseinfo.LegacyMarker
					}
				}
				h.Binary = append(h.Binary, []byte(marker)...)
				h.BinarySHA256 = Digest(h.Binary)
				b.Bootstrap.HostRecovery = h
				b.Agent = &AgentOptions{BindAddress: "0.0.0.0", Port: 50051, HostGuard: true}
			}
			i := releaseinfo.Current()
			i.SourceCommit = strings.Repeat("a", 40)
			legacy := i
			legacy.Capabilities = slices.DeleteFunc(slices.Clone(i.Capabilities), func(s string) bool { return s == releaseinfo.ImportedMACUnit })
			if !tc.newPolicy {
				i = legacy
			}
			var p Policy
			if err := Decode(b.Bootstrap.Policy, &p); err != nil {
				t.Fatal(err)
			}
			p.AgentBuilds = map[string]ReleaseBuild{strings.Repeat("b", 64): i}
			if tc.mixedPolicy {
				p.AgentBuilds[strings.Repeat("c", 64)] = legacy
			}
			b.Bootstrap.Policy, _ = json.Marshal(p)
			b.Bootstrap.PolicySHA256 = Digest(b.Bootstrap.Policy)
			// Metadata transport remains possible before the content reader is known.
			if err := b.WithoutContent().Bootstrap.Validate(false); err != nil {
				t.Fatal(err)
			}
			t.Run("content", func(t *testing.T) {
				err := b.Bootstrap.Validate(true)
				if (err != nil) != tc.reject || (tc.reject && !strings.Contains(err.Error(), "supervisor")) {
					t.Fatalf("supervisor content reader floor: %v, reject=%v", err, tc.reject)
				}
			})
			t.Run("installation", func(t *testing.T) {
				before := bootstrapTree(t, root)
				calls := 0
				err := EnsureBootstrap(t.Context(), root, b, func(context.Context) error { calls++; return nil })
				if tc.reject {
					if err == nil || !strings.Contains(err.Error(), "supervisor") {
						t.Errorf("incompatible supervisor was not rejected at content boundary: %v", err)
					}
					if calls != 0 || !reflect.DeepEqual(before, bootstrapTree(t, root)) {
						t.Fatalf("incompatible supervisor caused bootstrap writes/activation: calls=%d", calls)
					}
					return
				}
				if err != nil || calls != 1 {
					t.Fatalf("compatible bootstrap not activated: %v calls=%d", err, calls)
				}
				for path, want := range map[string][]byte{supervisorPath: b.Bootstrap.Supervisor, bootstrapPolicyPath: b.Bootstrap.Policy, supervisorUnitPath: []byte(SupervisorUnit)} {
					got, err := os.ReadFile(filepath.Join(root, path))
					if err != nil || Digest(got) != Digest(want) {
						t.Fatalf("bootstrap payload %s: %v", path, err)
					}
				}
				var owner bootstrapRecord
				raw, err := os.ReadFile(filepath.Join(root, bootstrapState, "owner.json"))
				if err != nil || Decode(raw, &owner) != nil || owner.Pending || owner.SupervisorSHA256 != b.Bootstrap.SupervisorSHA256 {
					t.Fatalf("bootstrap owner not finalized: %v", err)
				}
			})
		})
	}
}

func bootstrapTree(t *testing.T, root string) map[string]string {
	t.Helper()
	tree := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		tree[path] = info.Mode().String()
		if !d.IsDir() {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			tree[path] += Digest(raw)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return tree
}
