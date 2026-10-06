// SPDX-License-Identifier: Apache-2.0
package releasebundle

import (
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/ironcore-dev/sonic-operator/internal/agent/releaseinfo"
	"github.com/ironcore-dev/sonic-operator/internal/artifact"
)

// floorRepo creates a throwaway repository with a linear history
// base -> fix -> head and a side commit that does not contain fix.
func floorRepo(t *testing.T) (repo string, commits map[string]string) {
	t.Helper()
	repo = t.TempDir()
	git := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", repo, "-c", "user.name=test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false"}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Skipf("git unavailable: %v: %s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q", "-b", "main")
	commits = map[string]string{}
	for _, name := range []string{"base", "fix", "head"} {
		git("commit", "-q", "--allow-empty", "-m", name)
		commits[name] = git("rev-parse", "HEAD")
	}
	git("checkout", "-q", "-b", "side", commits["base"])
	git("commit", "-q", "--allow-empty", "-m", "side")
	commits["side"] = git("rev-parse", "HEAD")
	return repo, commits
}

func withFloors(t *testing.T, floors, mac []string) {
	t.Helper()
	savedFloors, savedMAC := Floors, ImportedMACFloors
	t.Cleanup(func() { Floors, ImportedMACFloors = savedFloors, savedMAC })
	Floors, ImportedMACFloors = floors, mac
}

func infoAt(commit string, mac bool) releaseinfo.Info {
	i := releaseinfo.Current()
	i.SourceCommit = commit
	i.Capabilities = slices.DeleteFunc(slices.Clone(i.Capabilities), func(c string) bool { return c == releaseinfo.ImportedMACUnit })
	if mac {
		i.Capabilities = append(i.Capabilities, releaseinfo.ImportedMACUnit)
	}
	return i
}

func TestCapabilityAncestry(t *testing.T) {
	repo, c := floorRepo(t)
	withFloors(t, []string{c["base"]}, []string{c["fix"]})
	for _, tc := range []struct {
		name, commit string
		mac, valid   bool
	}{
		{"legacy reader at base", c["base"], false, true},
		{"legacy reader on side branch", c["side"], false, true},
		{"MAC reader before fix", c["base"], true, false},
		{"MAC reader on side branch", c["side"], true, false},
		{"MAC reader at fix", c["fix"], true, true},
		{"MAC reader after fix", c["head"], true, true},
		{"unknown commit", strings.Repeat("0", 40), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := CheckAncestry(repo, infoAt(tc.commit, tc.mac)); (err == nil) != tc.valid {
				t.Fatalf("valid=%v: %v", tc.valid, err)
			}
		})
	}
	if CheckAncestry(t.TempDir(), infoAt(c["head"], true)) == nil {
		t.Fatal("unrelated source directory accepted")
	}
	i := infoAt(c["head"], false)
	i.SourceCommit = c["head"][:7]
	if CheckAncestry(repo, i) == nil {
		t.Fatal("abbreviated source accepted")
	}
}

func TestReleaseCapabilityFloors(t *testing.T) {
	legacyFloor, macFloor := strings.Repeat("a", 40), strings.Repeat("b", 40)
	withFloors(t, []string{legacyFloor}, []string{macFloor})
	release := func(mac bool) Release {
		b := Binary{Info: infoAt(strings.Repeat("c", 40), mac), SHA256: strings.Repeat("d", 64), Size: 1, GoVersion: "go1.26.0"}
		r := Release{Format: Format, ReviewRequired: true, Builds: map[string]Binary{}, Fallbacks: []Binary{b}, AgentBuilds: map[string]artifact.ReleaseBuild{b.SHA256: b.Info}}
		for _, role := range []string{"agent", "supervisor", "watchdog", "controller"} {
			r.Builds[role] = b
		}
		r.SourceFloors = requiredFloors(b.Info)
		return r
	}
	for _, tc := range []struct {
		name   string
		mac    bool
		change func(*Release)
		valid  bool
	}{
		{"legacy", false, func(*Release) {}, true},
		{"MAC", true, func(*Release) {}, true},
		{"MAC without its floor", true, func(r *Release) { r.SourceFloors = []string{legacyFloor} }, false},
		{"legacy with MAC floor", false, func(r *Release) { r.SourceFloors = append(r.SourceFloors, macFloor) }, false},
		{"unknown floor", false, func(r *Release) { r.SourceFloors = []string{strings.Repeat("e", 40)} }, false},
		{"duplicate floor", true, func(r *Release) { r.SourceFloors = []string{legacyFloor, legacyFloor} }, false},
		{"mixed reader capabilities", true, func(r *Release) {
			b := r.Builds["watchdog"]
			b.Info = infoAt(b.SourceCommit, false)
			r.Builds["watchdog"] = b
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := release(tc.mac)
			tc.change(&r)
			if err := ValidateRelease(r); (err == nil) != tc.valid {
				t.Fatalf("valid=%v: %v", tc.valid, err)
			}
		})
	}
}
