// SPDX-License-Identifier: Apache-2.0
// Package releaseinfo declares implemented reader/writer support, not authority.
package releaseinfo

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"runtime/debug"
	"slices"
)

// Marker is retained in each executable by Current. Release tooling verifies
// this bounded compiled declaration alongside Go VCS provenance and ELF identity.
const Marker = `SONIC-RELEASE-V1:["routing-safe-writers-v1","artifact-reservation-v1","artifact-chunks-v1","host-observed-active-mac-v1","host-causal-runtime-v1","host-artifact-admission-v1","host-mac-ownership-v1","host-bootstrap-v1"]:END-SONIC-RELEASE`

var compiledDeclaration = Marker

type Info struct {
	SourceCommit string   `json:"sourceCommit"`
	Capabilities []string `json:"capabilities"`
}

// SourceCommit is stamped by the reproducible release build. Unstamped developer
// builds retain their VCS identity when available and never invent a release SHA.
var SourceCommit string

var capabilities = [...]string{
	"routing-safe-writers-v1", "artifact-reservation-v1", "artifact-chunks-v1",
	"host-observed-active-mac-v1", "host-causal-runtime-v1", "host-artifact-admission-v1",
	"host-mac-ownership-v1", "host-bootstrap-v1",
}
var commitPattern = regexp.MustCompile(`^[a-f0-9]{40}$`)

func Current() Info {
	commit := SourceCommit
	if commit == "" {
		if b, ok := debug.ReadBuildInfo(); ok {
			for _, s := range b.Settings {
				if s.Key == "vcs.revision" {
					commit = s.Value
				}
			}
		}
	}
	var caps []string
	_ = json.Unmarshal([]byte(compiledDeclaration[len("SONIC-RELEASE-V1:"):len(compiledDeclaration)-len(":END-SONIC-RELEASE")]), &caps)
	return Info{SourceCommit: commit, Capabilities: caps}
}

// PrintRequested is a local, read-only mode usable before native dependencies.
func PrintRequested() bool {
	if len(os.Args) != 2 || os.Args[1] != "--release-info" {
		return false
	}
	_ = json.NewEncoder(os.Stdout).Encode(Current())
	return true
}

// Validate requires the exact, bounded integrated floor. Unknown names do not
// certify future behavior; adding one requires a reviewed policy migration.
func Validate(i Info) error {
	if !commitPattern.MatchString(i.SourceCommit) || len(i.Capabilities) != len(capabilities) {
		return fmt.Errorf("invalid release declaration")
	}
	seen := map[string]bool{}
	for _, c := range i.Capabilities {
		if !slices.Contains(capabilities[:], c) || seen[c] {
			return fmt.Errorf("unsupported release capability")
		}
		seen[c] = true
	}
	return nil
}

func Equal(a, b Info) bool {
	if Validate(a) != nil || Validate(b) != nil || a.SourceCommit != b.SourceCommit {
		return false
	}
	return true // Validation requires the exact same finite set, independent of order.
}
