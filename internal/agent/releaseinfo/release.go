// SPDX-License-Identifier: Apache-2.0
// Package releaseinfo declares implemented reader/writer support, not authority.
package releaseinfo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"runtime/debug"
	"slices"
)

// Marker is retained in each executable by Current. Release tooling verifies
// this bounded compiled declaration alongside Go VCS provenance and ELF identity.
const LegacyMarker = `SONIC-RELEASE-V1:["routing-safe-writers-v1","artifact-reservation-v1","artifact-chunks-v1","host-observed-active-mac-v1","host-causal-runtime-v1","host-artifact-admission-v1","host-mac-ownership-v1","host-bootstrap-v1"]:END-SONIC-RELEASE`
const Marker = `SONIC-RELEASE-V1:["routing-safe-writers-v1","artifact-reservation-v1","artifact-chunks-v1","host-observed-active-mac-v1","host-causal-runtime-v1","host-artifact-admission-v1","host-mac-ownership-v1","host-bootstrap-v1","host-imported-mac-unit-v1"]:END-SONIC-RELEASE`
const ImportedMACUnit = "host-imported-mac-unit-v1"

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

// Validate requires the eight-capability legacy floor and permits only the
// additional imported-unit reader. Profile-specific readers require it explicitly;
// old policies remain readable. Unknown names never certify future behavior.
func Validate(i Info) error {
	if !commitPattern.MatchString(i.SourceCommit) || (len(i.Capabilities) != len(capabilities) && len(i.Capabilities) != len(capabilities)+1) {
		return fmt.Errorf("invalid release declaration")
	}
	seen := map[string]bool{}
	for _, c := range i.Capabilities {
		if (!slices.Contains(capabilities[:], c) && c != ImportedMACUnit) || seen[c] {
			return fmt.Errorf("unsupported release capability")
		}
		seen[c] = true
	}
	for _, c := range capabilities {
		if !seen[c] {
			return fmt.Errorf("missing release capability")
		}
	}
	return nil
}

func Equal(a, b Info) bool {
	if Validate(a) != nil || Validate(b) != nil || a.SourceCommit != b.SourceCommit || len(a.Capabilities) != len(b.Capabilities) {
		return false
	}
	return true // Same finite capability set, independent of order.
}

// BinaryCapabilities preserves the declaration actually present in the binary;
// inspecting an older release must not copy the inspecting tool's capabilities.
// As with the original marker, this is provenance metadata, not an approval.
func BinaryCapabilities(raw []byte) ([]string, error) {
	marker := Marker
	if !bytes.Contains(raw, []byte(marker)) {
		marker = LegacyMarker
		if !bytes.Contains(raw, []byte(marker)) {
			return nil, fmt.Errorf("compiled release declaration unavailable")
		}
	}
	var caps []string
	err := json.Unmarshal([]byte(marker[len("SONIC-RELEASE-V1:"):len(marker)-len(":END-SONIC-RELEASE")]), &caps)
	return caps, err
}

func SupportsImportedMACUnit(i Info) bool {
	return Validate(i) == nil && slices.Contains(i.Capabilities, ImportedMACUnit)
}
