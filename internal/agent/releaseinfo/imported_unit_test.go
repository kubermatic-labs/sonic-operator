// SPDX-License-Identifier: Apache-2.0
package releaseinfo

import (
	"slices"
	"strings"
	"testing"
)

func TestImportedUnitReaderCapability(t *testing.T) {
	i := Current()
	i.SourceCommit = strings.Repeat("a", 40)
	if !slices.Contains(i.Capabilities, "host-imported-mac-unit-v1") {
		t.Fatal("new profile reader lacks compiled capability")
	}
	if Validate(i) != nil {
		t.Fatal("current declaration invalid")
	}
	legacy := i
	legacy.Capabilities = slices.DeleteFunc(slices.Clone(i.Capabilities), func(s string) bool { return s == "host-imported-mac-unit-v1" })
	if Validate(legacy) != nil {
		t.Fatal("legacy eight-capability policy no longer readable")
	}
	if Equal(i, legacy) {
		t.Fatal("old declaration claimed new profile support")
	}
}

func TestBinaryCapabilitiesPreserveLegacyDeclaration(t *testing.T) {
	for _, marker := range []string{LegacyMarker, Marker} {
		caps, err := BinaryCapabilities([]byte("binary-prefix" + marker + "binary-suffix"))
		if err != nil {
			t.Fatal(err)
		}
		i := Info{SourceCommit: strings.Repeat("a", 40), Capabilities: caps}
		if Validate(i) != nil || SupportsImportedMACUnit(i) != (marker == Marker) {
			t.Fatal("inspector misrepresented binary reader")
		}
	}
	if _, err := BinaryCapabilities([]byte("SONIC-RELEASE-V1:[\"host-imported-mac-unit-v1\"]:END-SONIC-RELEASE")); err == nil {
		t.Fatal("partial marker certified")
	}
}
