// SPDX-License-Identifier: Apache-2.0
package releasebundle

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
	"github.com/ironcore-dev/sonic-operator/internal/agent/releaseinfo"
	"github.com/ironcore-dev/sonic-operator/internal/artifact"
)

func TestNoHookProfilesRemainReadable(t *testing.T) {
	for _, name := range []string{"202411.1216684-48c2d4c3e.json", "202511.1217682-4784cca11.json"} {
		raw, err := os.ReadFile(filepath.Join("../../config/agent/profiles", name))
		if err != nil {
			t.Fatal(err)
		}
		p, err := host.ValidateNativeProfile(raw)
		if err != nil || p.ImportedMACEnvironment != "" || len(p.LegacyMACHooks) != 0 {
			t.Fatal("no-hook profile changed semantics", name, err)
		}
	}
}

func TestReleaseRejectsUnknownCapabilityAndWrongAcceptedFallback(t *testing.T) {
	i := releaseinfo.Current()
	i.SourceCommit = strings.Repeat("a", 40)
	b := Binary{Info: i, SHA256: strings.Repeat("b", 64), Size: 1, GoVersion: "go1.26.0"}
	r := Release{Format: Format, ReviewRequired: true, Builds: map[string]Binary{}, Fallbacks: []Binary{b}, AgentBuilds: map[string]artifact.ReleaseBuild{b.SHA256: i}, SourceFloors: []string{i.SourceCommit, strings.Repeat("b", 40)}}
	for _, role := range []string{"agent", "supervisor", "watchdog", "controller"} {
		r.Builds[role] = b
	}
	saved := Floors
	defer func() { Floors = saved }()
	savedMAC := ImportedMACFloors
	defer func() { ImportedMACFloors = savedMAC }()
	Floors, ImportedMACFloors = []string{i.SourceCommit, strings.Repeat("b", 40)}, nil
	if ValidateRelease(r) != nil {
		t.Fatal("valid release rejected")
	}
	legacy := b
	legacy.Capabilities = slices.DeleteFunc(slices.Clone(b.Capabilities), func(s string) bool { return s == releaseinfo.ImportedMACUnit })
	legacy.SHA256 = strings.Repeat("f", 64)
	r.Fallbacks = []Binary{legacy}
	r.AgentBuilds[legacy.SHA256] = legacy.Info
	if ValidateRelease(r) == nil {
		t.Fatal("legacy fallback cannot read new capability policy")
	}
	r.Fallbacks = []Binary{b}
	delete(r.AgentBuilds, legacy.SHA256)
	duplicated := r
	duplicated.SourceFloors = append([]string(nil), r.SourceFloors...)
	duplicated.SourceFloors[1] = duplicated.SourceFloors[0]
	if ValidateRelease(duplicated) == nil {
		t.Fatal("duplicate source floors disagree with schema")
	}
	r.AgentBuilds[b.SHA256] = releaseinfo.Info{SourceCommit: i.SourceCommit, Capabilities: append(i.Capabilities, "unknown")}
	if ValidateRelease(r) == nil {
		t.Fatal("unknown capability accepted")
	}
	r.AgentBuilds[b.SHA256] = i
	r.Fallbacks[0].SHA256 = strings.Repeat("c", 64)
	if ValidateRelease(r) == nil {
		t.Fatal("wrong fallback set accepted")
	}
}

func TestCapturedHooksPublicOnly(t *testing.T) {
	for _, raw := range []string{"[Service]\nExecStartPost=/usr/local/sbin/set-management-mac\n", "[Service]\nExecStartPost=/usr/bin/python3 /usr/local/sbin/dc-management-only-mac.py boot\n"} {
		if !publicHook([]byte(raw)) {
			t.Fatal("captured source rejected")
		}
	}
	for _, raw := range []string{"Environment=PASSWORD=SECRET", "-----BEGIN PRIVATE KEY-----", "ExecStartPost=/bin/sh -c secret", "community public", "ExecStartPost=/usr/bin/python3 /usr/local/sbin/dc-management-only-mac.py rollback"} {
		if publicHook([]byte(raw)) {
			t.Fatal("nonpublic or rollback hook accepted")
		}
	}
}

func TestAddressedOutputsReproducible(t *testing.T) {
	dir := t.TempDir()
	data := []byte("public metadata\n")
	a, err := WriteAddressed(dir, data)
	if err != nil {
		t.Fatal(err)
	}
	b, err := WriteAddressed(dir, data)
	if err != nil || a != b {
		t.Fatal("not reproducible", err)
	}
	got, _ := os.ReadFile(a)
	if !bytes.Equal(got, data) {
		t.Fatal("output changed")
	}
	_ = os.WriteFile(a, []byte("drift"), 0600)
	if _, err := WriteAddressed(dir, data); err == nil {
		t.Fatal("overwrote content-addressed conflict")
	}
}
