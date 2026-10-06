// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"strings"
	"testing"
)

// Exact empty pathd block observed on SONiC202511 / FRR10.4.1 after
// traditional->unified restart on leaf-03, 2026-09-12. It is emitted by
// pathd's running-config writer, not the sonic-cfggen startup candidate.
const frrMigrationEmptyPathd = "segment-routing\n traffic-eng\n exit\nexit\n"

func TestFRRMigrationUnifiedPathdBaseline(t *testing.T) {
	config := strings.ReplaceAll(frrMigrationDefaultConfig, "no service integrated-vtysh-config", "service integrated-vtysh-config")
	config = strings.ReplaceAll(config, "end\n", frrMigrationEmptyPathd+"!\nend\n")
	if err := frrMigrationEmptyRuntimeConfig([]byte(config), "leaf-03", true); err != nil {
		t.Fatal(err)
	}
	if err := frrMigrationEmptyRuntimeConfig([]byte(config), "leaf-03", false); err == nil {
		t.Fatal("traditional preflight accepted unified-only block")
	}
	if err := frrMigrationEmptyConfig([]byte(config), "leaf-03"); err == nil {
		t.Fatal("candidate validation accepted runtime-only block")
	}
	for _, tc := range []struct{ name, block string }{
		{"policy", "segment-routing\n traffic-eng\n  policy color 1 endpoint 192.0.2.1\n exit\nexit\n"},
		{"segment-list", "segment-routing\n traffic-eng\n  segment-list STEER\n exit\nexit\n"},
		{"pcep", "segment-routing\n traffic-eng\n  pcep\n exit\nexit\n"},
		{"srv6", "segment-routing\n srv6\n exit\nexit\n"},
		{"static-route", "segment-routing\n traffic-eng\n ip route 0.0.0.0/0 192.0.2.1\n exit\nexit\n"},
		{"route-map", "segment-routing\n traffic-eng\n route-map EXPORT permit 10\n exit\nexit\n"},
		{"prefix-list", "segment-routing\n traffic-eng\n ip prefix-list EXPORT permit 0.0.0.0/0\n exit\nexit\n"},
		{"bgp", "segment-routing\n traffic-eng\n router bgp 65000\n exit\nexit\n"},
		{"incomplete", "segment-routing\n traffic-eng\n exit\n"},
		{"wrong-nesting", "segment-routing\ntraffic-eng\nexit\nexit\n"},
		{"extra-exit", frrMigrationEmptyPathd + "exit\n"},
		{"duplicate", frrMigrationEmptyPathd + frrMigrationEmptyPathd},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := strings.Replace(config, frrMigrationEmptyPathd, tc.block, 1)
			if err := frrMigrationEmptyRuntimeConfig([]byte(bad), "leaf-03", true); err == nil {
				t.Fatal("populated or malformed runtime block accepted")
			}
		})
	}
}
