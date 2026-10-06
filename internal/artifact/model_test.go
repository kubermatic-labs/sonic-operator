// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"strings"
	"testing"
)

func TestTypedDestinationsAndIdentity(t *testing.T) {
	for _, slot := range []string{"PlatformComponent", "PlatformFanDrawer"} {
		if _, _, err := Destination(slot); err != nil {
			t.Fatalf("observed platform module missing: %s", slot)
		}
	}
	for _, slot := range []string{"../../etc/passwd", "/usr/local/sbin/sonic-operator-agent", "AgentUnit", "SupervisorBinary", "PlatformModule:../../evil"} {
		if _, _, err := Destination(slot); err == nil {
			t.Fatalf("accepted arbitrary destination %q", slot)
		}
	}
	path, mode, err := Destination("AgentKey")
	if err != nil || path != "/etc/sonic-operator-agent/tls.key" || mode != 0600 {
		t.Fatalf("key destination: %s %o %v", path, mode, err)
	}
	b := testBundle()
	if err := b.Validate(true); err != nil {
		t.Fatal(err)
	}
	b.Files[0].Data = []byte("tampered")
	if err := b.Validate(true); err == nil {
		t.Fatal("accepted content hash mismatch")
	}
	b = testBundle()
	b.Owner = ""
	if err := b.Validate(true); err == nil {
		t.Fatal("accepted missing owner")
	}
	b = testBundle()
	b.Files = append(b.Files, b.Files[0])
	if err := b.Validate(true); err == nil {
		t.Fatal("accepted duplicate slot")
	}
}

func TestGeneratedAgentUnitIsBounded(t *testing.T) {
	o := AgentOptions{BindAddress: "10.0.0.2", Port: 50051, Network: true, Artifacts: true}
	text, err := AgentUnit(o)
	if err != nil || !strings.Contains(string(text), "--allow-network-config=true") || !strings.Contains(string(text), "--tls-key-file=/etc/sonic-operator-agent/tls.key") {
		t.Fatalf("unit: %s %v", text, err)
	}
	o.BindAddress = "1.2.3.4\nExecStart=/bin/sh"
	if _, err := AgentUnit(o); err == nil {
		t.Fatal("accepted command injection")
	}
}

func TestAgentHostCapabilityUsesBoundedPersistentJournal(t *testing.T) {
	unit, err := AgentUnit(AgentOptions{BindAddress: "10.0.0.21", Port: 50051, HostConfig: true})
	if err != nil || !strings.Contains(string(unit), "--allow-host-config=true --host-journal-dir=/host/sonic-operator-host-journal") {
		t.Fatalf("host coordination flags missing: %s %v", unit, err)
	}
	unit, err = AgentUnit(AgentOptions{BindAddress: "10.0.0.21", Port: 50051, HostGuard: true})
	if err != nil || !strings.Contains(string(unit), "--allow-host-config=false --host-journal-dir=/host/sonic-operator-host-journal") {
		t.Fatal("cooperating guard not retained with writes disabled")
	}
}

func TestAgentBindAddressCannotInjectSystemdThroughIPv6Zone(t *testing.T) {
	if _, err := AgentUnit(AgentOptions{BindAddress: "fe80::1%eth0\nExecStart=/bin/sh", Port: 50051}); err == nil {
		t.Fatal("IPv6 zone injected unit directives")
	}
	if _, err := AgentUnit(AgentOptions{BindAddress: "0.0.0.0", Port: 50051}); err != nil {
		t.Fatal("typed wildcard listener needed for managed address transitions was rejected")
	}
}

func testBundle() Bundle {
	data := []byte(`{"ports":[]}`)
	return Bundle{Owner: "resource-uid", Target: "switch-uid@endpoint", Generation: 1, Baseline: "test-baseline", Files: []File{{Slot: "PlatformJSON", SHA256: Digest(data), Data: data}}}
}
