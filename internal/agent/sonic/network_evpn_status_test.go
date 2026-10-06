// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"strings"
	"testing"
)

func TestEVPNSessionSummaryRequiresExpectedPeer(t *testing.T) {
	s := evpnPeerSpec{Address: "192.0.2.2", RemoteASN: 65002, LocalAddress: "192.0.2.1", AdminState: "Up"}
	for _, tc := range []struct {
		raw   string
		ready bool
	}{
		{`{}`, false},
		{`{"peers":{"192.0.2.2":{"remoteAs":65002,"state":"Established"}}}`, true},
		{`{"peers":{"192.0.2.2":{"remoteAs":65003,"state":"Established"}}}`, false},
		{`{"peers":{"192.0.2.2":{"remoteAs":65002,"state":"Idle"}}}`, false},
		{`{"peers":{"192.0.2.3":{"remoteAs":65002,"state":"Established"}}}`, false},
	} {
		ok, err := evpnSessionSummary([]byte(tc.raw), s)
		if err != nil || ok != tc.ready {
			t.Fatalf("summary=%s ready=%v err=%v", tc.raw, ok, err)
		}
	}
}

func TestEVPNNegotiatedCapability(t *testing.T) {
	s := evpnPeerSpec{Address: "192.0.2.2", RemoteASN: 65002, LocalAddress: "192.0.2.1"}
	// FRR 10.4.1 bgp_vty.c: bgpState, hostLocal and multiprotocolExtensions.
	raw := `{"192.0.2.2":{"remoteAs":65002,"hostLocal":"192.0.2.1","bgpState":"Established","neighborCapabilities":{"multiprotocolExtensions":{"l2VpnEvpn":{"advertisedAndReceived":true}}}}}`
	if ok, err := evpnNegotiated([]byte(raw), s); err != nil || !ok {
		t.Fatalf("negotiation: %v %v", ok, err)
	}
	for _, bad := range []string{`{}`, strings.Replace(raw, "true", "false", 1), strings.Replace(raw, "l2VpnEvpn", "ipv4Unicast", 1), strings.Replace(raw, "192.0.2.1", "192.0.2.9", 1), strings.Replace(raw, "65002", "65003", 1)} {
		if ok, _ := evpnNegotiated([]byte(bad), s); ok {
			t.Fatal("invalid capability/source accepted")
		}
	}
}

func TestEVPNRouteCounts(t *testing.T) {
	two, three, err := evpnRouteCounts([]byte(`{"65001:100":{"[2]:[0]:[0]:[48]:[02:00:00:00:00:01]":{"prefix":"[2]:[0]:[0]:[48]:[02:00:00:00:00:01]","paths":[]},"[3]:[0]:[32]:[192.0.2.2]":{"prefix":"[3]:[0]:[32]:[192.0.2.2]","paths":[]}},"numPrefix":2}`))
	if err != nil || two != 1 || three != 1 {
		t.Fatalf("routes=%d/%d err=%v", two, three, err)
	}
}
