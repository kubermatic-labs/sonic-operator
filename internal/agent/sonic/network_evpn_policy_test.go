// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"strings"
	"testing"
)

func TestEVPNPeerPolicyExactReadback(t *testing.T) {
	policy, err := evpnBuildPeerPolicy("owner", "192.0.2.2", []string{"65001:100"}, []string{"65001:100", "65001:101"})
	if err != nil {
		t.Fatal(err)
	}
	config := evpnTestFRR + " address-family l2vpn evpn\n  neighbor 192.0.2.2 route-map " + policy.In + " in\n  neighbor 192.0.2.2 route-map " + policy.Out + " out\n  neighbor 192.0.2.2 send-community extended\n exit-address-family\n"
	for _, name := range []string{policy.In, policy.Out} {
		config += "bgp extcommunity-list standard " + name + " permit rt 65001:100\n"
		if name == policy.Out {
			config += "bgp extcommunity-list standard " + name + " permit rt 65001:101\n"
		}
		config += "route-map " + name + " permit 10\n match extcommunity " + name + "\n!\nroute-map " + name + " deny 65535\n!\n"
	}
	if err := evpnVerifyPeerPolicy([]byte(config), "65001", "192.0.2.2", policy); err != nil {
		t.Fatal(err)
	}
	// Captured SONiC FRR 10.4.1 writes sequence numbers on extcommunity
	// lists and explicit exit delimiters after route-map entries.
	native := strings.ReplaceAll(config, " permit rt 65001:100", " seq 5 permit rt 65001:100")
	native = strings.ReplaceAll(native, " permit rt 65001:101", " seq 10 permit rt 65001:101")
	native = strings.ReplaceAll(native, "\n!\n", "\nexit\n!\n")
	if err := evpnVerifyPeerPolicy([]byte(native), "65001", "192.0.2.2", policy); err != nil {
		t.Fatalf("native sequence/exit formatting rejected: %v", err)
	}
	// FRR 10.4.1 initializes extended-community sending enabled and renders
	// only its negation. Exact explicit policy attachments still must exist.
	defaults := strings.ReplaceAll(native, "  neighbor 192.0.2.2 send-community extended\n", "")
	if err := evpnVerifyPeerPolicy([]byte(defaults), "65001", "192.0.2.2", policy); err != nil {
		t.Fatalf("reviewed FRR default rejected: %v", err)
	}
	for _, bad := range []string{
		strings.ReplaceAll(native, " seq 10 permit", " seq 5 permit"),
		strings.ReplaceAll(native, " seq 5 permit", " seq 0 permit"),
		strings.ReplaceAll(native, " seq 5 permit", " seq bogus permit"),
	} {
		if err := evpnVerifyPeerPolicy([]byte(bad), "65001", "192.0.2.2", policy); err == nil {
			t.Fatal("invalid native sequence accepted")
		}
	}
	for name, bad := range map[string]string{
		"permit default":             strings.ReplaceAll(config, "deny 65535", "permit 65535"),
		"missing match":              strings.ReplaceAll(config, " match extcommunity "+policy.In+"\n", ""),
		"foreign permit":             config + "route-map " + policy.In + " permit 20\n!\n",
		"extra RT":                   config + "bgp extcommunity-list standard " + policy.In + " permit rt 65001:999\n",
		"wrong instance":             strings.Replace(config, "router bgp 65001", "router bgp 65001 vrf VrfOther", 1),
		"wrong AF":                   strings.Replace(config, "address-family l2vpn evpn", "address-family ipv4 unicast", 1),
		"call chain":                 strings.Replace(config, " match extcommunity "+policy.In, " call foreign\n match extcommunity "+policy.In, 1),
		"disabled extended":          strings.ReplaceAll(config, "  neighbor 192.0.2.2 send-community extended\n", "  no neighbor 192.0.2.2 send-community extended\n"),
		"disabled all":               strings.ReplaceAll(config, "  neighbor 192.0.2.2 send-community extended\n", "  no neighbor 192.0.2.2 send-community all\n"),
		"inherited peer":             strings.ReplaceAll(config, " neighbor 192.0.2.2 shutdown\n", " neighbor 192.0.2.2 shutdown\n neighbor 192.0.2.2 peer-group foreign\n"),
		"attachment inside VNI":      strings.Replace(config, " address-family l2vpn evpn\n", " address-family l2vpn evpn\n  vni 100\n", 1),
		"action after map separator": strings.Replace(config, " match extcommunity "+policy.In+"\n!", " match extcommunity "+policy.In+"\n!\n call foreign", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := evpnVerifyPeerPolicy([]byte(bad), "65001", "192.0.2.2", policy); err == nil {
				t.Fatal("unsafe policy readback accepted")
			}
		})
	}
}

func TestEVPNPeerPolicyNativeLists(t *testing.T) {
	p, err := evpnBuildPeerPolicy("owner", "192.0.2.2", []string{"65001:100"}, []string{"65001:101"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Rows["EXTENDED_COMMUNITY_SET|"+p.In]["community_member@"] != "route-target:65001:100" || p.Rows["ROUTE_MAP|"+p.Out+"|65535"]["route_operation"] != "deny" {
		t.Fatal("native route policy grammar not preserved")
	}
	if len(p.In) > 32 || len(p.Out) > 32 || p.In == p.Out {
		t.Fatal("invalid policy identities")
	}
	if _, err := evpnBuildPeerPolicy("", "192.0.2.2", []string{"65001:100"}, []string{"65001:100"}); err == nil {
		t.Fatal("missing owner accepted")
	}
}
