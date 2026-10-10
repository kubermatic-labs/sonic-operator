// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

func routingRequest(kind, spec string) *agent.NetworkRequest {
	return &agent.NetworkRequest{Kind: kind, OwnerID: "test-owner", Spec: json.RawMessage(spec)}
}

func routingDB() vlanChangeDB {
	return vlanChangeDB{
		"DEVICE_METADATA|localhost":             {"frr_mgmt_framework_config": "true", "has_sonic_dhcpv4_relay": "True"},
		"VLAN|Vlan100":                          {"vlanid": "100", "description": "unmanaged"},
		"VLAN_INTERFACE|Vlan100":                {},
		"VLAN_INTERFACE|Vlan100|192.0.2.1/24":   {},
		"VLAN_INTERFACE|Vlan100|2001:db8::1/64": {},
	}
}

func TestRoutingBGPPlan(t *testing.T) {
	t.Parallel()
	db := routingDB()
	before, _ := json.Marshal(db)
	p, err := planNetworkBGP(db, routingRequest("BGP", `{"localASN":65000,"routerID":"192.0.2.1"}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Identity != "BGP|default" || p.Runtime == nil {
		t.Fatalf("incomplete plan: %+v", p)
	}
	want := map[string]string{"local_asn": "65000", "router_id": "192.0.2.1", "default_ipv4_unicast": "false", "default_shutdown": "false"}
	if !reflect.DeepEqual(p.Desired["BGP_GLOBALS|default"], want) {
		t.Fatalf("global: %v", p.Desired)
	}
	for key := range p.Desired {
		if strings.HasPrefix(key, "BGP_GLOBALS_AF_NETWORK|") || strings.HasPrefix(key, "ROUTE_REDISTRIBUTE|") {
			t.Fatalf("implicit advertisement: %s", key)
		}
	}
	for _, family := range []string{"ipv4_unicast", "ipv6_unicast"} {
		name := routingExportName("default", family)
		if len(p.Desired["PREFIX_SET|"+name]) == 0 {
			t.Fatalf("missing export filter %s", family)
		}
	}
	after, _ := json.Marshal(db)
	if string(before) != string(after) {
		t.Fatal("planner mutated snapshot")
	}
	p, err = planNetworkBGP(db, routingRequest("BGP", `{"localASN":65000,"routerID":"192.0.2.1","prefixes":["192.0.2.0/24","2001:db8::/64"]}`))
	if err != nil {
		t.Fatal(err)
	}
	// frrcfgd drops network statements processed before the instance exists:
	// the first write creates the instance only, the next one adds networks.
	for key := range p.Desired {
		if strings.HasPrefix(key, "BGP_GLOBALS_AF_NETWORK|") {
			t.Fatalf("network written together with a new instance: %s", key)
		}
	}
	db["BGP_GLOBALS|default"] = p.Desired["BGP_GLOBALS|default"]
	p, err = planNetworkBGP(db, routingRequest("BGP", `{"localASN":65000,"routerID":"192.0.2.1","prefixes":["192.0.2.0/24","2001:db8::/64"]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"BGP_GLOBALS_AF_NETWORK|default|ipv4_unicast|192.0.2.0/24", "BGP_GLOBALS_AF_NETWORK|default|ipv6_unicast|2001:db8::/64"} {
		if p.Desired[key]["backdoor"] != "false" {
			t.Fatalf("missing explicit network %s", key)
		}
	}
}

func TestRoutingRejectsUnsafeSpecs(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, kind, spec, contains string }{
		{"unknown", "BGP", `{"localASN":65000,"routerID":"192.0.2.1","redistribute":true}`, "unknown"},
		{"duplicate field", "BGP", `{"localASN":65000,"localASN":1,"routerID":"192.0.2.1"}`, "duplicate"},
		{"duplicate nested field", "BGP", `{"localASN":65000,"routerID":"192.0.2.1","switchRef":{"name":"one","name":"two"}}`, "duplicate"},
		{"array null element", "DHCPRelay", `{"vlanID":100,"ipv4Servers":[null]}`, "address"},
		{"case mismatch", "BGP", `{"LocalASN":65000,"routerID":"192.0.2.1"}`, "unknown"},
		{"null", "BGP", `{"localASN":65000,"routerID":null}`, "null"},
		{"trailing", "BGP", `{"localASN":65000,"routerID":"192.0.2.1"} {}`, "JSON"},
		{"zero ASN", "BGP", `{"localASN":0,"routerID":"192.0.2.1"}`, "localASN"},
		{"IPv6 router ID", "BGP", `{"localASN":1,"routerID":"2001:db8::1"}`, "routerID"},
		{"host bits", "BGP", `{"localASN":1,"routerID":"192.0.2.1","prefixes":["192.0.2.1/24"]}`, "canonical"},
		{"duplicate prefix", "BGP", `{"localASN":1,"routerID":"192.0.2.1","prefixes":["::/0","::/0"]}`, "duplicate"},
		{"VRF injection", "BGP", `{"vrf":"default;touch /tmp/pwn","localASN":1,"routerID":"192.0.2.1"}`, "vrf"},
		{"mapped peer", "BGPPeer", `{"address":"::ffff:192.0.2.2","remoteASN":1,"addressFamilies":["ipv6Unicast"]}`, "address"},
		{"empty AF", "BGPPeer", `{"address":"192.0.2.2","remoteASN":1}`, "addressFamilies"},
		{"zero max", "BGPPeer", `{"address":"192.0.2.2","remoteASN":1,"addressFamilies":["ipv4Unicast"],"maxPrefixes":0}`, "maxPrefixes"},
		{"wrong server family", "DHCPRelay", `{"vlanID":100,"ipv4Servers":["2001:db8::2"]}`, "IPv4"},
		{"multicast", "DHCPRelay", `{"vlanID":100,"ipv6Servers":["ff02::1:2"]}`, "unicast"},
		{"linklocal", "DHCPRelay", `{"vlanID":100,"ipv6Servers":["fe80::2"]}`, "unicast"},
		{"scope", "DHCPRelay", `{"vlanID":100,"ipv6Servers":["fe80::2%Vlan100"]}`, "unicast"},
		{"empty servers", "DHCPRelay", `{"vlanID":100}`, "empty"},
		{"duplicate server", "DHCPRelay", `{"vlanID":100,"ipv4Servers":["192.0.2.2","192.0.2.2"]}`, "duplicate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := routingDB()
			var err error
			r := routingRequest(tc.kind, tc.spec)
			switch tc.kind {
			case "BGP":
				_, err = planNetworkBGP(db, r)
			case "BGPPeer":
				_, err = planNetworkBGPPeer(db, r)
			case "DHCPRelay":
				_, err = planNetworkDHCPRelay(db, r)
			}
			if err == nil || !strings.Contains(err.Error(), tc.contains) {
				t.Fatalf("error = %v, want %q", err, tc.contains)
			}
		})
	}
}

func TestRoutingPeerDefaults(t *testing.T) {
	t.Parallel()
	db := routingDB()
	bgp, err := planNetworkBGP(db, routingRequest("BGP", `{"localASN":65000,"routerID":"192.0.2.1"}`))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range bgp.Desired {
		db[k] = v
	}
	for _, address := range []string{"192.0.2.2", "2001:db8::2"} {
		p, err := planNetworkBGPPeer(db, routingRequest("BGPPeer", fmt.Sprintf(`{"address":%q,"remoteASN":65001,"addressFamilies":["ipv4Unicast","ipv6Unicast"]}`, address)))
		if err != nil {
			t.Fatal(err)
		}
		key := "BGP_NEIGHBOR|default|" + address
		if p.Desired[key]["admin_status"] != "down" {
			t.Fatal("peer defaults Up")
		}
		for _, af := range []string{"ipv4_unicast", "ipv6_unicast"} {
			fields := p.Desired["BGP_NEIGHBOR_AF|default|"+address+"|"+af]
			if fields["max_prefix_limit"] != "1000" || fields["prefix_list_out"] != routingExportName("default", af) {
				t.Fatalf("unprotected peer: %v", fields)
			}
		}
	}
}

func TestRoutingCapabilityGates(t *testing.T) {
	t.Parallel()
	db := routingDB()
	delete(db["DEVICE_METADATA|localhost"], "frr_mgmt_framework_config")
	if p, err := planNetworkBGP(db, routingRequest("BGP", `{"localASN":1,"routerID":"192.0.2.1"}`)); err == nil || p != nil || !strings.Contains(err.Error(), "traditional") {
		t.Fatalf("traditional BGP: %v %v", p, err)
	}
	if p, err := planNetworkBGPPeer(db, routingRequest("BGPPeer", `{"address":"192.0.2.2","remoteASN":1,"addressFamilies":["ipv4Unicast"]}`)); err == nil || p != nil || !strings.Contains(err.Error(), "maxPrefixes") {
		t.Fatalf("traditional peer: %v %v", p, err)
	}
	delete(db["DEVICE_METADATA|localhost"], "has_sonic_dhcpv4_relay")
	if p, err := planNetworkDHCPRelay(db, routingRequest("DHCPRelay", `{"vlanID":100,"ipv4Servers":["192.0.2.2"]}`)); err != nil || p == nil || p.Activate == nil {
		t.Fatalf("legacy relay: %v %v", p, err)
	}
	if p, err := planNetworkDHCPRelay(db, routingRequest("DHCPRelay", `{"vlanID":100,"ipv6Servers":["2001:db8::2"]}`)); err != nil || p == nil || p.Activate == nil {
		t.Fatalf("IPv6 relay: %v %v", p, err)
	}
}

func TestRoutingPeerUpRequiresPreflight(t *testing.T) {
	t.Parallel()
	db := routingDB()
	bgp, err := planNetworkBGP(db, routingRequest("BGP", `{"localASN":65000,"routerID":"192.0.2.1"}`))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range bgp.Desired {
		db[k] = v
	}
	down, err := planNetworkBGPPeer(db, routingRequest("BGPPeer", `{"address":"192.0.2.2","remoteASN":65001,"addressFamilies":["ipv4Unicast"]}`))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range down.Desired {
		db[k] = v
	}
	// Staged Redis policy permits planning, but never skips actual FRR preflight.
	if p, err := planNetworkBGPPeer(db, routingRequest("BGPPeer", `{"address":"192.0.2.2","remoteASN":65001,"addressFamilies":["ipv4Unicast"],"adminState":"Up"}`)); err != nil || p == nil || p.Preflight == nil {
		t.Fatalf("Up without preflight: %v %v", p, err)
	}
}

func TestRoutingConflictingAdvertisements(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, key, field, value string }{
		{"redistribution", "ROUTE_REDISTRIBUTE|default|connected|bgp|ipv4", "route_map", "UNMANAGED"},
		{"other network", "BGP_GLOBALS_AF_NETWORK|default|ipv4_unicast|198.51.100.0/24", "backdoor", "false"},
		{"import VRF", "BGP_GLOBALS_AF|default|ipv6_unicast", "import_vrf", "VrfBlue"},
		{"ASN change", "BGP_GLOBALS|default", "local_asn", "65001"},
		{"extra export rule", "PREFIX|" + routingExportName("default", "ipv4_unicast") + "|5|0.0.0.0/0|exact", "action", "permit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := routingDB()
			db[tc.key] = map[string]string{tc.field: tc.value}
			if p, err := planNetworkBGP(db, routingRequest("BGP", `{"localASN":65000,"routerID":"192.0.2.1"}`)); err == nil || p != nil {
				t.Fatalf("unsafe plan: %v %v", p, err)
			}
		})
	}
}

func TestRoutingNoPolicyChangesWhilePeersUp(t *testing.T) {
	t.Parallel()
	db := routingDB()
	r := routingRequest("BGP", `{"localASN":65000,"routerID":"192.0.2.1"}`)
	p, err := planNetworkBGP(db, r)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range p.Desired {
		db[k] = v
	}
	db["BGP_NEIGHBOR|default|192.0.2.2"] = map[string]string{"admin_status": "up", "asn": "65001"}
	if _, err := planNetworkBGP(db, r); err != nil {
		t.Fatalf("no-op rejected: %v", err)
	}
	if p, err := planNetworkBGP(db, routingRequest("BGP", `{"localASN":65000,"routerID":"192.0.2.1","prefixes":["192.0.2.0/24"]}`)); err == nil || p != nil {
		t.Fatalf("changed export policy with active peers: %v %v", p, err)
	}
}

func TestRoutingRelayPlan(t *testing.T) {
	t.Parallel()
	db := routingDB()
	db["DHCP_RELAY|Vlan100"] = map[string]string{"dhcpv6_servers@": "2001:db8::2", "unmanaged": "keep"}
	p, err := planNetworkDHCPRelay(db, routingRequest("DHCPRelay", `{"vlanID":100,"ipv4Servers":["192.0.2.2"],"ipv6Servers":["2001:db8::2"]}`))
	if err != nil {
		t.Fatal(err)
	}
	want := vlanChangeDB{"DHCPV4_RELAY|Vlan100": {"dhcpv4_servers@": "192.0.2.2"}, "DHCP_RELAY|Vlan100": {"dhcpv6_servers@": "2001:db8::2"}}
	if !reflect.DeepEqual(p.Desired, want) {
		t.Fatalf("got %v want %v", p.Desired, want)
	}
	delete(db, "VLAN_INTERFACE|Vlan100|2001:db8::1/64")
	if _, err := planNetworkDHCPRelay(db, routingRequest("DHCPRelay", `{"vlanID":100,"ipv6Servers":["2001:db8::2"]}`)); err == nil || !strings.Contains(err.Error(), "SVI") {
		t.Fatalf("missing v6 SVI: %v", err)
	}
	db["VLAN_INTERFACE|Vlan100"]["vrf_name"] = "VrfBlue"
	if _, err := planNetworkDHCPRelay(db, routingRequest("DHCPRelay", `{"vlanID":100,"ipv4Servers":["192.0.2.2"]}`)); err == nil || !strings.Contains(err.Error(), "VRF") {
		t.Fatalf("VRF mismatch: %v", err)
	}
}

func TestRoutingNativeRelayVRF(t *testing.T) {
	t.Parallel()
	db := routingDB()
	db["VRF|VrfBlue"] = map[string]string{"NULL": "NULL"}
	db["VLAN_INTERFACE|Vlan100"]["vrf_name"] = "VrfBlue"
	if p, err := planNetworkDHCPRelay(db, routingRequest("DHCPRelay", `{"vlanID":100,"vrf":"VrfBlue","ipv4Servers":["192.0.2.2"]}`)); err != nil || p.Desired["DHCPV4_RELAY|Vlan100"]["dhcpv4_servers@"] != "192.0.2.2" {
		t.Fatalf("native same VRF: %v %v", p, err)
	}
	db["DHCP_RELAY|Vlan100"] = map[string]string{"dhcpv6_servers@": "2001:db8::2"}
	if p, err := planNetworkDHCPRelay(db, routingRequest("DHCPRelay", `{"vlanID":100,"vrf":"VrfBlue","ipv6Servers":["2001:db8::2"]}`)); err == nil || p != nil {
		t.Fatalf("unsupported IPv6 VRF: %v %v", p, err)
	}
}

func TestRoutingCrossFeatureConsumerGrammar(t *testing.T) {
	t.Parallel()
	db := routingDB()
	bgp, err := planNetworkBGP(db, routingRequest("BGP", `{"localASN":65000,"routerID":"192.0.2.1","prefixes":["192.0.2.0/24","2001:db8::/64"]}`))
	if err != nil {
		t.Fatal(err)
	}
	relay, err := planNetworkDHCPRelay(db, routingRequest("DHCPRelay", `{"vlanID":100,"ipv4Servers":["192.0.2.2"],"ipv6Servers":["2001:db8::2"]}`))
	if err != nil {
		t.Fatal(err)
	}
	for key, fields := range bgp.Desired {
		db[key] = fields
	}
	for key, fields := range relay.Desired {
		db[key] = fields
	}
	// These exact planner-produced keys must remain understood by LAG/L3
	// dependency protection, rather than being whitelisted as opaque data.
	for key, fields := range db {
		if strings.HasPrefix(key, "PREFIX|") || strings.HasPrefix(key, "PREFIX_SET|") || strings.HasPrefix(key, "DHCP_RELAY|") || strings.HasPrefix(key, "DHCPV4_RELAY|") {
			if err := lagL3CrossFeatureGrammar(db, key, fields); err != nil {
				t.Fatalf("%s: %v", key, err)
			}
		}
	}
}

func TestRoutingRuntimeCommandFailure(t *testing.T) {
	t.Parallel()
	run := func(_ context.Context, command routingReadCommand) ([]byte, error) {
		return nil, fmt.Errorf("unavailable %d", command)
	}
	_, _, err := observeRoutingBGP(context.Background(), run, "default", 65000, "192.0.2.1", nil, nil)
	if err == nil {
		t.Fatal("command failure verified runtime")
	}
}

func TestRoutingObservationBound(t *testing.T) {
	t.Parallel()
	var output routingBoundedOutput
	// Hide strings.Reader.WriteTo to exercise the io.Copy ReaderFrom path used
	// by os/exec when collecting child output.
	reader := struct{ io.Reader }{strings.NewReader(strings.Repeat("x", (4<<20)+1))}
	if _, err := io.Copy(&output, reader); err == nil {
		t.Fatal("unbounded command output")
	}
}

func TestRoutingBGPRuntimeEvidence(t *testing.T) {
	t.Parallel()
	config := "router bgp 65000\n bgp router-id 192.0.2.1\n no bgp default ipv4-unicast\n!\n"
	for _, af := range []string{"ipv4_unicast", "ipv6_unicast"} {
		kind, prefix, bits := "ip", "0.0.0.0/0", "32"
		if af == "ipv6_unicast" {
			kind, prefix, bits = "ipv6", "::/0", "128"
		}
		config += kind + " prefix-list " + routingExportName("default", af) + " seq 4294967295 deny " + prefix + " le " + bits + "\n"
	}
	for _, tc := range []struct {
		name, config, daemon, summary string
		want                          bool
	}{
		{"consumed without peers", config, "frrcfgd RUNNING pid 1\nbgpd RUNNING pid 2", `{}`, true},
		{"wrong router ID", strings.ReplaceAll(config, "192.0.2.1", "192.0.2.9"), "frrcfgd RUNNING\nbgpd RUNNING", `{}`, false},
		{"traditional daemon", config, "bgpcfgd RUNNING\nbgpd RUNNING", `{}`, false},
		{"implicit redistribution", strings.Replace(config, " no bgp default ipv4-unicast\n", " no bgp default ipv4-unicast\n redistribute connected\n", 1), "frrcfgd RUNNING\nbgpd RUNNING", `{}`, false},
		{"wrong VRF", strings.Replace(config, "router bgp 65000", "router bgp 65000 vrf VrfBlue", 1), "frrcfgd RUNNING\nbgpd RUNNING", `{}`, false},
		{"missing export guard", strings.ReplaceAll(config, "deny", "permit"), "frrcfgd RUNNING\nbgpd RUNNING", `{}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := func(_ context.Context, c routingReadCommand) ([]byte, error) {
				switch c {
				case routingBGPConfig:
					return []byte(tc.config), nil
				case routingBGPDaemons:
					return []byte(tc.daemon), nil
				case routingBGPSummary:
					return []byte(tc.summary), nil
				}
				return nil, fmt.Errorf("unexpected command %d", c)
			}
			got, observed, err := observeRoutingBGP(context.Background(), run, "default", 65000, "192.0.2.1", nil, nil)
			if err != nil || got != tc.want || !json.Valid(observed) {
				t.Fatalf("got %v %s %v", got, observed, err)
			}
		})
	}
}

func TestRoutingRelayRuntimeEvidence(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, process string
		native        bool
		v4, v6        []string
		want          bool
	}{
		{"legacy argv", "/usr/sbin/dhcrelay -d -id Vlan100 -iu Ethernet0 192.0.2.2", false, []string{"192.0.2.2"}, nil, true},
		{"legacy primary gateway", "/usr/sbin/dhcrelay -d -m discard -a %h:%p %P --name-alias-map-file /tmp/port-name-alias-map.txt -id Vlan100 -iu Ethernet0 -pg 192.0.2.1 192.0.2.2", false, []string{"192.0.2.2"}, nil, true},
		{"wrong VLAN", "/usr/sbin/dhcrelay -d -id Vlan1000 192.0.2.2", false, []string{"192.0.2.2"}, nil, false},
		{"wrong server", "/usr/sbin/dhcrelay -d -id Vlan100 192.0.2.20", false, []string{"192.0.2.2"}, nil, false},
		{"native daemon insufficient", "/usr/sbin/dhcp4relay", true, []string{"192.0.2.2"}, nil, false},
		{"v6 daemon insufficient", "/usr/sbin/dhcp6relay", false, nil, []string{"2001:db8::2"}, false},
		{"dualstack partial", "/usr/sbin/dhcrelay -id Vlan100 192.0.2.2\n/usr/sbin/dhcp6relay", false, []string{"192.0.2.2"}, []string{"2001:db8::2"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := func(_ context.Context, c routingReadCommand) ([]byte, error) {
				if c != routingRelayProcesses {
					return nil, fmt.Errorf("unexpected command")
				}
				return []byte(tc.process), nil
			}
			got, observed, err := observeRoutingRelay(context.Background(), run, "Vlan100", tc.native, tc.v4, tc.v6)
			if err != nil || got != tc.want || !json.Valid(observed) {
				t.Fatalf("got %v %s %v", got, observed, err)
			}
		})
	}
}

func TestRoutingPeerRuntimeFamilies(t *testing.T) {
	t.Parallel()
	max := uint32(1000)
	peer := &routingPeerSpec{Address: "2001:db8::2", RemoteASN: 65001, AdminState: "Down", MaxPrefixes: &max, AddressFamilies: []string{"ipv4Unicast", "ipv6Unicast"}}
	config := "router bgp 65000\n bgp router-id 192.0.2.1\n no bgp default ipv4-unicast\n neighbor 2001:db8::2 remote-as 65001\n neighbor 2001:db8::2 shutdown\n"
	policies := ""
	for _, family := range []string{"ipv4_unicast", "ipv6_unicast"} {
		name := routingExportName("default", family)
		config += " !\n address-family " + strings.ReplaceAll(family, "_", " ") + "\n  neighbor 2001:db8::2 activate\n  neighbor 2001:db8::2 maximum-prefix 1000 100\n  neighbor 2001:db8::2 prefix-list " + name + " out\n exit-address-family\n"
		kind, prefix, bits := "ip", "0.0.0.0/0", "32"
		if family == "ipv6_unicast" {
			kind, prefix, bits = "ipv6", "::/0", "128"
		}
		policies += kind + " prefix-list " + name + " seq 4294967295 deny " + prefix + " le " + bits + "\n"
	}
	config += "!\n" + policies
	for _, tc := range []struct {
		name, config string
		want         bool
	}{
		{"both families", config, true},
		{"warning only", strings.ReplaceAll(config, "maximum-prefix 1000 100", "maximum-prefix 1000 100 warning-only"), false},
		{"peer not shutdown", strings.ReplaceAll(config, " neighbor 2001:db8::2 shutdown\n", ""), false},
		{"wrong remote ASN", strings.ReplaceAll(config, "remote-as 65001", "remote-as 65002"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := func(_ context.Context, c routingReadCommand) ([]byte, error) {
				switch c {
				case routingBGPConfig:
					return []byte(tc.config), nil
				case routingBGPDaemons:
					return []byte("frrcfgd RUNNING\nbgpd RUNNING"), nil
				case routingBGPSummary:
					return []byte(`{"default":{"ipv6Unicast":{"peers":{"2001:db8::2":{"state":"Idle"}}}}}`), nil
				}
				return nil, fmt.Errorf("unexpected command")
			}
			got, raw, err := observeRoutingBGP(context.Background(), run, "default", 65000, "192.0.2.1", nil, peer)
			if err != nil || got != tc.want || !strings.Contains(string(raw), "Idle") {
				t.Fatalf("got %v %s %v", got, raw, err)
			}
			peer.VRF = "default"
			preflightErr := routingPeerPreflight(context.Background(), run, 65000, "192.0.2.1", nil, *peer)
			if (preflightErr == nil) != tc.want {
				t.Fatalf("preflight: %v", preflightErr)
			}
		})
	}
	up := *peer
	up.AdminState = "Up"
	runUp := func(_ context.Context, c routingReadCommand) ([]byte, error) {
		switch c {
		case routingBGPConfig:
			return []byte(strings.ReplaceAll(config, " neighbor 2001:db8::2 shutdown\n", "")), nil
		case routingBGPDaemons:
			return []byte("frrcfgd RUNNING\nbgpd RUNNING"), nil
		case routingBGPSummary:
			return []byte(`{}`), nil
		}
		return nil, fmt.Errorf("unexpected command")
	}
	if verified, _, err := observeRoutingBGP(t.Context(), runUp, "default", 65000, "192.0.2.1", nil, &up); err != nil || !verified {
		t.Fatalf("FRR enabled peer: %v %v", verified, err)
	}
}

func TestRoutingPeerImportFilter(t *testing.T) {
	t.Parallel()
	db := routingDB()
	bgp, err := planNetworkBGP(db, routingRequest("BGP", `{"localASN":65000,"routerID":"192.0.2.1"}`))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range bgp.Desired {
		db[k] = v
	}
	spec := `{"address":"192.0.2.2","remoteASN":65001,"addressFamilies":["ipv4Unicast"],"importPrefixes":["198.51.100.0/24","203.0.113.7/32"]}`
	p, err := planNetworkBGPPeer(db, routingRequest("BGPPeer", spec))
	if err != nil {
		t.Fatal(err)
	}
	name := routingImportName("default", "192.0.2.2", "ipv4_unicast")
	if p.Desired["BGP_NEIGHBOR_AF|default|192.0.2.2|ipv4_unicast"]["prefix_list_in"] != name {
		t.Fatalf("no inbound filter: %v", p.Desired["BGP_NEIGHBOR_AF|default|192.0.2.2|ipv4_unicast"])
	}
	for _, key := range []string{"PREFIX_SET|" + name, "PREFIX|" + name + "|1|198.51.100.0/24|exact", "PREFIX|" + name + "|2|203.0.113.7/32|exact"} {
		if len(p.Desired[key]) == 0 {
			t.Fatalf("missing %s", key)
		}
	}
	if p.Desired["PREFIX|"+name+"|4294967295|0.0.0.0/0|0..32"]["action"] != "deny" {
		t.Fatal("inbound filter does not end with deny")
	}
	if _, ok := p.Desired["PREFIX_SET|"+routingImportName("default", "192.0.2.2", "ipv6_unicast")]; ok {
		t.Fatal("empty IPv6 import filter created")
	}
	if routingImportName("default", "192.0.2.2", "ipv4_unicast") == routingImportName("default", "192.0.2.3", "ipv4_unicast") {
		t.Fatal("import filters are not per peer")
	}
	if err := validateNetworkFields("BGPPeer", p.Desired); err != nil {
		t.Fatalf("peer fields not allowed: %v", err)
	}
	for k, v := range p.Desired {
		db[k] = v
	}
	if _, err := planNetworkBGPPeer(db, routingRequest("BGPPeer", `{"address":"192.0.2.2","remoteASN":65001,"addressFamilies":["ipv4Unicast"]}`)); err == nil || !strings.Contains(err.Error(), "importPrefixes") {
		t.Fatalf("import filter removal accepted: %v", err)
	}
	if _, err := planNetworkBGPPeer(db, routingRequest("BGPPeer", `{"address":"192.0.2.2","remoteASN":65001,"addressFamilies":["ipv4Unicast"],"importPrefixes":["198.51.100.1/24"]}`)); err == nil {
		t.Fatal("non-canonical import prefix accepted")
	}
}

func TestRoutingPeerRequiresNoDefaultShutdown(t *testing.T) {
	t.Parallel()
	db := routingDB()
	bgp, err := planNetworkBGP(db, routingRequest("BGP", `{"localASN":65000,"routerID":"192.0.2.1"}`))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range bgp.Desired {
		db[k] = v
	}
	db["BGP_GLOBALS|default"]["default_shutdown"] = "true"
	if _, err := planNetworkBGPPeer(db, routingRequest("BGPPeer", `{"address":"192.0.2.2","remoteASN":65001,"addressFamilies":["ipv4Unicast"]}`)); err == nil {
		t.Fatal("peer planned while FRR default shutdown blocks incoming sessions")
	}
	again, err := planNetworkBGP(db, routingRequest("BGP", `{"localASN":65000,"routerID":"192.0.2.1"}`))
	if err != nil {
		t.Fatal(err)
	}
	if again.Desired["BGP_GLOBALS|default"]["default_shutdown"] != "false" {
		t.Fatal("SwitchBGP does not migrate off default shutdown")
	}
}

func TestRoutingRuntimeImportFilterAndDefaultShutdown(t *testing.T) {
	t.Parallel()
	max := uint32(1000)
	peer := &routingPeerSpec{VRF: "default", Address: "192.0.2.2", RemoteASN: 65001, AdminState: "Down", MaxPrefixes: &max, AddressFamilies: []string{"ipv4Unicast"}, ImportPrefixes: []string{"198.51.100.0/24"}}
	out, in := routingExportName("default", "ipv4_unicast"), routingImportName("default", "192.0.2.2", "ipv4_unicast")
	config := "router bgp 65000\n bgp router-id 192.0.2.1\n no bgp default ipv4-unicast\n neighbor 192.0.2.2 remote-as 65001\n neighbor 192.0.2.2 shutdown\n !\n address-family ipv4 unicast\n  neighbor 192.0.2.2 activate\n  neighbor 192.0.2.2 maximum-prefix 1000 100\n  neighbor 192.0.2.2 prefix-list " + in + " in\n  neighbor 192.0.2.2 prefix-list " + out + " out\n exit-address-family\n!\n" +
		"ip prefix-list " + out + " seq 4294967295 deny 0.0.0.0/0 le 32\n" +
		"ipv6 prefix-list " + routingExportName("default", "ipv6_unicast") + " seq 4294967295 deny ::/0 le 128\n" +
		"ip prefix-list " + in + " seq 1 permit 198.51.100.0/24\n" +
		"ip prefix-list " + in + " seq 4294967295 deny 0.0.0.0/0 le 32\n"
	for _, tc := range []struct {
		name, config string
		want         bool
	}{
		{"complete", config, true},
		{"inbound filter not applied", strings.Replace(config, "  neighbor 192.0.2.2 prefix-list "+in+" in\n", "", 1), false},
		{"inbound entry missing", strings.Replace(config, "ip prefix-list "+in+" seq 1 permit 198.51.100.0/24\n", "", 1), false},
		{"extra inbound entry", config + "ip prefix-list " + in + " seq 2 permit 10.0.0.0/8\n", false},
		{"FRR default shutdown", strings.Replace(config, " no bgp default ipv4-unicast\n", " no bgp default ipv4-unicast\n bgp default shutdown\n", 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := func(_ context.Context, c routingReadCommand) ([]byte, error) {
				switch c {
				case routingBGPConfig:
					return []byte(tc.config), nil
				case routingBGPDaemons:
					return []byte("frrcfgd RUNNING\nbgpd RUNNING"), nil
				case routingBGPSummary:
					return []byte(`{}`), nil
				}
				return nil, fmt.Errorf("unexpected command")
			}
			got, _, err := observeRoutingBGP(context.Background(), run, "default", 65000, "192.0.2.1", nil, peer)
			if err != nil || got != tc.want {
				t.Fatalf("got %v, want %v (%v)", got, tc.want, err)
			}
		})
	}
}

func TestBGPDefaultShutdownMigrationIsOneWayAndNarrow(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		kind, key, field, old, value string
		want                         bool
	}{
		{"BGP", "BGP_GLOBALS|default", "default_shutdown", "true", "false", true},
		{"BGP", "BGP_GLOBALS|Vrf1", "default_shutdown", "true", "false", true},
		{"BGP", "BGP_GLOBALS|default", "default_shutdown", "false", "true", false},
		{"BGP", "BGP_GLOBALS|default", "default_ipv4_unicast", "true", "false", false},
		{"BGP", "BGP_NEIGHBOR|default|192.0.2.2", "default_shutdown", "true", "false", false},
		{"BGPPeer", "BGP_GLOBALS|default", "default_shutdown", "true", "false", false},
	} {
		if got := bgpDefaultShutdownMigration(tc.kind, tc.key, tc.field, tc.old, tc.value); got != tc.want {
			t.Fatalf("%+v: got %v", tc, got)
		}
	}
}
