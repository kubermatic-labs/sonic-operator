// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"maps"
	"reflect"
	"strings"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

// These fixtures use the actual planners, not hand-written approximations of
// their output. Prerequisites precede dependents; independent groups swap order.
func lagL3CoexistRequests(routingFirst bool) []*agent.NetworkRequest {
	req := func(kind, spec string) *agent.NetworkRequest {
		return &agent.NetworkRequest{Kind: kind, OwnerID: "fixture-" + kind, Spec: json.RawMessage(spec)}
	}
	l3 := []*agent.NetworkRequest{
		req("PortChannel", `{"name":"PortChannel10","members":["Ethernet0","Ethernet4"]}`),
		req("L3Interface", `{"name":"PortChannel10","addresses":["192.0.2.1/24","2001:db8::123/64"]}`),
		req("L3Interface", `{"name":"Ethernet8","addresses":["198.51.100.1/24"]}`),
	}
	routing := []*agent.NetworkRequest{
		req("BGP", `{"localASN":65001,"routerID":"192.0.2.1","prefixes":["203.0.113.0/24"]}`),
		req("BGPPeer", `{"address":"192.0.2.2","remoteASN":65002,"addressFamilies":["ipv4Unicast","ipv6Unicast"],"adminState":"Down"}`),
		req("DHCPRelay", `{"vlanID":100,"ipv4Servers":["192.0.2.10"],"ipv6Servers":["2001:db8::10"]}`),
	}
	requests := append(l3, routing...)
	if routingFirst {
		requests = append(routing, l3...)
	}
	return append(requests,
		req("StaticRoute", `{"prefix":"203.0.113.0/24","nextHops":[{"address":"192.0.2.2","interfaceName":"PortChannel10"},{"address":"192.0.2.3","distance":20}]}`),
		req("StaticRoute", `{"prefix":"2001:db8:1::/64","nextHops":[{"address":"2001:db8::2","interfaceName":"PortChannel10"}]}`))
}

func lagL3CoexistDB() vlanChangeDB {
	db := lagL3Fixture()
	db["DEVICE_METADATA|localhost"] = map[string]string{"frr_mgmt_framework_config": "true", "has_sonic_dhcpv4_relay": "True"}
	db["PORT|Ethernet8"] = map[string]string{"speed": "100000", "mtu": "9100"}
	db["VLAN_INTERFACE|Vlan100"] = map[string]string{"NULL": "NULL"}
	db["VLAN_INTERFACE|Vlan100|10.0.0.1/24"] = map[string]string{"NULL": "NULL"}
	db["VLAN_INTERFACE|Vlan100|2001:db8:100::1/64"] = map[string]string{"NULL": "NULL"}
	// IPv6 destinations are provisioned out of band: their consumer is startup-only.
	db["DHCP_RELAY|Vlan100"] = map[string]string{"dhcpv6_servers@": "2001:db8::10", "interface_id": "true"}
	return db
}

func TestNetworkLAGL3Coexist(t *testing.T) {
	for _, order := range []struct {
		name         string
		routingFirst bool
	}{{"routing first", true}, {"LAG first", false}} {
		t.Run(order.name, func(t *testing.T) {
			db := lagL3CoexistDB()
			requests := lagL3CoexistRequests(order.routingFirst)
			for pass := 0; pass < 2; pass++ {
				for _, r := range requests {
					before, _ := json.Marshal(db)
					p, err := planNetworkResource(db, r)
					if err != nil {
						t.Fatalf("pass %d %s: %v", pass, r.Kind, err)
					}
					after, _ := json.Marshal(db)
					if string(after) != string(before) {
						t.Fatal("planner changed snapshot")
					}
					if err := validateNetworkFields(r.Kind, p.Desired); err != nil {
						t.Fatal(err)
					}
					for key, fields := range p.Desired {
						if db[key] == nil {
							db[key] = map[string]string{}
						}
						maps.Copy(db[key], fields)
					}
				}
			}
			if db["PORT|Ethernet0"]["description"] != "preserve" || db["DHCP_RELAY|Vlan100"]["interface_id"] != "true" {
				t.Fatal("lost unmanaged fields")
			}
		})
	}
}

func TestNetworkLAGL3CrossFeatureGrammar(t *testing.T) {
	for _, tc := range []struct {
		name, key string
		fields    map[string]string
		valid     bool
	}{
		{"prefix set", "PREFIX_SET|EXPORT", map[string]string{"mode": "IPv4"}, true},
		{"prefix", "PREFIX|EXPORT|1|192.0.2.0/24|24..32", map[string]string{"action": "permit"}, true},
		{"prefix no sequence", "PREFIX|EXPORT|192.0.2.0/24|exact", map[string]string{"action": "deny"}, true},
		{"invalid range", "PREFIX|EXPORT|1|192.0.2.0/24|20..33", map[string]string{"action": "permit"}, false},
		{"family mismatch", "PREFIX|EXPORT|1|2001:db8::/64|exact", map[string]string{"action": "permit"}, false},
		{"prefix unknown field", "PREFIX_SET|EXPORT", map[string]string{"mode": "IPv4", "ports": "all"}, false},
		{"opaque prefix", "PREFIX|EXPORT|1|all|exact", map[string]string{"action": "permit"}, false},
		{"zero sequence", "PREFIX|EXPORT|0|192.0.2.0/24|exact", map[string]string{"action": "permit"}, false},
		{"relay v4", "DHCPV4_RELAY|Vlan100", map[string]string{"dhcpv4_servers@": "192.0.2.10"}, true},
		{"relay v6", "DHCP_RELAY|Vlan100", map[string]string{"dhcpv6_servers@": "2001:db8::10", "rfc6939_support": "false"}, true},
		{"relay affected source", "DHCPV4_RELAY|Vlan100", map[string]string{"dhcpv4_servers@": "192.0.2.10", "source_interface": "Ethernet0"}, false},
		{"relay unrelated source", "DHCPV4_RELAY|Vlan100", map[string]string{"dhcpv4_servers@": "192.0.2.10", "source_interface": "Ethernet8"}, true},
		{"relay opaque source", "DHCPV4_RELAY|Vlan100", map[string]string{"dhcpv4_servers@": "192.0.2.10", "source_interface": "all"}, false},
		{"relay unknown field", "DHCP_RELAY|Vlan100", map[string]string{"dhcpv6_servers@": "2001:db8::10", "ports": "all"}, false},
		{"relay wrong family", "DHCPV4_RELAY|Vlan100", map[string]string{"dhcpv4_servers@": "2001:db8::10"}, false},
		{"relay unknown vlan", "DHCP_RELAY|Vlan200", map[string]string{"dhcpv6_servers@": "2001:db8::10"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := lagL3CoexistDB()
			db["PREFIX_SET|EXPORT"] = map[string]string{"mode": "IPv4"}
			db[tc.key] = tc.fields
			err := lagL3PortFree(db, "Ethernet0", "PortChannel10")
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%t: %v", tc.valid, err)
			}
		})
	}
}

func TestNetworkLAGL3UnifiedRoutes(t *testing.T) {
	for _, prefix := range []string{"203.0.113.0/24", "2001:db8:1::/64"} {
		t.Run(prefix, func(t *testing.T) {
			db := lagL3CoexistDB()
			address := "192.0.2.2"
			if prefix == "2001:db8:1::/64" {
				address = "2001:db8::2"
			}
			spec, _ := json.Marshal(map[string]any{"prefix": prefix, "nextHops": []map[string]string{{"address": address}}})
			p, err := planNetworkStaticRoute(db, &agent.NetworkRequest{Kind: "StaticRoute", Spec: spec})
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]string{"nexthop": address, "distance": "1"}
			if !reflect.DeepEqual(p.Desired["STATIC_ROUTE|default|"+prefix], want) {
				t.Fatalf("inert or unexpected fields: %v", p.Desired)
			}
			db["ROUTE_REDISTRIBUTE|default|static|bgp|ipv4"] = map[string]string{"route_map": "ANY"}
			if _, err := planNetworkStaticRoute(db, &agent.NetworkRequest{Kind: "StaticRoute", Spec: spec}); err == nil {
				t.Fatal("implicit redistribution accepted")
			}
		})
	}
}

func TestNetworkLAGL3RuntimeReadErrors(t *testing.T) {
	readErr := context.DeadlineExceeded
	read := func(context.Context, string) (map[string]string, error) { return nil, readErr }
	if ok, _, err := lagL3InterfaceRuntime(t.Context(), "Ethernet0", "default", []string{"192.0.2.1/24"}, read, nil); ok || err != readErr {
		t.Fatalf("L3 read error lost: %v %v", ok, err)
	}
	if ok, _, err := lagL3PortChannelRuntime(t.Context(), "PortChannel10", nil, nil, read, nil, nil); ok || err != readErr {
		t.Fatalf("LAG read error lost: %v %v", ok, err)
	}
	if ok, _, err := lagL3VRFRuntime(t.Context(), "VrfBlue", func(context.Context, string) (map[string]string, error) { return nil, readErr }, nil); ok || err != readErr {
		t.Fatalf("read error lost: %v %v", ok, err)
	}
	distance := uint32(1)
	if ok, _, err := lagL3RouteRuntime(t.Context(), "default", "192.0.2.0/24", []lagL3NextHop{{Address: "192.0.2.2", Distance: &distance}}, 0, func(context.Context, ...string) ([]byte, error) { return nil, readErr }); ok || err != readErr {
		t.Fatalf("read error lost: %v %v", ok, err)
	}
}

func TestNetworkLAGL3UnifiedRouteRuntime(t *testing.T) {
	distance := uint32(1)
	for _, tc := range []struct {
		name, output string
		valid        bool
	}{
		{"unified tag zero", `{"192.0.2.0/24":[{"protocol":"static","distance":1,"nexthops":[{"ip":"198.51.100.2","active":true}]}]}`, true},
		{"traditional tag not unified", `{"192.0.2.0/24":[{"protocol":"static","distance":1,"tag":2,"nexthops":[{"ip":"198.51.100.2","active":true}]}]}`, false},
		{"inactive next hop", `{"192.0.2.0/24":[{"protocol":"static","distance":1,"nexthops":[{"ip":"198.51.100.2","active":false}]}]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, _, err := lagL3RouteRuntime(t.Context(), "default", "192.0.2.0/24", []lagL3NextHop{{Address: "198.51.100.2", Distance: &distance}}, 0, func(context.Context, ...string) ([]byte, error) { return []byte(tc.output), nil })
			if err != nil || ok != tc.valid {
				t.Fatalf("runtime: %t %v", ok, err)
			}
		})
	}
}

func TestNetworkLAGL3UnifiedRoutePreservation(t *testing.T) {
	r := &agent.NetworkRequest{Kind: "StaticRoute", Spec: json.RawMessage(`{"prefix":"203.0.113.0/24","nextHops":[{"address":"192.0.2.2"},{"address":"192.0.2.3","distance":20}]}`)}
	for _, tc := range []struct {
		name   string
		change func(vlanChangeDB)
		valid  bool
	}{
		{"default config mode", func(vlanChangeDB) {}, true},
		{"unified config mode", func(db vlanChangeDB) { db["DEVICE_METADATA|localhost"]["docker_routing_config_mode"] = "unified" }, true},
		{"unsupported config mode", func(db vlanChangeDB) { db["DEVICE_METADATA|localhost"]["docker_routing_config_mode"] = "split" }, false},
		{"startup incompatible advertise", func(db vlanChangeDB) {
			db["STATIC_ROUTE|default|203.0.113.0/24"] = map[string]string{"advertise": "false"}
		}, false},
		{"unmanaged tag", func(db vlanChangeDB) { db["STATIC_ROUTE|default|203.0.113.0/24"] = map[string]string{"tag": "12,12"} }, false},
		{"vector replacement", func(db vlanChangeDB) {
			db["STATIC_ROUTE|default|203.0.113.0/24"] = map[string]string{"nexthop": "192.0.2.9"}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := lagL3CoexistDB()
			tc.change(db)
			before, _ := json.Marshal(db)
			p, err := planNetworkStaticRoute(db, r)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%t: %v", tc.valid, err)
			}
			if tc.valid {
				fields := p.Desired["STATIC_ROUTE|default|203.0.113.0/24"]
				if !reflect.DeepEqual(fields, map[string]string{"nexthop": "192.0.2.2,192.0.2.3", "distance": "1,20"}) {
					t.Fatalf("vectors: %v", fields)
				}
			}
			after, _ := json.Marshal(db)
			if string(before) != string(after) {
				t.Fatal("mutated snapshot")
			}
		})
	}
}

func TestNetworkLAGL3ModeMatrix(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		framework, mode string
		route, bgp      bool
	}{
		{"", "", true, false}, {"false", "", true, false}, {"false", "separated", true, false},
		{"true", "", true, true}, {"true", "separated", true, true}, {"true", "unified", true, true},
		{"false", "unified", false, false}, {"unknown", "", false, false},
	} {
		t.Run(tc.framework+"/"+tc.mode, func(t *testing.T) {
			db := lagL3Fixture()
			db["DEVICE_METADATA|localhost"] = map[string]string{"frr_mgmt_framework_config": tc.framework, "docker_routing_config_mode": tc.mode}
			_, err := planNetworkStaticRoute(db, &agent.NetworkRequest{Kind: "StaticRoute", Spec: json.RawMessage(`{"vrf":"VrfBlue","prefix":"2001:db8::/64","nextHops":[{"address":"2001:db8:1::2"}]}`)})
			if (err == nil) != tc.route {
				t.Fatalf("route supported=%t: %v", tc.route, err)
			}
			_, err = planNetworkBGP(db, &agent.NetworkRequest{Kind: "BGP", Spec: json.RawMessage(`{"vrf":"VrfBlue","localASN":65001,"routerID":"192.0.2.1"}`)})
			if (err == nil) != tc.bgp {
				t.Fatalf("BGP supported=%t: %v", tc.bgp, err)
			}
		})
	}
}

func TestNetworkLAGL3NamedVRFCoexist(t *testing.T) {
	for _, mode := range []string{"", "separated", "unified"} {
		t.Run(mode, func(t *testing.T) {
			for _, first := range []bool{true, false} {
				db := lagL3CoexistDB()
				db["DEVICE_METADATA|localhost"]["docker_routing_config_mode"] = mode
				db["VLAN_INTERFACE|Vlan100"] = map[string]string{"vrf_name": "VrfBlue"}
				delete(db, "DHCP_RELAY|Vlan100")
				requests := lagL3CoexistRequests(first)
				for _, r := range requests {
					var spec map[string]any
					if err := json.Unmarshal(r.Spec, &spec); err != nil {
						t.Fatal(err)
					}
					if r.Kind != "PortChannel" {
						spec["vrf"] = "VrfBlue"
					}
					if r.Kind == "DHCPRelay" {
						delete(spec, "ipv6Servers")
					}
					r.Spec, _ = json.Marshal(spec)
				}
				for pass := 0; pass < 2; pass++ {
					for _, r := range requests {
						p, err := planNetworkResource(db, r)
						if err != nil {
							t.Fatalf("routingFirst=%t pass=%d %s: %v", first, pass, r.Kind, err)
						}
						for key, fields := range p.Desired {
							if db[key] == nil {
								db[key] = map[string]string{}
							}
							maps.Copy(db[key], fields)
						}
					}
				}
			}
		})
	}
}

func TestNetworkLAGL3DependencySchemaConstraints(t *testing.T) {
	for _, tc := range []struct {
		name string
		rows vlanChangeDB
	}{
		{"duplicate prefix sequence", vlanChangeDB{"PREFIX_SET|EXPORT": {"mode": "IPv4"}, "PREFIX|EXPORT|1|192.0.2.0/24|exact": {"action": "permit"}, "PREFIX|EXPORT|1|198.51.100.0/24|exact": {"action": "deny"}}},
		{"broadcast relay server", vlanChangeDB{"DHCPV4_RELAY|Vlan100": {"dhcpv4_servers@": "255.255.255.255"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := lagL3CoexistDB()
			maps.Copy(db, tc.rows)
			if err := lagL3PortFree(db, "Ethernet0", "PortChannel10"); err == nil {
				t.Fatal("invalid dependency schema accepted")
			}
		})
	}
	// Policy names are identifiers, not port selectors. Exact schemas allow these
	// names without weakening the relay source_interface dependency check.
	db := lagL3CoexistDB()
	db["PREFIX_SET|Ethernet0"] = map[string]string{"mode": "IPv4"}
	db["PREFIX|Ethernet0|1|192.0.2.0/24|exact"] = map[string]string{"action": "permit"}
	if err := lagL3PortFree(db, "Ethernet0", "PortChannel10"); err != nil {
		t.Fatal(err)
	}
	db["PORTCHANNEL|PortChannel10"] = map[string]string{"admin_status": "up"}
	db["DHCPV4_RELAY|Vlan100"] = map[string]string{"dhcpv4_servers@": "192.0.2.10", "source_interface": "PortChannel10"}
	if err := lagL3PortFree(db, "PortChannel10", ""); err == nil || !strings.Contains(err.Error(), "dependency") {
		t.Fatalf("LAG source dependency lost: %v", err)
	}
}
