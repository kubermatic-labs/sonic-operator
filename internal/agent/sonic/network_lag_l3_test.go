// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/vishvananda/netlink"
)

func lagL3Fixture() vlanChangeDB {
	return vlanChangeDB{
		"PORT|Ethernet0": {"speed": "100000", "mtu": "9100", "description": "preserve"},
		"PORT|Ethernet4": {"speed": "100000", "mtu": "9100"},
		"VLAN|Vlan100":   {"vlanid": "100"},
		"VRF|VrfBlue":    {"NULL": "NULL"},
	}
}

func TestNetworkLAGL3Plans(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, kind, spec string
		plan             func(vlanChangeDB, *agent.NetworkRequest) (*networkPlan, error)
		want             vlanChangeDB
	}{
		{"lag", "PortChannel", `{"name":"PortChannel10","members":["Ethernet4","Ethernet0"],"fastRate":true}`, planNetworkPortChannel, vlanChangeDB{"PORTCHANNEL|PortChannel10": {"admin_status": "up", "mtu": "9100", "min_links": "1", "fast_rate": "true"}, "PORTCHANNEL_MEMBER|PortChannel10|Ethernet0": {"NULL": "NULL"}, "PORTCHANNEL_MEMBER|PortChannel10|Ethernet4": {"NULL": "NULL"}}},
		{"vrf", "VRF", `{"name":"VrfRed"}`, planNetworkVRF, vlanChangeDB{"VRF|VrfRed": {"NULL": "NULL"}}},
		{"ipv6 host bits", "L3Interface", `{"name":"Ethernet0","vrf":"VrfBlue","addresses":["2001:db8::123/64","192.0.2.9/24"]}`, planNetworkL3Interface, vlanChangeDB{"INTERFACE|Ethernet0": {"vrf_name": "VrfBlue"}, "INTERFACE|Ethernet0|2001:db8::123/64": {"NULL": "NULL"}, "INTERFACE|Ethernet0|192.0.2.9/24": {"NULL": "NULL"}}},
		{"svi", "L3Interface", `{"name":"Vlan100","addresses":["192.0.2.1/24"]}`, planNetworkL3Interface, vlanChangeDB{"VLAN_INTERFACE|Vlan100": {"NULL": "NULL"}, "VLAN_INTERFACE|Vlan100|192.0.2.1/24": {"NULL": "NULL"}}},
		{"route", "StaticRoute", `{"prefix":"2001:db8:1::/64","nextHops":[{"address":"2001:db8::1"}]}`, planNetworkStaticRoute, vlanChangeDB{"STATIC_ROUTE|default|2001:db8:1::/64": {"nexthop": "2001:db8::1", "distance": "1", "advertise": "false"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := lagL3Fixture()
			before, _ := json.Marshal(db)
			p, err := tc.plan(db, &agent.NetworkRequest{Kind: tc.kind, OwnerID: "owner", Spec: json.RawMessage(tc.spec)})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(p.Desired, tc.want) || p.Identity == "" || p.Runtime == nil {
				t.Fatalf("plan: %+v, want %v", p, tc.want)
			}
			after, _ := json.Marshal(db)
			if string(before) != string(after) {
				t.Fatal("planner mutated snapshot")
			}
		})
	}
}

func TestNetworkLAGL3Rejects(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, kind, spec string
		plan             func(vlanChangeDB, *agent.NetworkRequest) (*networkPlan, error)
		change           func(vlanChangeDB)
	}{
		{"passive unsupported", "PortChannel", `{"name":"PortChannel1","members":["Ethernet0"],"lacpMode":"passive"}`, planNetworkPortChannel, nil},
		{"noncanonical lag", "PortChannel", `{"name":"PortChannel01","members":["Ethernet0"]}`, planNetworkPortChannel, nil},
		{"duplicate member", "PortChannel", `{"name":"PortChannel1","members":["Ethernet0","Ethernet0"]}`, planNetworkPortChannel, nil},
		{"unknown field", "VRF", `{"name":"VrfRed","vni":100}`, planNetworkVRF, nil},
		{"duplicate JSON", "VRF", `{"name":"VrfBlue","name":"VrfRed"}`, planNetworkVRF, nil},
		{"trailing JSON", "VRF", `{"name":"VrfRed"} {}`, planNetworkVRF, nil},
		{"mgmt VRF", "VRF", `{"name":"mgmt"}`, planNetworkVRF, nil},
		{"default VRF", "VRF", `{"name":"default"}`, planNetworkVRF, nil},
		{"long VRF", "VRF", `{"name":"Vrf12345678901234"}`, planNetworkVRF, nil},
		{"missing SVI", "L3Interface", `{"name":"Vlan101","addresses":["192.0.2.1/24"]}`, planNetworkL3Interface, nil},
		{"missing VRF", "L3Interface", `{"name":"Ethernet0","vrf":"VrfAbsent","addresses":["192.0.2.1/24"]}`, planNetworkL3Interface, nil},
		{"duplicate normalized address", "L3Interface", `{"name":"Ethernet0","addresses":["2001:db8::1/64","2001:0db8::1/64"]}`, planNetworkL3Interface, nil},
		{"route host bits", "StaticRoute", `{"prefix":"192.0.2.1/24","nextHops":[{"address":"192.0.2.2"}]}`, planNetworkStaticRoute, nil},
		{"route mixed families", "StaticRoute", `{"prefix":"192.0.2.0/24","nextHops":[{"address":"2001:db8::1"}]}`, planNetworkStaticRoute, nil},
		{"route scoped link local", "StaticRoute", `{"prefix":"2001:db8::/64","nextHops":[{"address":"fe80::1"}]}`, planNetworkStaticRoute, nil},
		{"route distance", "StaticRoute", `{"prefix":"192.0.2.0/24","nextHops":[{"address":"192.0.2.2","distance":256}]}`, planNetworkStaticRoute, nil},
		{"route mode", "StaticRoute", `{"prefix":"192.0.2.0/24","nextHops":[{"address":"192.0.2.2"}]}`, planNetworkStaticRoute, func(db vlanChangeDB) {
			db["DEVICE_METADATA|localhost"] = map[string]string{"docker_routing_config_mode": "unified"}
		}},
		{"lag speed", "PortChannel", `{"name":"PortChannel1","members":["Ethernet0","Ethernet4"]}`, planNetworkPortChannel, func(db vlanChangeDB) { db["PORT|Ethernet4"]["speed"] = "40000" }},
		{"lag mtu", "PortChannel", `{"name":"PortChannel1","members":["Ethernet0"]}`, planNetworkPortChannel, func(db vlanChangeDB) { db["PORT|Ethernet0"]["mtu"] = "1500" }},
		{"lag VLAN member", "PortChannel", `{"name":"PortChannel1","members":["Ethernet0"]}`, planNetworkPortChannel, func(db vlanChangeDB) {
			db["VLAN_MEMBER|Vlan100|Ethernet0"] = map[string]string{"tagging_mode": "tagged"}
		}},
		{"lag routed member", "PortChannel", `{"name":"PortChannel1","members":["Ethernet0"]}`, planNetworkPortChannel, func(db vlanChangeDB) { db["INTERFACE|Ethernet0|192.0.2.1/24"] = map[string]string{"NULL": "NULL"} }},
		{"lag other LAG", "PortChannel", `{"name":"PortChannel1","members":["Ethernet0"]}`, planNetworkPortChannel, func(db vlanChangeDB) {
			db["PORTCHANNEL_MEMBER|PortChannel2|Ethernet0"] = map[string]string{"NULL": "NULL"}
		}},
		{"lag immutable fast rate", "PortChannel", `{"name":"PortChannel1","members":["Ethernet0"],"fastRate":true}`, planNetworkPortChannel, func(db vlanChangeDB) {
			db["PORTCHANNEL|PortChannel1"] = map[string]string{"admin_status": "up", "fast_rate": "false"}
		}},
		{"L3 VLAN port", "L3Interface", `{"name":"Ethernet0","addresses":["192.0.2.1/24"]}`, planNetworkL3Interface, func(db vlanChangeDB) {
			db["VLAN_MEMBER|Vlan100|Ethernet0"] = map[string]string{"tagging_mode": "tagged"}
		}},
		{"immutable VRF binding", "L3Interface", `{"name":"Ethernet0","vrf":"VrfBlue","addresses":["192.0.2.1/24"]}`, planNetworkL3Interface, func(db vlanChangeDB) { db["INTERFACE|Ethernet0"] = map[string]string{"NULL": "NULL"} }},
		{"unknown port dependency", "PortChannel", `{"name":"PortChannel1","members":["Ethernet0"]}`, planNetworkPortChannel, func(db vlanChangeDB) { db["MYSTERY|all"] = map[string]string{"ports": "Ethernet0"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := lagL3Fixture()
			if tc.change != nil {
				tc.change(db)
			}
			if p, err := tc.plan(db, &agent.NetworkRequest{Kind: tc.kind, Spec: json.RawMessage(tc.spec)}); err == nil {
				t.Fatalf("accepted: %+v", p)
			}
		})
	}
}

func TestNetworkLAGVLANAcceptance(t *testing.T) {
	db := lagL3Fixture()
	db["PORTCHANNEL|PortChannel10"] = map[string]string{"admin_status": "up"}
	db["PORTCHANNEL_MEMBER|PortChannel10|Ethernet0"] = map[string]string{"NULL": "NULL"}
	r := &agent.VLANAuthorityRequest{OwnerID: "owner", VLAN: &agent.VLAN{ID: 100, Members: []agent.VLANMember{{InterfaceName: "PortChannel10", TaggingMode: "tagged"}}}}
	if err := validateVLANAuthority(r); err != nil {
		t.Fatal(err)
	}
	if err := vlanAuthoritySafe(db, 100, vlanAuthorityDesired(r)); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"PORTCHANNEL_INTERFACE|PortChannel10", "INTERFACE|Ethernet0", "VLAN_MEMBER|Vlan100|Ethernet0"} {
		t.Run(key, func(t *testing.T) {
			db[key] = map[string]string{"NULL": "NULL"}
			defer delete(db, key)
			if err := vlanAuthoritySafe(db, 100, vlanAuthorityDesired(r)); err == nil {
				t.Fatal("accepted conflicting LAG member")
			}
		})
	}
}

func TestNetworkLAGBreakoutDependency(t *testing.T) {
	db := lagL3Fixture()
	delete(db, "VRF|VrfBlue")
	db["PORTCHANNEL|PortChannel10"] = map[string]string{"admin_status": "up"}
	db["PORTCHANNEL_MEMBER|PortChannel10|Ethernet4"] = map[string]string{"NULL": "NULL"}
	db["VLAN_MEMBER|Vlan100|PortChannel10"] = map[string]string{"tagging_mode": "tagged"}
	p := &breakoutPlatform{Modes: map[string]vlanChangeDB{"mode": {"Ethernet0": {}}}}
	if err := breakoutDependencies(db, p); err != nil {
		t.Fatalf("unrelated LAG blocks breakout: %v", err)
	}
	db["PORTCHANNEL_MEMBER|PortChannel10|Ethernet0"] = map[string]string{"NULL": "NULL"}
	if err := breakoutDependencies(db, p); err == nil {
		t.Fatal("affected LAG must block breakout")
	}
}

func TestNetworkLAGL3RuntimeEvidence(t *testing.T) {
	read := func(_ context.Context, key string) (map[string]string, error) {
		switch key {
		case "INTF_TABLE:Ethernet0":
			return map[string]string{"vrf_name": "VrfBlue"}, nil
		case "INTF_TABLE:Ethernet0:2001:db8::123/64":
			return map[string]string{"family": "IPv6", "scope": "global"}, nil
		}
		return nil, fmt.Errorf("unexpected key %s", key)
	}
	link := func(name string) (netlink.Link, error) {
		if name == "VrfBlue" {
			return &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Index: 10}, Table: 1001}, nil
		}
		return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{MasterIndex: 10}}, nil
	}
	ok, raw, err := lagL3InterfaceRuntime(t.Context(), "Ethernet0", "VrfBlue", []string{"2001:db8::123/64"}, read, link)
	if err != nil || !ok || !strings.Contains(string(raw), "2001:db8::123/64") {
		t.Fatalf("runtime: %v %s %v", ok, raw, err)
	}
	ok, _, _ = lagL3InterfaceRuntime(t.Context(), "Ethernet0", "VrfBlue", []string{"2001:db8::123/64"}, func(context.Context, string) (map[string]string, error) { return nil, nil }, link)
	if ok {
		t.Fatal("CONFIG_DB alone must not prove runtime")
	}
}

func TestNetworkLAGL3AdditionalSafety(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, kind, spec string
		change           func(vlanChangeDB)
	}{
		{"opaque VLAN selector", "PortChannel", `{"name":"PortChannel1","members":["Ethernet0"]}`, func(db vlanChangeDB) { db["VLAN_MEMBER|Vlan100|all"] = map[string]string{"tagging_mode": "tagged"} }},
		{"opaque L3 selector", "PortChannel", `{"name":"PortChannel1","members":["Ethernet0"]}`, func(db vlanChangeDB) { db["INTERFACE|all"] = map[string]string{"NULL": "NULL"} }},
		{"legacy VLAN membership", "PortChannel", `{"name":"PortChannel1","members":["Ethernet0"]}`, func(db vlanChangeDB) { db["VLAN|Vlan100"]["members@"] = "etp1"; db["PORT|Ethernet0"]["alias"] = "etp1" }},
		{"invalid framework mode", "StaticRoute", `{"prefix":"192.0.2.0/24","nextHops":[{"address":"192.0.2.2"}]}`, func(db vlanChangeDB) {
			db["DEVICE_METADATA|localhost"] = map[string]string{"frr_mgmt_framework_config": "unknown"}
		}},
		{"legacy default route", "StaticRoute", `{"prefix":"192.0.2.0/24","nextHops":[{"address":"192.0.2.2"}]}`, func(db vlanChangeDB) { db["STATIC_ROUTE|192.0.2.0/24"] = map[string]string{"nexthop": "192.0.2.2"} }},
		{"existing LAG omitted incompatible member", "PortChannel", `{"name":"PortChannel1","members":["Ethernet0"]}`, func(db vlanChangeDB) {
			db["PORTCHANNEL_MEMBER|PortChannel1|Ethernet4"] = map[string]string{"NULL": "NULL"}
			db["PORT|Ethernet4"]["speed"] = "40000"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := lagL3Fixture()
			tc.change(db)
			r := &agent.NetworkRequest{Kind: tc.kind, Spec: json.RawMessage(tc.spec)}
			var err error
			if tc.kind == "PortChannel" {
				_, err = planNetworkPortChannel(db, r)
			} else {
				_, err = planNetworkStaticRoute(db, r)
			}
			if err == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
	for _, name := range []string{"Ethernet0", "PortChannel10", "Vlan100"} {
		t.Run("L3 "+name, func(t *testing.T) {
			db := lagL3Fixture()
			db["PORTCHANNEL|PortChannel10"] = map[string]string{"admin_status": "up"}
			db["PORTCHANNEL_MEMBER|PortChannel10|Ethernet4"] = map[string]string{"NULL": "NULL"}
			request := &agent.NetworkRequest{Kind: "L3Interface", Spec: json.RawMessage(fmt.Sprintf(`{"name":%q,"addresses":["192.0.2.1/24"]}`, name))}
			p, err := planNetworkL3Interface(db, request)
			if err != nil {
				t.Fatal(err)
			}
			for k, v := range p.Desired {
				db[k] = v
			}
			db["STATIC_ROUTE|default|198.51.100.0/24"] = map[string]string{"nexthop": "192.0.2.2", "ifname": name, "distance": "1", "advertise": "false"}
			if _, err = planNetworkL3Interface(db, request); err != nil {
				t.Fatalf("legitimate route consumer blocked idempotent L3: %v", err)
			}
		})
	}
}

func TestNetworkLAGL3RouteRuntime(t *testing.T) {
	distance := uint32(1)
	for _, tc := range []struct {
		name, output string
		want         bool
	}{
		{"present", `{"2001:db8::/64":[{"protocol":"static","distance":1,"tag":2,"nexthops":[{"ip":"2001:db8:1::1","active":true}]}]}`, true},
		{"other protocol", `{"2001:db8::/64":[{"protocol":"bgp","distance":1,"tag":2,"nexthops":[{"ip":"2001:db8:1::1","active":true}]}]}`, false},
		{"advertising tag", `{"2001:db8::/64":[{"protocol":"static","distance":1,"tag":1,"nexthops":[{"ip":"2001:db8:1::1","active":true}]}]}`, false},
		{"missing", `{}`, false},
		{"malformed", `% Unknown command`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, _, err := lagL3RouteRuntime(t.Context(), "VrfBlue", "2001:db8::/64", []lagL3NextHop{{Address: "2001:db8:1::1", Distance: &distance}}, 2, func(_ context.Context, args ...string) ([]byte, error) {
				if !reflect.DeepEqual(args, []string{"docker", "exec", "bgp", "vtysh", "-c", "show ipv6 route vrf VrfBlue 2001:db8::/64 json"}) {
					t.Fatalf("unsafe command: %v", args)
				}
				return []byte(tc.output), nil
			})
			if ok != tc.want || (tc.want && err != nil) {
				t.Fatalf("runtime: %v %v", ok, err)
			}
		})
	}
}

func TestNetworkLAGL3VRFRuntime(t *testing.T) {
	for _, valid := range []bool{false, true} {
		t.Run(fmt.Sprint(valid), func(t *testing.T) {
			ok, _, err := lagL3VRFRuntime(t.Context(), "VrfBlue", func(context.Context, string) (map[string]string, error) {
				return map[string]string{"NULL": "NULL"}, nil
			}, func(string) (netlink.Link, error) {
				if valid {
					return &netlink.Vrf{Table: 1001}, nil
				}
				return &netlink.Dummy{}, nil
			})
			if ok != valid || err != nil {
				t.Fatalf("runtime: %v %v", ok, err)
			}
		})
	}
}

func TestNetworkLAGL3PortChannelRuntime(t *testing.T) {
	for _, tc := range []struct {
		name                               string
		wrongMaster, wrongRate, missingApp bool
	}{
		{"valid", false, false, false}, {"wrong master", true, false, false}, {"wrong rate", false, true, false}, {"missing APPL", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, _, err := lagL3PortChannelRuntime(t.Context(), "PortChannel10", []string{"Ethernet0"}, map[string]string{"mtu": "9100", "admin_status": "up", "min_links": "1", "fast_rate": "true"},
				func(context.Context, string) (map[string]string, error) {
					if tc.missingApp {
						return nil, nil
					}
					return map[string]string{"mtu": "9100"}, nil
				},
				func(name string) (netlink.Link, error) {
					if name == "PortChannel10" {
						return &netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Index: 10, MTU: 9100, Flags: net.FlagUp}, LinkType: "team"}, nil
					}
					master := 10
					if tc.wrongMaster {
						master = 20
					}
					return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{MasterIndex: master}}, nil
				},
				func(_ context.Context, args ...string) ([]byte, error) {
					if !reflect.DeepEqual(args, []string{"docker", "exec", "teamd", "teamdctl", "PortChannel10", "config", "dump"}) {
						t.Fatalf("command: %v", args)
					}
					return []byte(fmt.Sprintf(`{"device":"PortChannel10","runner":{"name":"lacp","active":true,"min_ports":1,"fast_rate":%t}}`, !tc.wrongRate)), nil
				})
			if err != nil || ok != (tc.name == "valid") {
				t.Fatalf("runtime: %v %v", ok, err)
			}
		})
	}
}

func TestNetworkLAGL3CancelledRuntime(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	read := func(context.Context, string) (map[string]string, error) {
		t.Fatal("read after cancellation")
		return nil, nil
	}
	link := func(string) (netlink.Link, error) { t.Fatal("netlink after cancellation"); return nil, nil }
	run := func(context.Context, ...string) ([]byte, error) {
		t.Fatal("command after cancellation")
		return nil, nil
	}
	if ok, _, err := lagL3VRFRuntime(ctx, "VrfBlue", read, link); ok || err == nil {
		t.Fatal("VRF cancellation")
	}
	if ok, _, err := lagL3InterfaceRuntime(ctx, "Ethernet0", "default", nil, read, link); ok || err == nil {
		t.Fatal("L3 cancellation")
	}
	if ok, _, err := lagL3PortChannelRuntime(ctx, "PortChannel10", nil, nil, read, link, run); ok || err == nil {
		t.Fatal("LAG cancellation")
	}
	if ok, _, err := lagL3RouteRuntime(ctx, "default", "192.0.2.0/24", nil, 2, run); ok || err == nil {
		t.Fatal("route cancellation")
	}
}

func TestNetworkLAGL3RouteVectors(t *testing.T) {
	db := lagL3Fixture()
	db["INTERFACE|Ethernet0"] = map[string]string{"vrf_name": "VrfBlue"}
	db["INTERFACE|Ethernet0|192.0.2.1/24"] = map[string]string{"NULL": "NULL"}
	p, err := planNetworkStaticRoute(db, &agent.NetworkRequest{Kind: "StaticRoute", Spec: json.RawMessage(`{"vrf":"VrfBlue","prefix":"198.51.100.0/24","nextHops":[{"address":"192.0.2.3"},{"address":"192.0.2.2","interfaceName":"Ethernet0","distance":20}]}`)})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.Desired["STATIC_ROUTE|VrfBlue|198.51.100.0/24"], map[string]string{"nexthop": "192.0.2.2,192.0.2.3", "ifname": "Ethernet0,", "distance": "20,1", "advertise": "false"}) {
		t.Fatalf("vector alignment: %v", p.Desired)
	}
	db["INTERFACE|Ethernet0"]["vrf_name"] = "default"
	if _, err := planNetworkStaticRoute(db, &agent.NetworkRequest{Kind: "StaticRoute", Spec: json.RawMessage(`{"vrf":"VrfBlue","prefix":"198.51.100.0/24","nextHops":[{"address":"192.0.2.2","interfaceName":"Ethernet0"}]}`)}); err == nil {
		t.Fatal("VRF mismatch accepted")
	}
}

func TestNetworkLAGL3RuntimeOutputBound(t *testing.T) {
	var out lagL3BoundedOutput
	_, err := io.Copy(&out, io.LimitReader(strings.NewReader(strings.Repeat("x", (1<<20)+1)), (1<<20)+1))
	if err == nil {
		t.Fatal("runtime output bypassed size bound")
	}
}
