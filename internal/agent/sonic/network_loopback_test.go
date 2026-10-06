// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"reflect"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/vishvananda/netlink"
)

func TestNetworkLoopbackPlan(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"Loopback0", "Loopback4095"} {
		t.Run(name, func(t *testing.T) {
			db := lagL3Fixture()
			db["LOOPBACK_INTERFACE|"+name] = map[string]string{"NULL": "NULL"}
			db["LOOPBACK_INTERFACE|"+name+"|10.1.0.1/32"] = map[string]string{"NULL": "NULL"}
			before, _ := json.Marshal(db)
			r := &agent.NetworkRequest{Kind: "L3Interface", OwnerID: "owner", Spec: json.RawMessage(`{"name":"` + name + `","addresses":["10.1.0.1/32"]}`)}
			p, err := planNetworkResource(db, r)
			if err != nil {
				t.Fatal(err)
			}
			id, err := networkIdentity(r)
			if err != nil || id != p.Identity {
				t.Fatalf("identity %s: %v", id, err)
			}
			want := vlanChangeDB{"LOOPBACK_INTERFACE|" + name: {"NULL": "NULL"}, "LOOPBACK_INTERFACE|" + name + "|10.1.0.1/32": {"NULL": "NULL"}}
			if !reflect.DeepEqual(p.Desired, want) || !networkSubset(db, p.Desired) || p.Activate != nil {
				t.Fatalf("not no-op adoption: %+v", p)
			}
			if err := validateNetworkFields(r.Kind, p.Desired); err != nil {
				t.Fatal(err)
			}
			after, _ := json.Marshal(db)
			if string(before) != string(after) {
				t.Fatal("mutated snapshot")
			}
		})
	}
}

func TestNetworkLoopbackRuntime(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, kernel string
		want         bool
	}{
		{"matching carrier unknown", `[{"ifname":"Loopback0","addr_info":[{"family":"inet","local":"10.1.0.1","prefixlen":32,"scope":"global"}]}]`, true},
		{"missing address", `[{"ifname":"Loopback0","addr_info":[]}]`, false},
		{"wrong prefix", `[{"ifname":"Loopback0","addr_info":[{"family":"inet","local":"10.1.0.1","prefixlen":24,"scope":"global"}]}]`, false},
		{"tentative address", `[{"ifname":"Loopback0","addr_info":[{"family":"inet","local":"10.1.0.1","prefixlen":32,"scope":"global","tentative":true}]}]`, false},
		{"other interface", `[{"ifname":"Ethernet0","addr_info":[{"family":"inet","local":"10.1.0.1","prefixlen":32,"scope":"global"}]}]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.WithValue(t.Context(), routingCommandRunnerKey{}, routingCommandRunner(func(cmd *exec.Cmd) ([]byte, error) {
				if !reflect.DeepEqual(cmd.Args, []string{"ip", "-j", "address", "show", "dev", "Loopback0"}) {
					t.Fatalf("unexpected command: %v", cmd.Args)
				}
				return []byte(tc.kernel), nil
			}))
			read := func(_ context.Context, key string) (map[string]string, error) {
				switch key {
				case "INTF_TABLE:Loopback0":
					return map[string]string{"admin_status": "up"}, nil
				case "INTF_TABLE:Loopback0:10.1.0.1/32":
					return map[string]string{"family": "IPv4", "scope": "global"}, nil
				default:
					return nil, fmt.Errorf("unexpected key")
				}
			}
			link := func(string) (netlink.Link, error) {
				return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "Loopback0", Index: 5}}, nil
			}
			ok, _, err := lagL3InterfaceRuntime(ctx, "Loopback0", "default", []string{"10.1.0.1/32"}, read, link)
			if err != nil || ok != tc.want {
				t.Fatalf("runtime=%v want=%v err=%v", ok, tc.want, err)
			}
		})
	}
}

func TestNetworkLoopbackRejects(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, spec string
		change     func(vlanChangeDB)
	}{
		{"leading zero", `{"name":"Loopback00","addresses":["10.1.0.1/32"]}`, nil},
		{"out of range", `{"name":"Loopback4096","addresses":["10.1.0.1/32"]}`, nil},
		{"shell name", `{"name":"Loopback0;id","addresses":["10.1.0.1/32"]}`, nil},
		{"unknown field", `{"name":"Loopback0","addresses":["10.1.0.1/32"],"mtu":65536}`, nil},
		{"noncanonical prefix", `{"name":"Loopback0","addresses":["2001:0db8::1/128"]}`, nil},
		{"physical conflict", `{"name":"Loopback0","addresses":["10.1.0.1/32"]}`, func(db vlanChangeDB) { db["INTERFACE|Ethernet0|10.1.0.1/32"] = map[string]string{"NULL": "NULL"} }},
		{"loopback conflict", `{"name":"Ethernet0","addresses":["10.1.0.1/32"]}`, func(db vlanChangeDB) {
			db["LOOPBACK_INTERFACE|Loopback0|10.1.0.1/32"] = map[string]string{"NULL": "NULL"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := lagL3Fixture()
			if tc.change != nil {
				tc.change(db)
			}
			if _, err := planNetworkResource(db, &agent.NetworkRequest{Kind: "L3Interface", OwnerID: "owner", Spec: json.RawMessage(tc.spec)}); err == nil {
				t.Fatal("accepted unsupported/conflicting loopback")
			}
		})
	}
}
