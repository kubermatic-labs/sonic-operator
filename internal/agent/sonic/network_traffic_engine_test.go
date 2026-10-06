// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"encoding/json"
	"strings"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

func TestNetworkTrafficIdentity(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, kind, spec, want string }{
		{"policy", "ACLPolicy", `{"name":"Edge_1"}`, "ACLPolicy|Edge_1"},
		{"binding", "ACLBinding", `{"policy":"Edge_1","interfaces":null}`, "ACLBinding|Edge_1"},
		{"dscp", "QoSMap", `{"type":"DSCPToTC","name":"Map1"}`, "QoSMap|DSCPToTC|Map1"},
		{"dot1p", "QoSMap", `{"type":"Dot1pToTC","name":"Map1"}`, "QoSMap|Dot1pToTC|Map1"},
		{"tc", "QoSMap", `{"type":"TCToQueue","name":"Map1"}`, "QoSMap|TCToQueue|Map1"},
		{"scheduler", "Scheduler", `{"name":"Weighted","weight":null}`, "Scheduler|Weighted"},
		{"port", "QoSBinding", `{"interfaceName":"Ethernet0","queues":null}`, "QoSBinding|Ethernet0"},
		{"policy delimiter", "ACLPolicy", `{"name":"Edge|rule"}`, ""},
		{"binding delimiter", "ACLBinding", `{"policy":"Edge|rule"}`, ""},
		{"null binding", "ACLBinding", `{"policy":null}`, ""},
		{"numeric binding", "ACLBinding", `{"policy":1}`, ""},
		{"duplicate identity", "ACLPolicy", `{"name":"Edge","name":"Other"}`, ""},
		{"wrong map type", "QoSMap", `{"type":"DSCP_TO_TC_MAP","name":"Map1"}`, ""},
		{"map delimiter", "QoSMap", `{"type":"DSCPToTC","name":"Map|1"}`, ""},
		{"null map type", "QoSMap", `{"type":null,"name":"Map1"}`, ""},
		{"scheduler control", "Scheduler", `{"name":"Weighted\n"}`, ""},
		{"oversized name", "Scheduler", `{"name":"` + strings.Repeat("a", 65) + `"}`, ""},
		{"noncanonical port", "QoSBinding", `{"interfaceName":"Ethernet00"}`, ""},
		{"management port", "QoSBinding", `{"interfaceName":"eth0"}`, ""},
		{"lag binding", "QoSBinding", `{"interfaceName":"PortChannel0"}`, ""},
		{"numeric port", "QoSBinding", `{"interfaceName":0}`, ""},
		{"overflow port", "QoSBinding", `{"interfaceName":"Ethernet4294967296"}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := networkIdentity(&agent.NetworkRequest{Kind: tc.kind, Spec: json.RawMessage(tc.spec)})
			if got != tc.want || (err == nil) != (tc.want != "") {
				t.Fatalf("identity=%q err=%v want=%q", got, err, tc.want)
			}
		})
	}
}

func TestNetworkTrafficFieldReservations(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, kind, key, field string
		valid                  bool
	}{
		{"policy table", "ACLPolicy", "ACL_TABLE|Edge", "type", true},
		{"policy rule", "ACLPolicy", "ACL_RULE|Edge|Allow", "SRC_IPV6", true},
		{"binding ports", "ACLBinding", "ACL_TABLE|Edge", "ports@", true},
		{"policy cannot bind", "ACLPolicy", "ACL_TABLE|Edge", "ports@", false},
		{"binding cannot redefine", "ACLBinding", "ACL_TABLE|Edge", "type", false},
		{"binding cannot add rules", "ACLBinding", "ACL_RULE|Edge|Allow", "PRIORITY", false},
		{"no policer", "ACLPolicy", "ACL_RULE|Edge|Allow", "POLICER", false},
		{"family qualifier", "ACLPolicy", "ACL_RULE|Edge|Allow", "IP_TYPE", true},
		{"IPv6 protocol", "ACLPolicy", "ACL_RULE|Edge|Allow", "NEXT_HEADER", true},
		{"multiple field tokens", "ACLPolicy", "ACL_TABLE|Edge", "type stage", false},
		{"invalid rule name", "ACLPolicy", "ACL_RULE|Edge|Allow|extra", "PRIORITY", false},
		{"invalid table name", "ACLPolicy", "ACL_TABLE|Edge|extra", "type", false},
		{"dscp zero", "QoSMap", "DSCP_TO_TC_MAP|Map1", "0", true},
		{"dscp max", "QoSMap", "DSCP_TO_TC_MAP|Map1", "63", true},
		{"dscp overflow", "QoSMap", "DSCP_TO_TC_MAP|Map1", "64", false},
		{"dot1p max", "QoSMap", "DOT1P_TO_TC_MAP|Map1", "7", true},
		{"dot1p overflow", "QoSMap", "DOT1P_TO_TC_MAP|Map1", "8", false},
		{"tc max", "QoSMap", "TC_TO_QUEUE_MAP|Map1", "255", true},
		{"tc overflow", "QoSMap", "TC_TO_QUEUE_MAP|Map1", "256", false},
		{"map field escape", "QoSMap", "DSCP_TO_TC_MAP|Map1", "admin_status", false},
		{"map unknown table", "QoSMap", "PORT|Ethernet0", "0", false},
		{"map name delimiter", "QoSMap", "DSCP_TO_TC_MAP|Map1|extra", "0", false},
		{"noncanonical numeric", "QoSMap", "DSCP_TO_TC_MAP|Map1", "01", false},
		{"signed numeric", "QoSMap", "DSCP_TO_TC_MAP|Map1", "+1", false},
		{"negative numeric", "QoSMap", "DSCP_TO_TC_MAP|Map1", "-1", false},
		{"numeric whitespace", "QoSMap", "DSCP_TO_TC_MAP|Map1", "1 ", false},
		{"empty numeric", "QoSMap", "DSCP_TO_TC_MAP|Map1", "", false},
		{"scheduler", "Scheduler", "SCHEDULER|Weighted", "pir", true},
		{"no wred", "Scheduler", "WRED_PROFILE|Weighted", "pir", false},
		{"port map", "QoSBinding", "PORT_QOS_MAP|Ethernet0", "dscp_to_tc_map", true},
		{"queue", "QoSBinding", "QUEUE|Ethernet0|7", "scheduler", true},
		{"queue range", "QoSBinding", "QUEUE|Ethernet0|0-7", "scheduler", false},
		{"queue overflow", "QoSBinding", "QUEUE|Ethernet0|4294967296", "scheduler", false},
		{"queue alias", "QoSBinding", "QUEUE|Ethernet00|7", "scheduler", false},
		{"no pfc", "QoSBinding", "PORT_QOS_MAP|Ethernet0", "pfc_enable", false},
		{"no buffer", "QoSBinding", "BUFFER_PG|Ethernet0|0", "profile", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateNetworkFields(tc.kind, vlanChangeDB{tc.key: {tc.field: "value"}})
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
		})
	}
}

func TestNetworkTrafficPlannerDispatch(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, kind, spec, identity string
		db                         vlanChangeDB
	}{
		{"policy", "ACLPolicy", `{"name":"Edge","family":"IPv4","defaultAction":"Drop","rules":[]}`, "ACLPolicy|Edge", nil},
		{"dscp", "QoSMap", `{"name":"Map1","type":"DSCPToTC","entries":[{"from":63,"to":0}]}`, "QoSMap|DSCPToTC|Map1", nil},
		{"dot1p", "QoSMap", `{"name":"Map1","type":"Dot1pToTC","entries":[{"from":7,"to":0}]}`, "QoSMap|Dot1pToTC|Map1", nil},
		{"tc", "QoSMap", `{"name":"Map1","type":"TCToQueue","entries":[{"from":0,"to":0}]}`, "QoSMap|TCToQueue|Map1", nil},
		{"scheduler", "Scheduler", `{"name":"Strict","algorithm":"STRICT"}`, "Scheduler|Strict", nil},
		{"qos binding", "QoSBinding", `{"interfaceName":"Ethernet0","dscpToTC":"Map1","queues":[{"index":0,"scheduler":"Strict"}]}`, "QoSBinding|Ethernet0", vlanChangeDB{
			"PORT|Ethernet0": {"lanes": "0"}, "DSCP_TO_TC_MAP|Map1": {"0": "0"}, "SCHEDULER|Strict": {"type": "STRICT", "meter_type": "bytes"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &agent.NetworkRequest{Kind: tc.kind, OwnerID: "uid", Spec: json.RawMessage(tc.spec)}
			p, err := planNetworkResource(tc.db, r)
			if err != nil {
				t.Fatal(err)
			}
			if p.Identity != tc.identity || p.Preflight == nil || p.Runtime == nil || p.Activate != nil {
				t.Fatalf("traffic planner contract: %+v", p)
			}
			if err := validateNetworkFields(tc.kind, p.Desired); err != nil {
				t.Fatal(err)
			}
			if tc.kind == "ACLPolicy" {
				if _, binds := p.Desired["ACL_TABLE|Edge"]["ports@"]; binds {
					t.Fatal("policy reserves binding field")
				}
				// Port presence is a planner dependency; supply it with the staged table.
				p.Desired["PORT|Ethernet0"] = map[string]string{"lanes": "0"}
				binding, err := planNetworkResource(p.Desired, &agent.NetworkRequest{Kind: "ACLBinding", OwnerID: "binding-uid", Spec: json.RawMessage(`{"policy":"Edge","interfaces":["Ethernet0"]}`)})
				if err != nil {
					t.Fatal(err)
				}
				if binding.Identity != "ACLBinding|Edge" || binding.Preflight == nil || binding.Runtime == nil {
					t.Fatalf("binding contract: %+v", binding)
				}
				if err := validateNetworkFields("ACLBinding", binding.Desired); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
