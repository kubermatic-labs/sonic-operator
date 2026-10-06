// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

func aclRequest(kind, spec string) *agent.NetworkRequest {
	return &agent.NetworkRequest{Kind: kind, OwnerID: "acl-test-owner", Spec: json.RawMessage(spec)}
}

const aclTestSpec = `{"name":"EDGE","family":"IPv4","defaultAction":"Drop","rules":[{"name":"WEB","priority":100,"action":"Permit","source":"192.0.2.0/24","protocol":6,"destinationPort":443}]}`

func TestACLPolicyNativeMapping(t *testing.T) {
	t.Parallel()
	p, err := planNetworkACLPolicy(vlanChangeDB{}, aclRequest("ACLPolicy", aclTestSpec))
	if err != nil {
		t.Fatal(err)
	}
	want := vlanChangeDB{
		"ACL_TABLE|EDGE":        {"type": "L3", "stage": "INGRESS"},
		"ACL_RULE|EDGE|WEB":     {"PRIORITY": "100", "PACKET_ACTION": "FORWARD", "IP_TYPE": "IPV4ANY", "SRC_IP": "192.0.2.0/24", "IP_PROTOCOL": "6", "L4_DST_PORT": "443"},
		"ACL_RULE|EDGE|DEFAULT": {"PRIORITY": "1", "PACKET_ACTION": "DROP", "IP_TYPE": "IPV4ANY"},
	}
	if p.Identity != "ACLPolicy|EDGE" || !reflect.DeepEqual(p.Desired, want) || p.Preflight == nil || p.Runtime == nil {
		t.Fatalf("unexpected plan: %+v", p)
	}
	v6 := strings.NewReplacer("IPv4", "IPv6", "192.0.2.0/24", "2001:db8::/32").Replace(aclTestSpec)
	p, err = planNetworkACLPolicy(nil, aclRequest("ACLPolicy", v6))
	if err != nil {
		t.Fatal(err)
	}
	if p.Desired["ACL_TABLE|EDGE"]["type"] != "L3V6" || p.Desired["ACL_RULE|EDGE|WEB"]["NEXT_HEADER"] != "6" || p.Desired["ACL_RULE|EDGE|WEB"]["SRC_IPV6"] != "2001:db8::/32" {
		t.Fatal(p.Desired)
	}
}

func TestACLPolicyRejectsInvalidSpecs(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, old, replacement string }{
		{"unknown", `"family"`, `"unknown"`},
		{"case", `"family"`, `"Family"`},
		{"duplicate", `"family":"IPv4"`, `"family":"IPv4","family":"IPv4"`},
		{"null", `"protocol":6`, `"protocol":null`},
		{"missing default", `"defaultAction":"Drop",`, ``},
		{"invalid default", `"Drop"`, `"drop"`},
		{"reserved rule", `"WEB"`, `"DEFAULT"`},
		{"priority one", `"priority":100`, `"priority":1`},
		{"priority overflow", `"priority":100`, `"priority":1000000`},
		{"protocol zero", `"protocol":6`, `"protocol":0`},
		{"protocol overflow", `"protocol":6`, `"protocol":144`},
		{"port overflow", `"destinationPort":443`, `"destinationPort":65536`},
		{"ports without TCP UDP", `"protocol":6`, `"protocol":1`},
		{"family mismatch", `192.0.2.0/24`, `2001:db8::/32`},
		{"noncanonical prefix", `192.0.2.0/24`, `192.0.2.1/24`},
		{"injection", `"EDGE"`, `"EDGE;id"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := planNetworkACLPolicy(nil, aclRequest("ACLPolicy", strings.Replace(aclTestSpec, tc.old, tc.replacement, 1))); err == nil {
				t.Fatal("accepted invalid policy")
			}
		})
	}
}

func TestACLPolicyActiveMutationAndBindingOwnership(t *testing.T) {
	t.Parallel()
	r := aclRequest("ACLPolicy", aclTestSpec)
	p, err := planNetworkACLPolicy(nil, r)
	if err != nil {
		t.Fatal(err)
	}
	db := p.Desired
	db["PORT|Ethernet0"] = map[string]string{"admin_status": "up"}
	b, err := planNetworkACLBinding(db, aclRequest("ACLBinding", `{"policy":"EDGE","interfaces":["Ethernet0"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(b.Desired, vlanChangeDB{"ACL_TABLE|EDGE": {"ports@": "Ethernet0"}}) {
		t.Fatal(b.Desired)
	}
	db["ACL_TABLE|EDGE"]["ports@"] = "Ethernet0"
	if _, err = planNetworkACLPolicy(db, r); err != nil {
		t.Fatalf("bound exact no-op rejected: %v", err)
	}
	delete(db, "ACL_RULE|EDGE|WEB")
	if _, err = planNetworkACLPolicy(db, r); err == nil {
		t.Fatal("partial bound policy accepted")
	}
	delete(db["ACL_TABLE|EDGE"], "ports@")
	delete(db, "ACL_RULE|EDGE|DEFAULT")
	if _, err = planNetworkACLBinding(db, aclRequest("ACLBinding", `{"policy":"EDGE","interfaces":["Ethernet0"]}`)); err == nil {
		t.Fatal("binding without default accepted")
	}
}

func TestACLPolicyUniquenessAndPortZero(t *testing.T) {
	t.Parallel()
	var s aclPolicySpec
	if err := json.Unmarshal([]byte(aclTestSpec), &s); err != nil {
		t.Fatal(err)
	}
	zero := uint32(0)
	s.Rules[0].SourcePort = &zero
	raw, _ := json.Marshal(s)
	p, err := planNetworkACLPolicy(nil, aclRequest("ACLPolicy", string(raw)))
	if err != nil || p.Desired["ACL_RULE|EDGE|WEB"]["L4_SRC_PORT"] != "0" {
		t.Fatalf("explicit port zero lost: %+v %v", p, err)
	}
	for _, tc := range []struct {
		name string
		rule aclRuleSpec
	}{
		{"duplicate name", aclRuleSpec{Name: "WEB", Priority: 200, Action: "Drop"}},
		{"duplicate priority", aclRuleSpec{Name: "OTHER", Priority: 100, Action: "Drop"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := s
			copy.Rules = append(append([]aclRuleSpec(nil), s.Rules...), tc.rule)
			raw, _ := json.Marshal(copy)
			if _, err := planNetworkACLPolicy(nil, aclRequest("ACLPolicy", string(raw))); err == nil {
				t.Fatal("duplicate accepted")
			}
		})
	}
}

func TestACLBindingRejectsUnsafeInterfaces(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, spec string
		member     bool
	}{
		{"management", `{"policy":"EDGE","interfaces":["eth0"]}`, false},
		{"missing", `{"policy":"EDGE","interfaces":["Ethernet4"]}`, false},
		{"duplicate", `{"policy":"EDGE","interfaces":["Ethernet0","Ethernet0"]}`, false},
		{"LAG member", `{"policy":"EDGE","interfaces":["Ethernet0"]}`, true},
		{"unknown", `{"policy":"EDGE","interfaces":["Ethernet0"],"stage":"EGRESS"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := planNetworkACLPolicy(nil, aclRequest("ACLPolicy", aclTestSpec))
			if err != nil {
				t.Fatal(err)
			}
			db := p.Desired
			db["PORT|Ethernet0"] = map[string]string{"admin_status": "up"}
			if tc.member {
				db["PORTCHANNEL_MEMBER|PortChannel1|Ethernet0"] = map[string]string{"NULL": "NULL"}
			}
			if _, err := planNetworkACLBinding(db, aclRequest("ACLBinding", tc.spec)); err == nil {
				t.Fatal("unsafe interface accepted")
			}
		})
	}
}

func TestACLPolicyRejectsNativeOverrides(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		mutate func(vlanChangeDB)
	}{
		{"custom table type", func(db vlanChangeDB) {
			db["ACL_TABLE_TYPE|L3"] = map[string]string{"matches@": "DSCP", "actions@": "REDIRECT_ACTION"}
		}},
		{"unknown rule field", func(db vlanChangeDB) { db["ACL_RULE|EDGE|WEB"]["POLICER"] = "policer" }},
		{"unknown table field", func(db vlanChangeDB) { db["ACL_TABLE|EDGE"]["services@"] = "SSH" }},
		{"extra rule", func(db vlanChangeDB) {
			db["ACL_RULE|EDGE|EXTRA"] = map[string]string{"PRIORITY": "300", "PACKET_ACTION": "DROP", "IP_TYPE": "IPV4ANY"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := aclRequest("ACLPolicy", aclTestSpec)
			p, err := planNetworkACLPolicy(nil, r)
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(p.Desired)
			if _, err := planNetworkACLPolicy(p.Desired, r); err == nil {
				t.Fatal("native override accepted")
			}
		})
	}
}
