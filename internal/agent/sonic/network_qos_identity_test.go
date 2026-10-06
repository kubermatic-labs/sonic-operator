// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"encoding/json"
	"strings"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

func TestNetworkQoSNameContract(t *testing.T) {
	t.Parallel()
	for _, resource := range []struct{ name, kind, typ, table string }{
		{"dscp", "QoSMap", "DSCPToTC", "DSCP_TO_TC_MAP"},
		{"dot1p", "QoSMap", "Dot1pToTC", "DOT1P_TO_TC_MAP"},
		{"tc", "QoSMap", "TCToQueue", "TC_TO_QUEUE_MAP"},
		{"scheduler", "Scheduler", "", "SCHEDULER"},
	} {
		t.Run(resource.name, func(t *testing.T) {
			for _, tc := range []struct {
				name, value string
				valid       bool
			}{
				{"digit", "1", true},
				{"digit prefix", "1-default", true},
				{"letters", "Default_1", true},
				{"maximum length", "1" + strings.Repeat("a", 31), true},
				{"too long", "1" + strings.Repeat("a", 32), false},
				{"letter leading too long", strings.Repeat("a", 33), false},
				{"empty", "", false},
				{"hyphen prefix", "-default", false},
				{"underscore prefix", "_default", false},
				{"delimiter", "1|default", false},
				{"slash", "1/default", false},
				{"space", "1 default", false},
				{"control", "1\n", false},
				{"unicode", "1é", false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					spec := map[string]any{"name": tc.value}
					identity := resource.kind + "|" + tc.value
					fields := map[string]string{"type": "STRICT"}
					if resource.kind == "QoSMap" {
						spec["type"] = resource.typ
						spec["entries"] = []map[string]uint32{{"from": 0, "to": 0}}
						identity = resource.kind + "|" + resource.typ + "|" + tc.value
						fields = map[string]string{"0": "0"}
					} else {
						spec["algorithm"] = "STRICT"
					}
					raw, err := json.Marshal(spec)
					if err != nil {
						t.Fatal(err)
					}
					r := &agent.NetworkRequest{Kind: resource.kind, OwnerID: "uid", Spec: raw}
					p, planErr := planNetworkResource(nil, r)
					id, identityErr := networkIdentity(r)
					fieldErr := validateNetworkFields(resource.kind, vlanChangeDB{resource.table + "|" + tc.value: fields})
					if (planErr == nil) != tc.valid || (identityErr == nil) != tc.valid || (fieldErr == nil) != tc.valid {
						t.Fatalf("valid=%v planner=%v identity=%v fields=%v", tc.valid, planErr, identityErr, fieldErr)
					}
					if tc.valid {
						if id != identity || p.Identity != identity {
							t.Fatalf("identity=%q planner=%q want=%q", id, p.Identity, identity)
						}
						if err := validateNetworkFields(resource.kind, p.Desired); err != nil {
							t.Fatal(err)
						}
					}
				})
			}
		})
	}
}

func TestNetworkACLNamesRemainLetterLeading(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, kind, spec, key, field string }{
		{"policy", "ACLPolicy", `{"name":"1-default"}`, "ACL_TABLE|1-default", "type"},
		{"binding", "ACLBinding", `{"policy":"1-default"}`, "ACL_TABLE|1-default", "ports@"},
		{"rule", "ACLPolicy", `{"name":"1"}`, "ACL_RULE|Edge|1-default", "PRIORITY"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := networkIdentity(&agent.NetworkRequest{Kind: tc.kind, Spec: json.RawMessage(tc.spec)}); err == nil {
				t.Fatal("numeric ACL identity accepted")
			}
			if err := validateNetworkFields(tc.kind, vlanChangeDB{tc.key: {tc.field: "value"}}); err == nil {
				t.Fatal("numeric ACL target accepted")
			}
		})
	}
}
