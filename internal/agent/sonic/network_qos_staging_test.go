// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"strings"
	"testing"
)

const qosTestStageSupport = `{"running":true,"tokens":["SCHEDULER","STRICT","WRR","DWRR","bytes","packets","type","weight","meter_type","cir","pir","cbs","pbs"]}`

func TestNetworkQoSSchedulerStageConsumer(t *testing.T) {
	fields := qosRuntimeFixture().db["CONFIG_DB"]["SCHEDULER|shape"]
	for _, tc := range []struct {
		name, data string
		want       bool
	}{
		{"supported contract", qosTestStageSupport, true},
		{"stopped", strings.Replace(qosTestStageSupport, "true", "false", 1), false},
		{"missing enum", strings.Replace(qosTestStageSupport, `"DWRR",`, "", 1), false},
		{"unconsumed shape", strings.Replace(qosTestStageSupport, `,"pir"`, "", 1), false},
		{"invalid probe", `{`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if (qosValidateStageSupport([]byte(tc.data), fields) == nil) != tc.want {
				t.Fatal("consumer verdict mismatch")
			}
		})
	}
}

func TestNetworkQoSSchedulerStagingRejectsDanglingReferences(t *testing.T) {
	for _, tc := range []struct{ name, key, field, value string }{
		{"queue", "QUEUE|Ethernet0|9", "scheduler", "new"},
		{"grouped queue", "QUEUE|Ethernet0,Ethernet4|0-9", "scheduler", "new"},
		{"port", "PORT_QOS_MAP|Ethernet0", "scheduler", "new"},
		{"bracket reference", "VENDOR|x", "profile", "[SCHEDULER|new]"},
		{"qualified reference", "VENDOR|x", "profile", "SCHEDULER|new"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := qosRuntimeFixture()
			r.db["CONFIG_DB"][tc.key] = map[string]string{tc.field: tc.value}
			if err := qosProfilePreflight(t.Context(), r, vlanChangeDB{"SCHEDULER|new": {"type": "STRICT", "meter_type": "bytes"}}); err == nil {
				t.Fatal("creating scheduler would resolve existing binding")
			}
		})
	}
}

func TestNetworkQoSStandaloneTopologyEvidence(t *testing.T) {
	// Topology helpers remain independently tested even though profile-name
	// acknowledgement currently blocks the binding path before these checks.
	r := qosRuntimeFixture()
	caps := r.db["STATE_DB"]["SWITCH_CAPABILITY|switch"]
	if oid, err := qosQueueOID(t.Context(), r, "Ethernet0", qosTestPort, "9", caps); err != nil || oid != qosTestQueue {
		t.Fatalf("%s %v", oid, err)
	}
	if group, _, err := qosQueueGroup(t.Context(), r, qosTestPort, qosTestQueue); err != nil || group != qosTestGroup {
		t.Fatalf("%s %v", group, err)
	}
	r.db["ASIC_DB"]["ASIC_STATE:SAI_OBJECT_TYPE_SCHEDULER_GROUP:"+qosTestGroup]["SAI_SCHEDULER_GROUP_ATTR_CHILD_LIST"] = "2:" + qosTestQueue + ",oid:0x15000000000002"
	if group, _, err := qosQueueGroup(t.Context(), r, qosTestPort, qosTestQueue); err != nil || group != "" {
		t.Fatal("shared group accepted")
	}
}

func TestNetworkQoSMapReferenceGuard(t *testing.T) {
	for _, typ := range []string{"DSCPToTC", "Dot1pToTC", "TCToQueue"} {
		kind := qosMapKinds[typ]
		for _, ref := range []struct{ name, key, field, value string }{
			{"port", "PORT_QOS_MAP|Ethernet0", kind.field, "NewMap"},
			{"global", "PORT_QOS_MAP|global", kind.field, "NewMap"},
			{"grouped", "PORT_QOS_MAP|Ethernet0,Ethernet4", kind.field, "NewMap"},
			{"tunnel", "TUNNEL|t", "decap_" + kind.field, "NewMap"},
			{"qualified", "VENDOR|x", "profile", kind.table + "|NewMap"},
			{"bracket list", "VENDOR|x", "profiles@", "other,[" + kind.table + "|NewMap]"},
		} {
			t.Run(typ+"/"+ref.name, func(t *testing.T) {
				r := qosRuntimeFixture()
				key := kind.table + "|NewMap"
				r.db["CONFIG_DB"][ref.key] = map[string]string{ref.field: ref.value}
				desired := vlanChangeDB{key: {"1": "1"}}
				if err := qosProfilePreflight(t.Context(), r, desired); err == nil {
					t.Fatal("dangling map reference would autoactivate")
				}
				r.db["CONFIG_DB"][key] = map[string]string{"0": "0"}
				if err := qosProfilePreflight(t.Context(), r, desired); err == nil {
					t.Fatal("bound map extension accepted")
				}
				desired = vlanChangeDB{key: {"0": "0"}}
				if err := qosProfilePreflight(t.Context(), r, desired); err != nil {
					t.Fatalf("no-op blocked: %v", err)
				}
				if _, _, err := qosObserveProfile(t.Context(), r, desired); err != nil {
					t.Fatalf("observation blocked: %v", err)
				}
			})
		}
	}
}
