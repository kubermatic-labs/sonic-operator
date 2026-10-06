// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"errors"
	"maps"
	"path"
	"strings"
	"testing"
)

type qosFakeRead struct {
	db       map[string]vlanChangeDB
	errDB    string
	stageErr error
}

func (r *qosFakeRead) schedulerStageSupport(context.Context, map[string]string) error {
	return r.stageErr
}

func (r *qosFakeRead) configSnapshot(context.Context) (vlanChangeDB, error) {
	if r.errDB == "CONFIG_DB" {
		return nil, errors.New("probe denied")
	}
	db := vlanChangeDB{}
	for key, row := range r.db["CONFIG_DB"] {
		db[key] = maps.Clone(row)
	}
	return db, nil
}

func (r *qosFakeRead) hash(_ context.Context, db, key string) (map[string]string, error) {
	if r.errDB == db {
		return nil, errors.New("probe denied")
	}
	return maps.Clone(r.db[db][key]), nil
}
func (r *qosFakeRead) keys(_ context.Context, db, pattern string) ([]string, error) {
	if r.errDB == db {
		return nil, errors.New("probe denied")
	}
	var keys []string
	for key := range r.db[db] {
		if ok, _ := path.Match(pattern, key); ok {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

const (
	qosTestPort      = "oid:0x1000000000001"
	qosTestQueue     = "oid:0x15000000000001"
	qosTestGroup     = "oid:0x17000000000001"
	qosTestMap       = "oid:0x14000000000001"
	qosTestScheduler = "oid:0x16000000000001"
)

func qosRuntimeFixture() *qosFakeRead {
	return &qosFakeRead{db: map[string]vlanChangeDB{
		"CONFIG_DB": {
			"PORT|Ethernet0":         {"lanes": "0"},
			"DSCP_TO_TC_MAP|native":  {"63": "9"},
			"SCHEDULER|shape":        {"type": "DWRR", "weight": "5", "meter_type": "bytes", "cir": "1000", "pir": "2000", "cbs": "100", "pbs": "200"},
			"PORT_QOS_MAP|Ethernet0": {"dscp_to_tc_map": "native"},
			"QUEUE|Ethernet0|9":      {"scheduler": "shape", "wred_profile": "untouched"},
		},
		"STATE_DB":    {"SWITCH_CAPABILITY|switch": {"SWITCH|NUMBER_OF_TRAFFIC_CLASSES": "10", "SWITCH|NUMBER_OF_UNICAST_QUEUES": "10"}},
		"COUNTERS_DB": {"COUNTERS_PORT_NAME_MAP": {"Ethernet0": qosTestPort}, "COUNTERS_QUEUE_NAME_MAP": {"Ethernet0:9": qosTestQueue}},
		"ASIC_DB": {
			"VIDTORID": {qosTestPort: "oid:0x1", qosTestQueue: "oid:0x2", qosTestGroup: "oid:0x3", qosTestMap: "oid:0x4", qosTestScheduler: "oid:0x5"},
			"ASIC_STATE:SAI_OBJECT_TYPE_PORT:" + qosTestPort:             {"SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP": qosTestMap, "SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL": "0", "SAI_PORT_ATTR_QOS_SCHEDULER_GROUP_LIST": "1:" + qosTestGroup},
			"ASIC_STATE:SAI_OBJECT_TYPE_QUEUE:" + qosTestQueue:           {"SAI_QUEUE_ATTR_TYPE": "SAI_QUEUE_TYPE_UNICAST", "SAI_QUEUE_ATTR_INDEX": "9", "SAI_QUEUE_ATTR_PORT": qosTestPort},
			"ASIC_STATE:SAI_OBJECT_TYPE_SCHEDULER_GROUP:" + qosTestGroup: {"SAI_SCHEDULER_GROUP_ATTR_PORT_ID": qosTestPort, "SAI_SCHEDULER_GROUP_ATTR_CHILD_COUNT": "1", "SAI_SCHEDULER_GROUP_ATTR_CHILD_LIST": "1:" + qosTestQueue, "SAI_SCHEDULER_GROUP_ATTR_SCHEDULER_PROFILE_ID": qosTestScheduler},
			"ASIC_STATE:SAI_OBJECT_TYPE_QOS_MAP:" + qosTestMap:           {"SAI_QOS_MAP_ATTR_TYPE": "SAI_QOS_MAP_TYPE_DSCP_TO_TC", "SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST": `{"count":1,"list":[{"key":{"dscp":63},"value":{"tc":9}}]}`},
			"ASIC_STATE:SAI_OBJECT_TYPE_SCHEDULER:" + qosTestScheduler:   {"SAI_SCHEDULER_ATTR_SCHEDULING_TYPE": "SAI_SCHEDULING_TYPE_DWRR", "SAI_SCHEDULER_ATTR_SCHEDULING_WEIGHT": "5", "SAI_SCHEDULER_ATTR_METER_TYPE": "SAI_METER_TYPE_BYTES", "SAI_SCHEDULER_ATTR_MIN_BANDWIDTH_RATE": "1000", "SAI_SCHEDULER_ATTR_MAX_BANDWIDTH_RATE": "2000", "SAI_SCHEDULER_ATTR_MIN_BANDWIDTH_BURST_RATE": "100", "SAI_SCHEDULER_ATTR_MAX_BANDWIDTH_BURST_RATE": "200"},
		},
	}}
}

func TestNetworkQoSProfileRuntime(t *testing.T) {
	t.Parallel()
	for _, table := range []string{"DSCP_TO_TC_MAP|native", "SCHEDULER|shape"} {
		t.Run(table, func(t *testing.T) {
			for _, tc := range []struct {
				name          string
				mutate        func(*qosFakeRead)
				want, wantErr bool
			}{
				{"stale exact object is not name proof", func(*qosFakeRead) {}, false, false},
				{"absent configuration", func(r *qosFakeRead) { delete(r.db["CONFIG_DB"], table) }, false, false},
				{"config only", func(r *qosFakeRead) { r.db["ASIC_DB"] = vlanChangeDB{} }, false, false},
				{"no translation", func(r *qosFakeRead) { delete(r.db["ASIC_DB"], "VIDTORID") }, false, false},
				{"duplicate config", func(r *qosFakeRead) {
					prefix, _, _ := strings.Cut(table, "|")
					r.db["CONFIG_DB"][prefix+"|ambiguous"] = maps.Clone(r.db["CONFIG_DB"][table])
				}, false, false},
				{"probe error", func(r *qosFakeRead) { r.errDB = "ASIC_DB" }, false, true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					r := qosRuntimeFixture()
					desired := vlanChangeDB{table: maps.Clone(r.db["CONFIG_DB"][table])}
					tc.mutate(r)
					ok, raw, err := qosObserveProfile(t.Context(), r, desired)
					if ok != tc.want || (err != nil) != tc.wantErr {
						t.Fatalf("ok=%v raw=%s err=%v", ok, raw, err)
					}
				})
			}
		})
	}
}

func TestNetworkQoSBindingRuntimeAndPreflight(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name           string
		mutate         func(*qosFakeRead)
		want, probeErr bool
	}{
		{"matching binding OID is not consumer name proof", func(*qosFakeRead) {}, false, false},
		{"missing caps", func(r *qosFakeRead) { r.db["STATE_DB"] = vlanChangeDB{} }, false, false},
		{"smaller device", func(r *qosFakeRead) {
			r.db["STATE_DB"]["SWITCH_CAPABILITY|switch"]["SWITCH|NUMBER_OF_TRAFFIC_CLASSES"] = "8"
		}, false, false},
		{"missing profile", func(r *qosFakeRead) { delete(r.db["CONFIG_DB"], "SCHEDULER|shape") }, false, false},
		{"missing map SAI", func(r *qosFakeRead) { delete(r.db["ASIC_DB"], "ASIC_STATE:SAI_OBJECT_TYPE_QOS_MAP:"+qosTestMap) }, false, false},
		{"multicast", func(r *qosFakeRead) {
			r.db["ASIC_DB"]["ASIC_STATE:SAI_OBJECT_TYPE_QUEUE:"+qosTestQueue]["SAI_QUEUE_ATTR_TYPE"] = "SAI_QUEUE_TYPE_MULTICAST"
		}, false, false},
		{"wrong queue index", func(r *qosFakeRead) {
			r.db["ASIC_DB"]["ASIC_STATE:SAI_OBJECT_TYPE_QUEUE:"+qosTestQueue]["SAI_QUEUE_ATTR_INDEX"] = "0"
		}, false, false},
		{"foreign queue port", func(r *qosFakeRead) {
			r.db["ASIC_DB"]["ASIC_STATE:SAI_OBJECT_TYPE_QUEUE:"+qosTestQueue]["SAI_QUEUE_ATTR_PORT"] = "oid:0x2"
		}, false, false},
		{"absent group metadata", func(r *qosFakeRead) {
			delete(r.db["ASIC_DB"]["ASIC_STATE:SAI_OBJECT_TYPE_PORT:"+qosTestPort], "SAI_PORT_ATTR_QOS_SCHEDULER_GROUP_LIST")
		}, false, false},
		{"sibling queue", func(r *qosFakeRead) {
			g := r.db["ASIC_DB"]["ASIC_STATE:SAI_OBJECT_TYPE_SCHEDULER_GROUP:"+qosTestGroup]
			g["SAI_SCHEDULER_GROUP_ATTR_CHILD_LIST"] = "2:" + qosTestQueue + ",oid:0x15000000000002"
			g["SAI_SCHEDULER_GROUP_ATTR_CHILD_COUNT"] = "2"
		}, false, false},
		{"range overlap", func(r *qosFakeRead) {
			r.db["CONFIG_DB"]["QUEUE|Ethernet0|8-9"] = map[string]string{"scheduler": "shape"}
		}, false, false},
		{"grouped port overlap", func(r *qosFakeRead) {
			r.db["CONFIG_DB"]["PORT_QOS_MAP|Ethernet0,Ethernet4"] = map[string]string{"dscp_to_tc_map": "native"}
		}, false, false},
		{"untracked PFC", func(r *qosFakeRead) {
			r.db["ASIC_DB"]["ASIC_STATE:SAI_OBJECT_TYPE_PORT:"+qosTestPort]["SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL"] = "8"
		}, false, false},
		{"probe denied", func(r *qosFakeRead) { r.errDB = "COUNTERS_DB" }, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := qosRuntimeFixture()
			tc.mutate(r)
			desired := vlanChangeDB{"PORT_QOS_MAP|Ethernet0": {"dscp_to_tc_map": "native"}, "QUEUE|Ethernet0|9": {"scheduler": "shape"}}
			ok, raw, err := qosBindingProof(t.Context(), r, "Ethernet0", desired, true)
			if ok != tc.want || (err != nil) != tc.probeErr {
				t.Fatalf("runtime ok=%v raw=%s err=%v", ok, raw, err)
			}
			_, _, err = qosBindingProof(t.Context(), r, "Ethernet0", desired, false)
			if (err == nil) != tc.want {
				t.Fatalf("preflight err=%v", err)
			}
		})
	}
}

func TestNetworkQoSBindingRequiresCausalProofEvenWithUnboundProfiles(t *testing.T) {
	r := qosRuntimeFixture()
	delete(r.db["CONFIG_DB"], "PORT_QOS_MAP|Ethernet0")
	delete(r.db["CONFIG_DB"], "QUEUE|Ethernet0|9")
	delete(r.db["ASIC_DB"]["ASIC_STATE:SAI_OBJECT_TYPE_PORT:"+qosTestPort], "SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP")
	delete(r.db["ASIC_DB"]["ASIC_STATE:SAI_OBJECT_TYPE_SCHEDULER_GROUP:"+qosTestGroup], "SAI_SCHEDULER_GROUP_ATTR_SCHEDULER_PROFILE_ID")
	desired := vlanChangeDB{"PORT_QOS_MAP|Ethernet0": {"dscp_to_tc_map": "native"}, "QUEUE|Ethernet0|9": {"scheduler": "shape"}}
	if _, raw, err := qosBindingProof(t.Context(), r, "Ethernet0", desired, false); err == nil {
		t.Fatalf("binding without causal name proof accepted: %s", raw)
	}
	for key, row := range desired {
		r.db["CONFIG_DB"][key] = maps.Clone(row)
	}
	if ok, _, err := qosBindingProof(t.Context(), r, "Ethernet0", desired, true); ok || err != nil {
		t.Fatalf("CONFIG is not applied proof: %v %v", ok, err)
	}
}

func TestNetworkQoSSchedulerStagingDoesNotRequireExistingShape(t *testing.T) {
	r := qosRuntimeFixture()
	desired := vlanChangeDB{"SCHEDULER|new": maps.Clone(r.db["CONFIG_DB"]["SCHEDULER|shape"])}
	if err := qosProfilePreflight(t.Context(), r, desired); err != nil {
		t.Fatal(err)
	}
	desired["SCHEDULER|new"]["pir"] = "3000"
	if err := qosProfilePreflight(t.Context(), r, desired); err != nil {
		t.Fatalf("first shaping combination must be stageable unbound: %v", err)
	}
	desired["SCHEDULER|new"]["pir"] = "2000"
	delete(r.db["ASIC_DB"], "VIDTORID")
	if err := qosProfilePreflight(t.Context(), r, desired); err != nil {
		t.Fatalf("staging must not depend on existing ASIC objects: %v", err)
	}
	r.stageErr = errors.New("consumer unsupported")
	if err := qosProfilePreflight(t.Context(), r, desired); err == nil {
		t.Fatal("unsupported consumer accepted")
	}
}

func TestNetworkQoSNativeMapSerialization(t *testing.T) {
	// sonic-sairedis 202511 meta/SaiSerialize.cpp serializes queue_index as
	// qidx and color as an enum string, including all zero-valued fields.
	for _, tc := range []struct {
		name, typ, fields, serialized string
		want                          bool
	}{
		{"native dscp", "DSCPToTC", "63", `{"count":1,"list":[{"key":{"tc":0,"dscp":63,"dot1p":0,"prio":0,"pg":0,"qidx":0,"mpls_exp":0,"color":"SAI_PACKET_COLOR_GREEN","fc":0},"value":{"tc":9,"dscp":0,"dot1p":0,"prio":0,"pg":0,"qidx":0,"mpls_exp":0,"color":"SAI_PACKET_COLOR_GREEN","fc":0}}]}`, true},
		{"native queue", "TCToQueue", "0", `{"count":1,"list":[{"key":{"tc":0,"color":"SAI_PACKET_COLOR_GREEN"},"value":{"qidx":9,"color":"SAI_PACKET_COLOR_GREEN"}}]}`, true},
		{"nonzero extra", "DSCPToTC", "63", `{"count":1,"list":[{"key":{"dscp":63,"prio":1},"value":{"tc":9}}]}`, false},
		{"wrong count", "DSCPToTC", "63", `{"count":2,"list":[{"key":{"dscp":63},"value":{"tc":9}}]}`, false},
		{"unexpected color", "DSCPToTC", "63", `{"count":1,"list":[{"key":{"dscp":63,"color":"SAI_PACKET_COLOR_RED"},"value":{"tc":9}}]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kind := qosMapKinds[tc.typ]
			if got := qosMapMatches(kind, map[string]string{tc.fields: "9"}, map[string]string{"SAI_QOS_MAP_ATTR_TYPE": "SAI_QOS_MAP_TYPE_" + kind.sai, "SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST": tc.serialized}); got != tc.want {
				t.Fatalf("match=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestNetworkQoSNativeSchemaAndPFCGuards(t *testing.T) {
	for _, tc := range []struct {
		name, table string
		fields      map[string]string
	}{
		{"native tc schema", "DSCP_TO_TC_MAP", map[string]string{"0": "16"}},
		{"native queue schema", "TC_TO_QUEUE_MAP", map[string]string{"0": "10"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if qosValidateMap(tc.table, tc.fields) == nil {
				t.Fatal("exceeded installed YANG schema")
			}
		})
	}
	for _, tc := range []struct {
		name          string
		config, attrs map[string]string
		valid         bool
	}{
		{"preserved", map[string]string{"pfc_enable": "3,4"}, map[string]string{"SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL": "24"}, true},
		{"config drift", map[string]string{"pfc_enable": "3"}, map[string]string{"SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL": "24"}, false},
		{"missing runtime", map[string]string{"pfc_enable": "3"}, nil, false},
		{"asymmetric", nil, map[string]string{"SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL": "0", "SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL_MODE": "SAI_PORT_PRIORITY_FLOW_CONTROL_MODE_SEPARATE", "SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL_RX": "8"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if (qosPreservePFC(tc.config, tc.attrs) == nil) != tc.valid {
				t.Fatal("PFC preservation verdict mismatch")
			}
		})
	}
}
