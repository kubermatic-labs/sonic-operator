// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"maps"
	"os"
	"strings"
	"testing"
)

func (r *qosFakeRead) bufferConsumer(ctx context.Context) (map[string]string, error) {
	return r.hash(ctx, "NATIVE", "BUFFER_CONSUMER")
}

func (r *qosFakeRead) bufferObject(ctx context.Context, table, name string) (map[string]string, error) {
	return r.hash(ctx, "TEST_CONSUMER_OBJECTS", table+"|"+name)
}

const (
	bufferPortOID    = "oid:0x1000000000629"
	bufferPGOID      = "oid:0x1a0000000006aa"
	bufferPoolOID    = "oid:0x180000000006ce"
	bufferProfileOID = "oid:0x190000000006cf"
)

// Native attributes/counter mappings below were captured read-only from a
// reference switch. PORT existence is test scaffolding, not port configuration evidence.
func bufferNativeFixture() *qosFakeRead {
	config := bufferTestDB()
	delete(config, "BUFFER_POOL|egress")
	delete(config, "BUFFER_PROFILE|out")
	config["BUFFER_POOL|PORT3_INGRESS_POOL"] = map[string]string{"mode": "dynamic", "size": "10875072", "type": "ingress", "xoff": "4194112"}
	config["DEVICE_METADATA|localhost"] = map[string]string{"buffer_model": "traditional", "platform": "x86_64-dell_z9100_c2538-r0", "hwsku": "Force10-Z9100-C32"}
	return &qosFakeRead{db: map[string]vlanChangeDB{
		// Synthetic independent producer instrumentation contract. These rows
		// are NOT captured evidence and do not exist on the inspected SONiC.
		"TEST_CONSUMER_OBJECTS": {
			"BUFFER_POOL|PORT3_INGRESS_POOL":       {"oid": bufferPoolOID, "pending_remove": "false", "lifecycle": "test-create-1"},
			"BUFFER_PROFILE|PORT3_INGRESS_PROFILE": {"oid": bufferProfileOID, "pending_remove": "false", "lifecycle": "test-create-1"},
		},
		"CONFIG_DB": config,
		"NATIVE":    {"BUFFER_CONSUMER": {"orchagent": "fed521d9700df9b79a22696d5b50f2308e1e7cf1bfccda59b458e7f59c7d2939", "buffermgrd": "682a6b8bbe3b2b0ed132ba26eaad7c2b0992ef68866542336fc8083b698398bb"}},
		"APPL_DB": {
			"BUFFER_POOL_TABLE:PORT3_INGRESS_POOL":       maps.Clone(config["BUFFER_POOL|PORT3_INGRESS_POOL"]),
			"BUFFER_PROFILE_TABLE:PORT3_INGRESS_PROFILE": maps.Clone(config["BUFFER_PROFILE|PORT3_INGRESS_PROFILE"]),
			"BUFFER_PG_TABLE:Ethernet11:7":               {"profile": "PORT3_INGRESS_PROFILE"},
		},
		"COUNTERS_DB": {
			"COUNTERS_BUFFER_POOL_NAME_MAP": {"PORT3_INGRESS_POOL": bufferPoolOID},
			"COUNTERS_PORT_NAME_MAP":        {"Ethernet11": bufferPortOID},
			"COUNTERS_PG_NAME_MAP":          {"Ethernet11:7": bufferPGOID},
			"COUNTERS_PG_INDEX_MAP":         {bufferPGOID: "7"},
			"COUNTERS_PG_PORT_MAP":          {bufferPGOID: bufferPortOID},
		},
		"ASIC_DB": {
			"VIDTORID": {bufferPortOID: "oid:0x10000003d", bufferPGOID: "oid:0x3d001a00000008", bufferPoolOID: "oid:0x1800000001", bufferProfileOID: "oid:0x1900000006"},
			"ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_POOL:" + bufferPoolOID:          {"SAI_BUFFER_POOL_ATTR_THRESHOLD_MODE": "SAI_BUFFER_POOL_THRESHOLD_MODE_DYNAMIC", "SAI_BUFFER_POOL_ATTR_SIZE": "10875072", "SAI_BUFFER_POOL_ATTR_TYPE": "SAI_BUFFER_POOL_TYPE_INGRESS", "SAI_BUFFER_POOL_ATTR_XOFF_SIZE": "4194112"},
			"ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_PROFILE:" + bufferProfileOID:    {"SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE": "SAI_BUFFER_PROFILE_THRESHOLD_MODE_DYNAMIC", "SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH": "3", "SAI_BUFFER_PROFILE_ATTR_POOL_ID": bufferPoolOID, "SAI_BUFFER_PROFILE_ATTR_RESERVED_BUFFER_SIZE": "0"},
			"ASIC_STATE:SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP:" + bufferPGOID: {"NULL": "NULL", "SAI_INGRESS_PRIORITY_GROUP_ATTR_BUFFER_PROFILE": bufferProfileOID},
		},
	}}
}

// Composite unit fixture: captured native leaf TC-to-PG attributes and real
// per-port PG topology, alongside the core buffer fixture.
func bufferQoSNativeFixture() *qosFakeRead {
	r := bufferNativeFixture()
	r.db["TEST_CONSUMER_OBJECTS"]["TC_TO_PRIORITY_GROUP_MAP|PROVISIONING_LOSSY"] = map[string]string{"oid": "oid:0x140000000006ee", "pending_remove": "false", "lifecycle": "test-create-1"}
	fields := map[string]string{}
	entries := []any{}
	for n := uint64(0); n < 8; n++ {
		fields[qosUint(n)] = "0"
		entries = append(entries, map[string]any{"key": map[string]any{"tc": n}, "value": map[string]any{"pg": 0}})
	}
	raw, _ := json.Marshal(map[string]any{"count": 8, "list": entries})
	r.db["CONFIG_DB"]["TC_TO_PRIORITY_GROUP_MAP|PROVISIONING_LOSSY"] = fields
	r.db["CONFIG_DB"]["PORT_QOS_MAP|Ethernet11"] = map[string]string{"tc_to_pg_map": "PROVISIONING_LOSSY"}
	r.db["STATE_DB"] = vlanChangeDB{"SWITCH_CAPABILITY|switch": {"SWITCH|NUMBER_OF_TRAFFIC_CLASSES": "10"}}
	r.db["COUNTERS_DB"]["COUNTERS_PG_NAME_MAP"]["Ethernet11:0"] = "oid:0x1a0000000006a3"
	r.db["COUNTERS_DB"]["COUNTERS_PG_INDEX_MAP"]["oid:0x1a0000000006a3"] = "0"
	r.db["COUNTERS_DB"]["COUNTERS_PG_PORT_MAP"]["oid:0x1a0000000006a3"] = bufferPortOID
	r.db["ASIC_DB"]["VIDTORID"]["oid:0x1a0000000006a3"] = "oid:0x3d001a00000001"
	r.db["ASIC_DB"]["VIDTORID"]["oid:0x140000000006ee"] = "oid:0x1400000001"
	r.db["ASIC_DB"]["ASIC_STATE:SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP:oid:0x1a0000000006a3"] = map[string]string{"NULL": "NULL"}
	r.db["ASIC_DB"]["ASIC_STATE:SAI_OBJECT_TYPE_PORT:"+bufferPortOID] = map[string]string{"SAI_PORT_ATTR_QOS_TC_TO_PRIORITY_GROUP_MAP": "oid:0x140000000006ee"}
	r.db["ASIC_DB"]["ASIC_STATE:SAI_OBJECT_TYPE_QOS_MAP:oid:0x140000000006ee"] = map[string]string{"SAI_QOS_MAP_ATTR_TYPE": "SAI_QOS_MAP_TYPE_TC_TO_PRIORITY_GROUP", "SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST": string(raw)}
	return r
}

func TestNetworkBufferNativeTCMapAndBinding(t *testing.T) {
	for _, key := range []string{"TC_TO_PRIORITY_GROUP_MAP|PROVISIONING_LOSSY", "PORT_QOS_MAP|Ethernet11"} {
		t.Run(key, func(t *testing.T) {
			r := bufferQoSNativeFixture()
			desired := vlanChangeDB{key: maps.Clone(r.db["CONFIG_DB"][key])}
			p, err := bufferDiscover(t.Context(), r, desired)
			if err != nil {
				t.Fatal(err)
			}
			if err := bufferVerify(t.Context(), r, p, false); err != nil {
				t.Fatal(err)
			}
			delete(r.db["COUNTERS_DB"]["COUNTERS_PG_NAME_MAP"], "Ethernet11:0")
			if _, err := bufferDiscover(t.Context(), r, desired); err == nil {
				t.Fatal("unproven PG output accepted")
			}
		})
	}
}

func TestNetworkBufferNativeAdoption(t *testing.T) {
	for _, key := range []string{"BUFFER_POOL|PORT3_INGRESS_POOL", "BUFFER_PROFILE|PORT3_INGRESS_PROFILE", "BUFFER_PG|Ethernet11|7"} {
		t.Run(key, func(t *testing.T) {
			read := bufferNativeFixture()
			desired := vlanChangeDB{key: maps.Clone(read.db["CONFIG_DB"][key])}
			proof, err := bufferDiscover(t.Context(), read, desired)
			if err != nil {
				t.Fatal(err)
			}
			if err := proof.validate(desired); err != nil {
				t.Fatal(err)
			}
			if err := bufferVerify(t.Context(), read, proof, false); err != nil {
				t.Fatal(err)
			}
			// Restoring an adopted value is permitted without accepting a new spec.
			for field := range desired[key] {
				read.db["CONFIG_DB"][key][field] = "drift"
				break
			}
			if err := bufferVerify(t.Context(), read, proof, false); err == nil {
				t.Fatal("drift reported as applied")
			}
			if err := bufferVerify(t.Context(), read, proof, true); err != nil {
				t.Fatalf("recorded target repair blocked: %v", err)
			}
			read.db["ASIC_DB"]["VIDTORID"][bufferPoolOID] = "oid:0x999"
			if err := bufferVerify(t.Context(), read, proof, true); err == nil {
				t.Fatal("changed native identity authorized repair")
			}
		})
	}
}

func TestNetworkBufferNativeRequiresCausalPath(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*qosFakeRead)
	}{
		{"missing native consumer", func(r *qosFakeRead) { delete(r.db, "NATIVE") }},
		{"no pool name map", func(r *qosFakeRead) { delete(r.db["COUNTERS_DB"], "COUNTERS_BUFFER_POOL_NAME_MAP") }},
		{"wrong PG index", func(r *qosFakeRead) { r.db["COUNTERS_DB"]["COUNTERS_PG_INDEX_MAP"][bufferPGOID] = "6" }},
		{"wrong PG port", func(r *qosFakeRead) { r.db["COUNTERS_DB"]["COUNTERS_PG_PORT_MAP"][bufferPGOID] = "oid:0x999" }},
		{"untranslated profile", func(r *qosFakeRead) { delete(r.db["ASIC_DB"]["VIDTORID"], bufferProfileOID) }},
		{"equal unbound profile is insufficient", func(r *qosFakeRead) {
			delete(r.db["ASIC_DB"]["ASIC_STATE:SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP:"+bufferPGOID], "SAI_INGRESS_PRIORITY_GROUP_ATTR_BUFFER_PROFILE")
		}},
		{"wrong profile pool", func(r *qosFakeRead) {
			r.db["ASIC_DB"]["ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_PROFILE:"+bufferProfileOID]["SAI_BUFFER_PROFILE_ATTR_POOL_ID"] = "oid:0x999"
		}},
		{"wrong native value", func(r *qosFakeRead) {
			r.db["ASIC_DB"]["ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_PROFILE:"+bufferProfileOID]["SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH"] = "2"
		}},
		{"dynamic buffer manager", func(r *qosFakeRead) { r.db["CONFIG_DB"]["DEVICE_METADATA|localhost"]["buffer_model"] = "dynamic" }},
		{"APPL read error", func(r *qosFakeRead) { r.errDB = "APPL_DB" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := bufferNativeFixture()
			desired := vlanChangeDB{"BUFFER_PG|Ethernet11|7": {"profile": "PORT3_INGRESS_PROFILE"}}
			tc.mutate(r)
			if _, err := bufferDiscover(t.Context(), r, desired); err == nil {
				t.Fatal("unqualified adoption allowed")
			}
		})
	}
}

func TestNetworkBufferNativeRepairKeepsObjectIdentity(t *testing.T) {
	r := bufferNativeFixture()
	key := "BUFFER_PG|Ethernet11|7"
	p, err := bufferDiscover(t.Context(), r, vlanChangeDB{key: maps.Clone(r.db["CONFIG_DB"][key])})
	if err != nil {
		t.Fatal(err)
	}
	native := "ASIC_STATE:SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP:" + bufferPGOID
	r.db["ASIC_DB"][native]["SAI_INGRESS_PRIORITY_GROUP_ATTR_BUFFER_PROFILE"] = "oid:0x999"
	if err := bufferVerify(t.Context(), r, p, false); err == nil {
		t.Fatal("native profile drift reported ready")
	}
	if err := bufferVerify(t.Context(), r, p, true); err != nil {
		t.Fatal("same-identity repair rejected", err)
	}
	delete(r.db["ASIC_DB"], native)
	if err := bufferVerify(t.Context(), r, p, true); err == nil {
		t.Fatal("missing native object authorized recreation")
	}
}

func TestNetworkBufferCapturedGraphsAreNotConsumerAcknowledgements(t *testing.T) {
	for _, host := range []string{"core-01", "leaf-03", "leaf-05"} {
		t.Run(host, func(t *testing.T) {
			raw, err := os.ReadFile("testdata/buffer-ownership/native/" + host + ".json")
			if err != nil {
				t.Fatal(err)
			}
			r := &qosFakeRead{}
			if err := json.Unmarshal(raw, &r.db); err != nil {
				t.Fatal(err)
			}
			count := 0
			for key, fields := range r.db["CONFIG_DB"] {
				if !strings.HasPrefix(key, "BUFFER_") && !strings.HasPrefix(key, "PORT_QOS_MAP|") && !strings.HasPrefix(key, "TC_TO_PRIORITY_GROUP_MAP|") {
					continue
				}
				t.Run(key, func(t *testing.T) {
					// Captures lack authoritative consumer-private name/OID and
					// deletion lifecycle state. Never certify them as RuntimeReady.
					if _, err := bufferDiscover(t.Context(), r, vlanChangeDB{key: maps.Clone(fields)}); err == nil {
						t.Fatal("captured graph falsely certified without independent producer state")
					}
				})
				count++
			}
			if count < 3 {
				t.Fatal("capture omitted buffer resources")
			}
		})
	}
}
