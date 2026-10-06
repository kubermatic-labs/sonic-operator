// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"maps"
	"strings"
	"testing"
)

func TestNetworkBufferIndependentNameIdentity(t *testing.T) {
	t.Run("equal differently named profile", func(t *testing.T) {
		r := bufferNativeFixture()
		other := "oid:0x1900000000999"
		r.db["CONFIG_DB"]["BUFFER_PROFILE|B"] = maps.Clone(r.db["CONFIG_DB"]["BUFFER_PROFILE|PORT3_INGRESS_PROFILE"])
		r.db["APPL_DB"]["BUFFER_PROFILE_TABLE:B"] = maps.Clone(r.db["CONFIG_DB"]["BUFFER_PROFILE|B"])
		r.db["TEST_CONSUMER_OBJECTS"]["BUFFER_PROFILE|B"] = map[string]string{"oid": other, "pending_remove": "false", "lifecycle": "test-create-b"}
		r.db["ASIC_DB"]["ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_PROFILE:"+other] = maps.Clone(r.db["ASIC_DB"]["ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_PROFILE:"+bufferProfileOID])
		r.db["ASIC_DB"]["VIDTORID"][other] = "oid:0x19000999"
		r.db["ASIC_DB"]["ASIC_STATE:SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP:"+bufferPGOID]["SAI_INGRESS_PRIORITY_GROUP_ATTR_BUFFER_PROFILE"] = other
		if _, err := bufferDiscover(t.Context(), r, vlanChangeDB{"BUFFER_PG|Ethernet11|7": {"profile": "PORT3_INGRESS_PROFILE"}}); err == nil {
			t.Fatal("bound equal-valued B was accepted as named profile A")
		}
		// An earlier valid selector must not hide a later wrong-name association.
		pg6 := "oid:0x1a0000000006a9"
		r.db["CONFIG_DB"]["BUFFER_PG|Ethernet11|6"] = map[string]string{"profile": "PORT3_INGRESS_PROFILE"}
		r.db["APPL_DB"]["BUFFER_PG_TABLE:Ethernet11:6"] = map[string]string{"profile": "PORT3_INGRESS_PROFILE"}
		r.db["COUNTERS_DB"]["COUNTERS_PG_NAME_MAP"]["Ethernet11:6"] = pg6
		r.db["COUNTERS_DB"]["COUNTERS_PG_INDEX_MAP"][pg6] = "6"
		r.db["COUNTERS_DB"]["COUNTERS_PG_PORT_MAP"][pg6] = bufferPortOID
		r.db["ASIC_DB"]["VIDTORID"][pg6] = "oid:0x3d001a00000007"
		r.db["ASIC_DB"]["ASIC_STATE:SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP:"+pg6] = map[string]string{"SAI_INGRESS_PRIORITY_GROUP_ATTR_BUFFER_PROFILE": bufferProfileOID}
		profileKey := "BUFFER_PROFILE|PORT3_INGRESS_PROFILE"
		if _, err := bufferDiscover(t.Context(), r, vlanChangeDB{profileKey: maps.Clone(r.db["CONFIG_DB"][profileKey])}); err == nil {
			t.Fatal("profile verified only its first binding")
		}
	})
	t.Run("equal differently named TC map", func(t *testing.T) {
		r := bufferQoSNativeFixture()
		other := "oid:0x1400000000999"
		key := "TC_TO_PRIORITY_GROUP_MAP|PROVISIONING_LOSSY"
		r.db["CONFIG_DB"]["TC_TO_PRIORITY_GROUP_MAP|B"] = maps.Clone(r.db["CONFIG_DB"][key])
		r.db["TEST_CONSUMER_OBJECTS"]["TC_TO_PRIORITY_GROUP_MAP|B"] = map[string]string{"oid": other, "pending_remove": "false", "lifecycle": "test-create-b"}
		r.db["ASIC_DB"]["ASIC_STATE:SAI_OBJECT_TYPE_QOS_MAP:"+other] = maps.Clone(r.db["ASIC_DB"][bufferTestMapKey])
		r.db["ASIC_DB"]["VIDTORID"][other] = "oid:0x14000999"
		r.db["ASIC_DB"]["ASIC_STATE:SAI_OBJECT_TYPE_PORT:"+bufferPortOID]["SAI_PORT_ATTR_QOS_TC_TO_PRIORITY_GROUP_MAP"] = other
		if _, err := bufferDiscover(t.Context(), r, vlanChangeDB{key: maps.Clone(r.db["CONFIG_DB"][key])}); err == nil {
			t.Fatal("bound equal-valued B was accepted as named TC map A")
		}
	})
}

func TestNetworkBufferDeletedOwnedFieldsFailClosed(t *testing.T) {
	r := bufferNativeFixture()
	key := "BUFFER_PROFILE|PORT3_INGRESS_PROFILE"
	proof, err := bufferDiscover(t.Context(), r, vlanChangeDB{key: maps.Clone(r.db["CONFIG_DB"][key])})
	if err != nil {
		t.Fatal(err)
	}
	delete(r.db["CONFIG_DB"], key)
	if err := bufferRepairPreflight(t.Context(), r, proof); err == nil {
		t.Fatal("unqualified DEL-to-SET transition permitted")
	}
}

func TestNetworkBufferProductionReaderDoesNotInventAcknowledgement(t *testing.T) {
	_, err := (qosRedisRead{}).bufferObject(context.Background(), "BUFFER_PROFILE", "A")
	if err == nil || !strings.Contains(err.Error(), "producer instrumentation") {
		t.Fatalf("production state reader: %v", err)
	}
}

func TestNetworkBufferConsumerLifecycleRequired(t *testing.T) {
	for _, key := range []string{"BUFFER_POOL|PORT3_INGRESS_POOL", "BUFFER_PROFILE|PORT3_INGRESS_PROFILE", "TC_TO_PRIORITY_GROUP_MAP|PROVISIONING_LOSSY"} {
		t.Run(key, func(t *testing.T) {
			r := bufferQoSNativeFixture()
			desired := vlanChangeDB{key: maps.Clone(r.db["CONFIG_DB"][key])}
			proof, err := bufferDiscover(t.Context(), r, desired)
			if err != nil {
				t.Fatal(err)
			}
			// Model native consumption of DEL: referenced object remains, removal is
			// pending. A later SET can restore CONFIG/APPL while this flag stays true.
			r.db["TEST_CONSUMER_OBJECTS"][key]["pending_remove"] = "true"
			if err := bufferVerify(t.Context(), r, proof, false); err == nil {
				t.Fatal("consumed DEL then SET falsely reported ready")
			}
			if err := bufferVerify(t.Context(), r, proof, true); err == nil {
				t.Fatal("pending removal authorized repair SET")
			}
			r.db["TEST_CONSUMER_OBJECTS"][key]["pending_remove"] = "false"
			r.db["TEST_CONSUMER_OBJECTS"][key]["lifecycle"] = "test-consumed-del-2"
			if err := bufferVerify(t.Context(), r, proof, true); err == nil {
				t.Fatal("changed consumer lifecycle reused old proof")
			}
		})
	}
}

func TestNetworkBufferWithoutProducerStateFailsClosed(t *testing.T) {
	r := bufferNativeFixture()
	delete(r.db, "TEST_CONSUMER_OBJECTS")
	if _, err := bufferDiscover(t.Context(), r, vlanChangeDB{"BUFFER_PG|Ethernet11|7": {"profile": "PORT3_INGRESS_PROFILE"}}); err == nil {
		t.Fatal("consumer-private identity/lifecycle inferred from binding")
	}
}

func TestNetworkBufferConsumedPGDeletionKeepsCounterFence(t *testing.T) {
	r := bufferNativeFixture()
	key := "BUFFER_PG|Ethernet11|7"
	p, err := bufferDiscover(t.Context(), r, vlanChangeDB{key: maps.Clone(r.db["CONFIG_DB"][key])})
	if err != nil {
		t.Fatal(err)
	}
	delete(r.db["COUNTERS_DB"]["COUNTERS_PG_NAME_MAP"], "Ethernet11:7")
	delete(r.db["COUNTERS_DB"]["COUNTERS_PG_INDEX_MAP"], bufferPGOID)
	delete(r.db["COUNTERS_DB"]["COUNTERS_PG_PORT_MAP"], bufferPGOID)
	if err := bufferRepairPreflight(t.Context(), r, p); err == nil {
		t.Fatal("consumed PG deletion silently recreated counter identity")
	}
}
