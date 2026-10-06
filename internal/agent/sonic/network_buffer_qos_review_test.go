// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"encoding/json"
	"maps"
	"slices"
	"testing"
)

const bufferTestMapKey = "ASIC_STATE:SAI_OBJECT_TYPE_QOS_MAP:oid:0x140000000006ee"
const bufferTestMapAttr = "SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST"

func rewriteBufferTestMap(t *testing.T, r *qosFakeRead, change func([]map[string]map[string]any)) {
	t.Helper()
	var value struct {
		Count int                         `json:"count"`
		List  []map[string]map[string]any `json:"list"`
	}
	if err := json.Unmarshal([]byte(r.db["ASIC_DB"][bufferTestMapKey][bufferTestMapAttr]), &value); err != nil {
		t.Fatal(err)
	}
	change(value.List)
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	r.db["ASIC_DB"][bufferTestMapKey][bufferTestMapAttr] = string(raw)
}

func TestNetworkBufferTCMapSemanticReadback(t *testing.T) {
	r := bufferQoSNativeFixture()
	key := "TC_TO_PRIORITY_GROUP_MAP|PROVISIONING_LOSSY"
	proof, err := bufferDiscover(t.Context(), r, vlanChangeDB{key: maps.Clone(r.db["CONFIG_DB"][key])})
	if err != nil {
		t.Fatal(err)
	}
	rewriteBufferTestMap(t, r, func(entries []map[string]map[string]any) { slices.Reverse(entries) })
	if err := bufferVerify(t.Context(), r, proof, false); err != nil {
		t.Fatalf("equivalent serialization is drift: %v", err)
	}
	rewriteBufferTestMap(t, r, func(entries []map[string]map[string]any) { entries[0]["value"]["pg"] = 1 })
	if err := bufferVerify(t.Context(), r, proof, false); err == nil {
		t.Fatal("changed TC mapping reported converged")
	}
}

func TestNetworkBufferPartialMapFencesUnownedEntries(t *testing.T) {
	r := bufferQoSNativeFixture()
	key := "TC_TO_PRIORITY_GROUP_MAP|PROVISIONING_LOSSY"
	proof, err := bufferDiscover(t.Context(), r, vlanChangeDB{key: {"0": "0"}})
	if err != nil {
		t.Fatal(err)
	}
	rewriteBufferTestMap(t, r, func(entries []map[string]map[string]any) { entries[7]["value"]["pg"] = 1 })
	if err := bufferVerify(t.Context(), r, proof, true); err == nil {
		t.Fatal("unowned TC7 may be overwritten by TC0 repair")
	}
	r = bufferQoSNativeFixture()
	rewriteBufferTestMap(t, r, func(entries []map[string]map[string]any) { entries[0]["value"]["pg"] = 1 })
	if err := bufferVerify(t.Context(), r, proof, true); err != nil {
		t.Fatalf("owned TC0 restoration rejected: %v", err)
	}
}

func TestNetworkBufferPortMapFencesWholeRowEffects(t *testing.T) {
	key := "PORT_QOS_MAP|Ethernet11"
	t.Run("extra configured map", func(t *testing.T) {
		r := bufferQoSNativeFixture()
		r.db["CONFIG_DB"][key]["dscp_to_tc_map"] = "other"
		if _, err := bufferDiscover(t.Context(), r, vlanChangeDB{key: {"tc_to_pg_map": "PROVISIONING_LOSSY"}}); err == nil {
			t.Fatal("unqualified full-row map side effects accepted")
		}
	})
	t.Run("unowned native map drift", func(t *testing.T) {
		r := bufferQoSNativeFixture()
		proof, err := bufferDiscover(t.Context(), r, vlanChangeDB{key: maps.Clone(r.db["CONFIG_DB"][key])})
		if err != nil {
			t.Fatal(err)
		}
		r.db["ASIC_DB"]["ASIC_STATE:SAI_OBJECT_TYPE_PORT:"+bufferPortOID]["SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP"] = "oid:0x999"
		if err := bufferVerify(t.Context(), r, proof, true); err == nil {
			t.Fatal("tc-to-PG repair may reset unowned native DSCP map")
		}
	})
}
