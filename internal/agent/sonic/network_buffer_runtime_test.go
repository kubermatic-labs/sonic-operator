// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNetworkBufferRuntimeDoesNotInferActivation(t *testing.T) {
	desired := vlanChangeDB{"BUFFER_PG|Ethernet11|7": {"profile": "PORT3_INGRESS_PROFILE"}}
	read := &qosFakeRead{db: map[string]vlanChangeDB{"APPL_DB": {"BUFFER_PG_TABLE:Ethernet11:7": {"profile": "PORT3_INGRESS_PROFILE"}}}}
	ok, raw, err := bufferObserve(t.Context(), read, desired)
	var proof map[string]any
	if err == nil || json.Unmarshal(raw, &proof) != nil || ok || !strings.Contains(string(raw), "not qualified") {
		t.Fatalf("ok=%v raw=%s err=%v", ok, raw, err)
	}
	read.errDB = "APPL_DB"
	if _, _, err := bufferObserve(t.Context(), read, desired); err == nil {
		t.Fatal("native probe error swallowed")
	}
}

func TestNetworkBufferTCMapCannotBypassNativeCapability(t *testing.T) {
	caps := map[string]string{"SWITCH|NUMBER_OF_TRAFFIC_CLASSES": "8", "SWITCH|NUMBER_OF_UNICAST_QUEUES": "8"}
	if err := qosCheckMapBounds("TC_TO_PRIORITY_GROUP_MAP", map[string]string{"7": "7"}, caps); err == nil {
		t.Fatal("queue count was accepted as priority-group capability")
	}
	for _, fields := range []map[string]string{{"16": "0"}, {"0": "8"}, {"00": "0"}} {
		if err := qosValidateMap("TC_TO_PRIORITY_GROUP_MAP", fields); err == nil {
			t.Fatal("invalid TC-to-PG map accepted")
		}
	}
}
