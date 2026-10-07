// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Every non-TC-to-PG binding replayed/removed by the inspected QosOrch port-row
// consumer must be unset. An absent SAI map attribute has the null-OID default.
var bufferOtherPortMaps = []string{
	"SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP", "SAI_PORT_ATTR_QOS_MPLS_EXP_TO_TC_MAP",
	"SAI_PORT_ATTR_QOS_DOT1P_TO_TC_MAP", "SAI_PORT_ATTR_QOS_TC_TO_QUEUE_MAP",
	"SAI_PORT_ATTR_QOS_TC_AND_COLOR_TO_DOT1P_MAP", "SAI_PORT_ATTR_QOS_TC_AND_COLOR_TO_DSCP_MAP",
	"SAI_PORT_ATTR_QOS_PFC_PRIORITY_TO_PRIORITY_GROUP_MAP", "SAI_PORT_ATTR_QOS_PFC_PRIORITY_TO_QUEUE_MAP",
	"SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID", "SAI_PORT_ATTR_QOS_DSCP_TO_FORWARDING_CLASS_MAP",
	"SAI_PORT_ATTR_QOS_MPLS_EXP_TO_FORWARDING_CLASS_MAP",
}

const bufferMapListAttr = "SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST"

func bufferNormalizeChecked(key string, row map[string]string) (map[string]string, error) {
	out := bufferNormalize(key, row)
	if strings.HasPrefix(key, "ASIC_STATE:SAI_OBJECT_TYPE_QOS_MAP:") {
		entries, err := qosMapEntries(qosMapKinds["TCToPriorityGroup"], row)
		if err != nil {
			return nil, err
		}
		if err := qosValidateMap("TC_TO_PRIORITY_GROUP_MAP", entries); err != nil {
			return nil, err
		}
		raw, _ := json.Marshal(entries)
		out[bufferMapListAttr] = string(raw)
	}
	return out, nil
}

func bufferUnownedTCEntries(canonical string, desired vlanChangeDB) (string, error) {
	var entries map[string]string
	if err := json.Unmarshal([]byte(canonical), &entries); err != nil || entries == nil {
		return "", fmt.Errorf("invalid canonical TC-to-PG evidence")
	}
	for key, fields := range desired {
		if strings.HasPrefix(key, "TC_TO_PRIORITY_GROUP_MAP|") {
			for from := range fields {
				delete(entries, from)
			}
		}
	}
	raw, _ := json.Marshal(entries)
	return string(raw), nil
}
