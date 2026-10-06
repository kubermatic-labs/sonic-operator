// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Only typed desired fields are compared; raw saved configuration never enters
// a journal, status or error. Empty saved objects are native NULL placeholders.
func networkSavedFields(data []byte, desired vlanChangeDB) (bool, error) {
	var saved map[string]map[string]map[string]json.RawMessage
	if len(data) > 4<<20 || mlagJSON(data, &saved, false) != nil || saved == nil {
		return false, fmt.Errorf("invalid saved CONFIG_DB JSON")
	}
	for key, fields := range desired {
		table, name, ok := strings.Cut(key, "|")
		if !ok {
			return false, fmt.Errorf("invalid persistence target")
		}
		row, exists := saved[table][name]
		if !exists {
			return false, nil
		}
		if table == "LOOPBACK_INTERFACE" && !strings.Contains(name, "|") {
			if _, exists := row["vnet_name"]; exists {
				return false, nil
			}
			bound := ""
			if raw, exists := row["vrf_name"]; exists && json.Unmarshal(raw, &bound) != nil {
				return false, fmt.Errorf("invalid saved loopback binding")
			}
			if bound != fields["vrf_name"] {
				return false, nil
			}
		}
		for field, value := range fields {
			raw, exists := row[field]
			if !exists && field == "NULL" && value == "NULL" {
				continue
			}
			var actual string
			if !exists || json.Unmarshal(raw, &actual) != nil || actual != value {
				return false, nil
			}
		}
	}
	return true, nil
}

func networkFieldPersistence(desired vlanChangeDB) func(context.Context, *SonicAgent) (bool, error) {
	return func(ctx context.Context, _ *SonicAgent) (bool, error) {
		data, err := lagL3Run(ctx, "cat", "/etc/sonic/config_db.json")
		if err != nil {
			return false, fmt.Errorf("saved CONFIG_DB read failed")
		}
		return networkSavedFields(data, desired)
	}
}
