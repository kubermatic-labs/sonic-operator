// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
)

// Layout/context is read-only qualification, not desired fields or permission
// to write lanes. The engine separately requires this live context to match the
// durable adoption record and rejects concurrent CONFIG_DB changes.
func networkPortPersistence(desired vlanChangeDB, name string, layout map[string]string) func(context.Context, *SonicAgent) (bool, error) {
	return func(ctx context.Context, _ *SonicAgent) (bool, error) {
		data, err := lagL3Run(ctx, "cat", "/etc/sonic/config_db.json")
		if err != nil {
			return false, fmt.Errorf("saved CONFIG_DB read failed")
		}
		matches, err := networkSavedFields(data, desired)
		if err != nil || !matches {
			return false, err
		}
		// Size, duplicate/null rejection and native row types were checked above.
		var saved map[string]map[string]map[string]json.RawMessage
		if json.Unmarshal(data, &saved) != nil {
			return false, fmt.Errorf("invalid saved CONFIG_DB JSON")
		}
		row := saved["PORT"][name]
		contextFields := map[string]string{}
		for field := range networkPortLayoutContext(nil) {
			if raw, exists := row[field]; exists {
				var value string
				if json.Unmarshal(raw, &value) != nil {
					return false, fmt.Errorf("invalid saved port layout field")
				}
				contextFields[field] = value
			}
		}
		return reflect.DeepEqual(layout, networkPortLayoutContext(contextFields)), nil
	}
}
