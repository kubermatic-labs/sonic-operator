// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"fmt"
	"reflect"
	"strings"
)

// Native regeneration also re-emits daemon identity, logging and credentials.
// They are not BGP-owned fields: refuse to overwrite a runtime customization
// that differs from the actual generating inputs. Opaque values stay in memory
// and are never returned, logged, or included in the ownership journal.
func traditionalPreflightPolicy(configs map[string]string, running string, s routingBGPSpec) error {
	matched, err := traditionalPolicy(configs, s, false)
	if err != nil || !matched {
		return fmt.Errorf("native candidate does not exactly reproduce declared traditional policy")
	}
	if _, err := traditionalPolicy(map[string]string{"running": running}, s, true); err != nil {
		return err
	}
	want, valid := traditionalUnmanagedFields(configs)
	actual, currentValid := traditionalUnmanagedFields(map[string]string{"running": running})
	if !valid || !currentValid || !reflect.DeepEqual(want, actual) {
		return fmt.Errorf("native regeneration would change unmanaged daemon settings")
	}
	return nil
}

func traditionalUnmanagedFields(configs map[string]string) (map[string]string, bool) {
	values := map[string]string{}
	for _, config := range configs {
		for _, raw := range strings.Split(config, "\n") {
			line, key := strings.TrimSpace(raw), ""
			for _, prefix := range []string{"hostname ", "password ", "enable password ", "log syslog ", "log facility "} {
				if strings.HasPrefix(line, prefix) {
					key = prefix
					break
				}
			}
			if line == "agentx" {
				key = "agentx"
			}
			if key == "" {
				continue
			}
			if previous, exists := values[key]; exists && previous != line {
				return nil, false
			}
			values[key] = line
		}
	}
	return values, true
}

func traditionalPreservation(ctx context.Context, s routingBGPSpec) error {
	configs, err := traditionalRender(ctx, "candidate", s.LocalASN)
	if err != nil {
		return err
	}
	running, err := runRoutingRead(ctx, routingBGPConfig)
	if err != nil {
		return err
	}
	return traditionalPreflightPolicy(configs, string(running), s)
}
