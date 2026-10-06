// SPDX-License-Identifier: Apache-2.0
package artifact

import "fmt"

func validateBootstrapPolicy(policy Policy) error {
	for hash := range policy.AgentBuilds {
		if err := ValidateAgentRelease(policy, hash); err != nil {
			return err
		}
	}
	for slot, p := range policy.Platform {
		if policy.ImageSHA256 != coreImageSHA || p == "" || p != coreDestination(slot) {
			return fmt.Errorf("unqualified remote bootstrap destination policy")
		}
	}
	consumers := map[string]RuntimeFile{
		"PlatformJSON":   {Container: "pmon", Path: "/usr/share/sonic/platform/platform.json"},
		"HWSKUJSON":      {Container: "syncd", Path: "/usr/share/sonic/hwsku/hwsku.json"},
		"PortConfig":     {Container: "syncd", Path: "/usr/share/sonic/hwsku/port_config.ini"},
		"SAIProfile":     {Container: "syncd", Path: "/usr/share/sonic/hwsku/sai.profile"},
		"BroadcomConfig": {Container: "syncd", Path: "/usr/share/sonic/hwsku/dc-flex-with-sfp.config.bcm"},
	}
	for slot, runtime := range policy.Runtime {
		expected, ok := consumers[slot]
		if !ok || policy.ImageSHA256 != coreImageSHA || runtime != expected {
			return fmt.Errorf("unqualified remote bootstrap runtime policy")
		}
	}
	return nil
}
