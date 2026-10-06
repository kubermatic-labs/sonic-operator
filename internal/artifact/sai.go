// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"bytes"
	"fmt"
	"strings"
)

func verifySAICommand(raw []byte) error {
	args := bytes.Split(bytes.TrimRight(raw, "\x00"), []byte{0})
	if len(args) == 0 {
		return fmt.Errorf("missing syncd command")
	}
	if string(args[0]) == "/usr/bin/dsserve" {
		args = args[1:]
	}
	if len(args) == 0 || string(args[0]) != "/usr/bin/syncd" {
		return fmt.Errorf("unqualified syncd executable")
	}
	profiles := 0
	for i, arg := range args {
		if string(arg) == "-p" {
			profiles++
			if i+1 >= len(args) || string(args[i+1]) != "/etc/sai.d/sai.profile" {
				return fmt.Errorf("syncd is not consuming the generated SAI input")
			}
		}
		if strings.HasPrefix(string(arg), "--profile") {
			return fmt.Errorf("unqualified SAI override")
		}
	}
	if profiles != 1 {
		return fmt.Errorf("ambiguous syncd profile selection")
	}
	return nil
}

func validateSAIProfile(data []byte) error {
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 || values[parts[0]] != "" {
			return fmt.Errorf("invalid qualified SAI profile")
		}
		values[parts[0]] = parts[1]
	}
	if len(values) != 2 || values["SAI_INIT_CONFIG_FILE"] != "/usr/share/sonic/hwsku/dc-flex-with-sfp.config.bcm" || values["SAI_NUM_ECMP_MEMBERS"] != "64" {
		return fmt.Errorf("SAI profile differs from qualified runtime input contract")
	}
	return nil
}
