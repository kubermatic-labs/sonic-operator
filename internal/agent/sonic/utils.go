// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/vishvananda/netlink"
)

func parseDeviceStatus(value string) agent.DeviceStatus {
	if value == string(agent.StatusUp) || value == string(agent.StatusDown) {
		return agent.DeviceStatus(value)
	}
	return agent.StatusUnknown
}

func ethernetNumber(name string) (int, bool) {
	if !strings.HasPrefix(name, "Ethernet") {
		return 0, false
	}
	number, err := strconv.Atoi(strings.TrimPrefix(name, "Ethernet"))
	return number, err == nil && number >= 0 && name == "Ethernet"+strconv.Itoa(number)
}

func (m *SonicAgent) getLinkByName(name string) (netlink.Link, error) {
	if m.linkByName != nil {
		return m.linkByName(name)
	}
	return netlink.LinkByName(name)
}

func GetSonicVersionInfo() (map[string]string, error) {
	info := make(map[string]string)

	content, err := os.ReadFile("/etc/sonic/sonic_version.yml")
	if err != nil {
		return nil, fmt.Errorf("failed to read sonic_version.yml: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "---") || line == "" {
			continue
		}

		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				// Remove quotes if present
				value = strings.Trim(value, `'"`)
				info[key] = value
			}
		}
	}

	return info, nil
}
