// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"encoding/json"
	"fmt"
	"strings"
)

func frrMigrationValidateCandidate(data []byte, hostname, mode string) error {
	if mode == "Unified" {
		return frrMigrationEmptyConfig(data, hostname)
	}
	var files map[string]string
	if json.Unmarshal(data, &files) != nil || len(files) != 3 || hostname == "" {
		return fmt.Errorf("invalid separated candidate files")
	}
	// Stock SONiC202511 templates inspected read-only on leaf-03. Each
	// daemon has its own exact defaults: zebra/staticd do not emit agentx.
	for _, name := range []string{"bgpd.conf", "zebra.conf", "staticd.conf"} {
		config, ok := files[name]
		if !ok {
			return fmt.Errorf("missing separated candidate")
		}
		seen := map[string]bool{}
		for _, line := range strings.Split(config, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "!") {
				continue
			}
			allowed := line == "hostname "+hostname
			switch line {
			case "password zebra", "enable password zebra", "log syslog informational", "log facility local4":
				allowed = true
			case "agentx":
				allowed = name == "bgpd.conf"
			case "zebra nexthop kernel enable", "no fpm use-next-hop-groups", "fpm address 127.0.0.1", "zebra nexthop-group keep 1", "ip nht resolve-via-default", "ipv6 nht resolve-via-default":
				allowed = name == "zebra.conf"
			}
			if !allowed || seen[line] {
				return fmt.Errorf("unsupported separated candidate directive")
			}
			seen[line] = true
		}
		required := []string{"hostname " + hostname, "password zebra", "enable password zebra", "log syslog informational", "log facility local4"}
		if name == "bgpd.conf" {
			required = append(required, "agentx")
		}
		if name == "zebra.conf" {
			required = append(required, "zebra nexthop kernel enable", "no fpm use-next-hop-groups", "fpm address 127.0.0.1", "zebra nexthop-group keep 1", "ip nht resolve-via-default", "ipv6 nht resolve-via-default")
		}
		for _, line := range required {
			if !seen[line] {
				return fmt.Errorf("incomplete separated candidate")
			}
		}
	}
	return nil
}
