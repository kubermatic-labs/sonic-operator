// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"fmt"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
)

// Exact inspected FRR 10.0.1 traditional LeafRouter policy. Startup's global
// IPv4 network and implicit prefix-list sequence normalize to FRR readback.
// Unknown commands (especially neighbors/policy) block native regeneration.
// Missing/changed owned scalars are drift, not permission to drop foreign policy.
//
//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func traditionalPolicy(configs map[string]string, s routingBGPSpec, runtime bool) (bool, error) {
	expected := map[string]string{"asn": strconv.FormatUint(uint64(s.LocalASN), 10), "routerID": s.RouterID, "network": s.RouterID + "/32", "prefixList": s.RouterID + "/32", "source": s.RouterID, "route-map RM_SET_SRC permit 10": "true", "ip protocol bgp route-map RM_SET_SRC": "true"}
	bgpFlags := []string{"bgp suppress-fib-pending", "bgp log-neighbor-changes", "no bgp ebgp-requires-policy", "no bgp default ipv4-unicast", "bgp bestpath as-path multipath-relax"}
	zebraFlags := []string{"no zebra nexthop kernel enable", "fpm address 127.0.0.1", "no fpm use-next-hop-groups", "ip nht resolve-via-default", "ipv6 nht resolve-via-default"}
	for _, f := range append(bgpFlags, zebraFlags...) {
		expected[f] = "true"
	}
	if runtime {
		for _, f := range []string{"no service integrated-vtysh-config", "frr version 10.0.1", "frr defaults traditional"} {
			expected[f] = "true"
		}
	}
	actual := map[string]string{}
	bad := func() (bool, error) { return false, fmt.Errorf("unsupported or ambiguous traditional FRR policy") }
	put := func(k, v string) bool {
		if _, exists := actual[k]; exists {
			return false
		}
		actual[k] = v
		return true
	}
	for _, config := range configs {
		section, af := "", ""
		for _, raw := range strings.Split(config, "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "!") || line == "Building configuration..." || line == "Current configuration:" {
				continue
			}
			parts := strings.Fields(line)
			if line == "exit-address-family" {
				af = ""
				continue
			}
			if line == "exit" || line == "end" {
				section, af = "", ""
				continue
			}
			if strings.HasPrefix(line, "hostname ") || strings.HasPrefix(line, "password ") || strings.HasPrefix(line, "enable password ") {
				continue
			}
			switch line {
			case "log syslog informational", "log facility local4", "agentx":
				continue
			case "no service integrated-vtysh-config", "frr version 10.0.1", "frr defaults traditional":
				if runtime && !put(line, "true") {
					return bad()
				}
				continue
			}
			flag := false
			for _, f := range bgpFlags {
				if line == f {
					if section != "bgp" || af != "" || !put(f, "true") {
						return bad()
					}
					flag = true
					break
				}
			}
			if flag {
				continue
			}
			for _, f := range zebraFlags {
				if line == f {
					actual[f] = "true"
					flag = true
					break
				}
			}
			if flag {
				continue
			}
			if len(parts) == 3 && parts[0] == "router" && parts[1] == "bgp" {
				asn, err := strconv.ParseUint(parts[2], 10, 32)
				if err != nil || asn == 0 || parts[2] != strconv.FormatUint(asn, 10) || !put("asn", parts[2]) {
					return bad()
				}
				section, af = "bgp", ""
				continue
			}
			if line == "address-family ipv4" || line == "address-family ipv4 unicast" || (!runtime && line == "address-family ipv6") {
				if section != "bgp" || af != "" {
					return bad()
				}
				af = parts[1]
				continue
			}
			// The pinned startup emits maximum-paths 514; this FRR build does not
			// retain it. It is image-baseline output, not a managed BGP field.
			if !runtime && line == "maximum-paths 514" && section == "bgp" && af != "" {
				continue
			}
			if len(parts) == 3 && parts[0] == "bgp" && parts[1] == "router-id" && section == "bgp" && af == "" {
				ip, err := netip.ParseAddr(parts[2])
				if err != nil || !ip.Is4() || !put("routerID", ip.String()) {
					return bad()
				}
				continue
			}
			if len(parts) == 2 && parts[0] == "network" && section == "bgp" && (af == "ipv4" || !runtime && af == "") {
				p, err := netip.ParsePrefix(parts[1])
				if err != nil || !p.Addr().Is4() || p.Bits() != 32 || !put("network", p.String()) {
					return bad()
				}
				continue
			}
			if strings.HasPrefix(line, "ip prefix-list PL_LoopbackV4 ") {
				tail := strings.TrimPrefix(line, "ip prefix-list PL_LoopbackV4 ")
				if runtime {
					tail = strings.TrimPrefix(tail, "seq 5 ")
				}
				f := strings.Fields(tail)
				if len(f) != 2 || f[0] != "permit" {
					return bad()
				}
				p, err := netip.ParsePrefix(f[1])
				if err != nil || !p.Addr().Is4() || p.Bits() != 32 || !put("prefixList", p.String()) {
					return bad()
				}
				continue
			}
			if line == "route-map RM_SET_SRC permit 10" {
				if !put(line, "true") {
					return bad()
				}
				section, af = "setsrc", ""
				continue
			}
			if len(parts) == 3 && parts[0] == "set" && parts[1] == "src" && section == "setsrc" {
				ip, err := netip.ParseAddr(parts[2])
				if err != nil || !ip.Is4() || !put("source", ip.String()) {
					return bad()
				}
				continue
			}
			if line == "ip protocol bgp route-map RM_SET_SRC" {
				if !put(line, "true") {
					return bad()
				}
				continue
			}
			return bad()
		}
	}
	return reflect.DeepEqual(actual, expected), nil
}
