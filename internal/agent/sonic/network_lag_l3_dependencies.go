// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

var lagL3PolicyName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
var lagL3LoopbackName = regexp.MustCompile(`^Loopback(0|[1-9][0-9]*)$`)

// Exact installed sonic-routing-policy-sets/sonic-dhcpv4-relay/sonic-dhcpv6-relay
// grammars. Prefix lists cannot refer to ports; relay source_interface can. The
// caller still checks references after this function validates the typed fields.
func lagL3CrossFeatureGrammar(db vlanChangeDB, key string, fields map[string]string) error {
	parts := strings.Split(key, "|")
	if len(parts) < 2 || len(fields) == 0 {
		return fmt.Errorf("malformed cross-feature dependency")
	}
	table, name := parts[0], parts[1]
	bad := func() error { return fmt.Errorf("unsupported or malformed %s dependency", table) }
	switch table {
	case "PREFIX_SET":
		if len(parts) != 2 || !lagL3PolicyName.MatchString(name) || len(fields) != 1 || (fields["mode"] != "IPv4" && fields["mode"] != "IPv6") {
			return bad()
		}
	case "PREFIX":
		if (len(parts) != 4 && len(parts) != 5) || !lagL3PolicyName.MatchString(name) || len(fields) != 1 || (fields["action"] != "permit" && fields["action"] != "deny") {
			return bad()
		}
		parent := db["PREFIX_SET|"+name]
		if err := lagL3CrossFeatureGrammar(db, "PREFIX_SET|"+name, parent); err != nil {
			return err
		}
		if len(parts) == 5 {
			n, err := strconv.ParseUint(parts[2], 10, 32)
			if err != nil || n == 0 || strconv.FormatUint(n, 10) != parts[2] {
				return bad()
			}
			// sonic-routing-policy-sets requires sequence uniqueness within a
			// named list, even when prefix and mask-range key components differ.
			for other := range db {
				if other != key && strings.HasPrefix(other, "PREFIX|"+name+"|"+parts[2]+"|") {
					return bad()
				}
			}
		}
		p, err := netip.ParsePrefix(parts[len(parts)-2])
		if err != nil || p.Addr().Is4In6() || p != p.Masked() || p.String() != parts[len(parts)-2] || p.Addr().Is4() != (parent["mode"] == "IPv4") {
			return bad()
		}
		mask := parts[len(parts)-1]
		if mask != "exact" {
			lo, hi, ok := strings.Cut(mask, "..")
			a, e1 := strconv.Atoi(lo)
			b, e2 := strconv.Atoi(hi)
			if !ok || e1 != nil || e2 != nil || a < p.Bits() || b < a || b > p.Addr().BitLen() || strconv.Itoa(a) != lo || strconv.Itoa(b) != hi {
				return bad()
			}
		}
	case "DHCPV4_RELAY", "DHCP_RELAY":
		if len(parts) != 2 || lagL3InterfaceTable(name) != "VLAN_INTERFACE" || db["VLAN|"+name]["vlanid"] != strings.TrimPrefix(name, "Vlan") {
			return bad()
		}
		serverField := "dhcpv4_servers@"
		if table == "DHCP_RELAY" {
			serverField = "dhcpv6_servers@"
		}
		if fields[serverField] == "" {
			return bad()
		}
		seen := map[netip.Addr]bool{}
		for _, value := range strings.Split(fields[serverField], ",") {
			ip, err := netip.ParseAddr(value)
			if err != nil || ip.Is4In6() || ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.Is4() != (table == "DHCPV4_RELAY") || seen[ip] {
				return bad()
			}
			seen[ip] = true
		}
		for field, value := range fields {
			if field == serverField {
				continue
			}
			if table == "DHCP_RELAY" {
				if (field != "rfc6939_support" && field != "interface_id") || (value != "true" && value != "false") {
					return bad()
				}
				continue
			}
			switch field {
			case "source_interface":
				if lagL3LoopbackName.MatchString(value) && len(value) <= 15 {
					if db["LOOPBACK_INTERFACE|"+value] == nil {
						return bad()
					}
				} else if err := lagL3InterfaceExists(db, value); err != nil {
					return bad()
				}
			case "server_vrf":
				if len(value) > 15 || !lagL3VRFName.MatchString(value) || db["VRF|"+value] == nil || fields["server_id_override"] != "enable" || fields["link_selection"] != "enable" || fields["vrf_selection"] != "enable" {
					return bad()
				}
			case "link_selection", "vrf_selection", "server_id_override":
				if value != "enable" && value != "disable" {
					return bad()
				}
				if field == "link_selection" && value == "enable" && fields["source_interface"] == "" {
					return bad()
				}
			case "agent_relay_mode":
				if value != "forward_and_append" && value != "forward_and_replace" && value != "forward_untouched" && value != "discard" {
					return bad()
				}
			case "max_hop_count":
				n, err := strconv.ParseUint(value, 10, 8)
				if err != nil || n < 1 || n > 16 {
					return bad()
				}
			default:
				return bad()
			}
		}
	default:
		return bad()
	}
	return nil
}
