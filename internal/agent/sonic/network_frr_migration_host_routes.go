// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
)

type frrMigrationHostEvidence map[string][]netip.Prefix

// Dynamic management addresses need not appear in CONFIG_DB. Read them from
// the kernel, but only use eth0 globals and link-local addresses on known SONiC
// interfaces. Never turn this evidence into persisted configuration.
//
//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func frrMigrationHostAddresses(raw []byte, db vlanChangeDB) (frrMigrationHostEvidence, error) {
	var rows []map[string]json.RawMessage
	// Reject duplicate keys everywhere, while tolerating null in unconsumed
	// iproute2 metadata (pimreg emits link:null after unified FRR starts).
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 32 {
			return fmt.Errorf("host JSON nesting limit")
		}
		t, err := decoder.Token()
		if err != nil {
			return err
		}
		d, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		seen := map[string]bool{}
		for decoder.More() {
			if d == '{' {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				s, ok := key.(string)
				if !ok || seen[s] {
					return fmt.Errorf("duplicate host JSON key")
				}
				seen[s] = true
			}
			if err := walk(depth + 1); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	}
	if err := walk(0); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing host JSON")
	}
	if json.Unmarshal(raw, &rows) != nil || rows == nil {
		return nil, fmt.Errorf("invalid host address JSON")
	}
	result := frrMigrationHostEvidence{}
	seen := map[string]bool{}
	for _, row := range rows {
		var name string
		if json.Unmarshal(row["ifname"], &name) != nil || name == "" || seen[name] {
			return nil, fmt.Errorf("invalid host interface evidence")
		}
		seen[name] = true
		known := name == "eth0" || name == "Bridge" || name == "dummy" || name == "sr0" || db["PORT|"+name] != nil || db["VLAN|"+name] != nil || db["PORTCHANNEL|"+name] != nil
		if !known {
			continue
		}
		var checked any
		if err := mlagJSON(row["addr_info"], &checked, false); err != nil {
			return nil, err
		}
		var addresses []struct {
			Family string `json:"family"`
			Local  string `json:"local"`
			Bits   int    `json:"prefixlen"`
			Scope  string `json:"scope"`
		}
		if json.Unmarshal(row["addr_info"], &addresses) != nil {
			return nil, fmt.Errorf("invalid host address list")
		}
		for _, address := range addresses {
			a, err := netip.ParseAddr(address.Local)
			if err != nil || a.Is4In6() || a.Zone() != "" || address.Bits < 1 || address.Bits > a.BitLen() || (a.Is4() && address.Family != "inet") || (a.Is6() && address.Family != "inet6") {
				return nil, fmt.Errorf("invalid host address")
			}
			if name == "eth0" && a.IsGlobalUnicast() && address.Scope == "global" || a.Is6() && a.IsLinkLocalUnicast() && address.Bits == 64 && address.Scope == "link" {
				result[name] = append(result[name], netip.PrefixFrom(a, address.Bits))
			}
		}
	}
	if len(result["eth0"]) == 0 {
		return nil, fmt.Errorf("management address evidence missing")
	}
	return result, nil
}

func (e frrMigrationHostEvidence) semantic() string {
	var values []string
	for name, prefixes := range e {
		for _, p := range prefixes {
			values = append(values, name+"|"+p.String())
		}
	}
	sort.Strings(values)
	return strings.Join(values, ";")
}

//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func (e frrMigrationHostEvidence) routeAllowed(dst, dev, protocol, kind, gateway string, kernel bool) bool {
	addresses := e[dev]
	if len(addresses) == 0 {
		return false
	}
	defaultRoute := dst == "default" || dst == "0.0.0.0/0" || dst == "::/0"
	if defaultRoute {
		if dev != "eth0" || kind != "" && kind != "unicast" {
			return false
		}
		if kernel {
			if protocol != "" && protocol != "kernel" && protocol != "boot" && protocol != "dhcp" && protocol != "ra" {
				return false
			}
		} else if protocol != "kernel" {
			return false
		}
		g, err := netip.ParseAddr(gateway)
		if err != nil || g.IsUnspecified() || g.IsMulticast() || g.IsLoopback() || g.Is4In6() || g.Zone() != "" {
			return false
		}
		if dst == "0.0.0.0/0" && !g.Is4() || dst == "::/0" && !g.Is6() || protocol == "ra" && !g.Is6() {
			return false
		}
		for _, p := range addresses {
			if p.Addr().Is4() != g.Is4() {
				continue
			}
			if g.Is6() && g.IsLinkLocalUnicast() || p.Masked().Contains(g) && g != p.Addr() {
				return true
			}
		}
		return false
	}
	if gateway != "" || kind != "" && kind != "unicast" && kind != "local" && kind != "broadcast" && kind != "anycast" && kind != "multicast" {
		return false
	}
	if kernel {
		if protocol != "kernel" && !(dev == "eth0" && (protocol == "" || protocol == "boot")) {
			return false
		}
	} else if protocol != "connected" {
		return false
	}
	if kernel && dst == "ff00::/8" && kind == "multicast" {
		for _, p := range addresses {
			if p.Addr().Is6() {
				return true
			}
		}
		return false
	}
	p, err := netip.ParsePrefix(dst)
	if err != nil {
		a, err := netip.ParseAddr(dst)
		if err != nil {
			return false
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	for _, local := range addresses {
		if dev != "eth0" && !local.Addr().IsLinkLocalUnicast() {
			continue
		}
		if (kind == "" || kind == "unicast") && p == local.Masked() {
			return true
		}
		if kernel && kind == "local" && p.Bits() == local.Addr().BitLen() && p.Addr() == local.Addr() {
			return true
		}
		if kernel && kind == "anycast" && p.Bits() == 128 && p.Addr() == local.Masked().Addr() {
			return true
		}
		if kernel && kind == "broadcast" && local.Addr().Is4() && p.Bits() == 32 {
			b := local.Masked().Addr().As4()
			for bit := local.Bits(); bit < 32; bit++ {
				b[bit/8] |= 1 << (7 - bit%8)
			}
			if p.Addr() == netip.AddrFrom4(b) || p.Addr() == local.Masked().Addr() {
				return true
			}
		}
	}
	return false
}
