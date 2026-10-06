// SPDX-License-Identifier: Apache-2.0
package host

import (
	"encoding/json"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

// Database is internal only. It never appears in an RPC or recovery record.
type Database map[string]map[string]map[string]string

func cloneDB(db Database) Database {
	out := Database{}
	for table, rows := range db {
		out[table] = map[string]map[string]string{}
		for key, fields := range rows {
			out[table][key] = maps.Clone(fields)
		}
	}
	return out
}
func managementDatabase(db Database, m Management) (Database, error) {
	if ValidateManagement(m) != nil {
		return nil, ErrInvalid
	}
	out := cloneDB(db)
	if out["MGMT_INTERFACE"] == nil {
		out["MGMT_INTERFACE"] = map[string]map[string]string{}
	}
	for key, fields := range out["MGMT_INTERFACE"] {
		if strings.HasPrefix(key, "eth0|") {
			for f, v := range fields {
				if f != "gwaddr" && !(f == "NULL" && v == "NULL") {
					return nil, ErrNative
				}
			}
			delete(out["MGMT_INTERFACE"], key)
		}
	}
	for _, a := range m.Addresses {
		fields := map[string]string{"NULL": "NULL"}
		if a.Gateway != "" {
			fields = map[string]string{"gwaddr": a.Gateway}
		}
		out["MGMT_INTERFACE"]["eth0|"+a.Prefix] = fields
	}
	return out, nil
}
func managementFromDB(db Database, mac string) (Management, error) {
	m := Management{Interface: "eth0", MAC: mac}
	for key, f := range db["MGMT_INTERFACE"] {
		if strings.HasPrefix(key, "eth0|") {
			m.Addresses = append(m.Addresses, Address{Prefix: strings.TrimPrefix(key, "eth0|"), Gateway: f["gwaddr"]})
		}
	}
	slices.SortFunc(m.Addresses, func(a, b Address) int { return strings.Compare(a.Prefix, b.Prefix) })
	return m, ValidateManagement(m)
}
func systemDatabase(db Database, s System) (Database, error) {
	if ValidateSystem(s) != nil {
		return nil, ErrInvalid
	}
	out := cloneDB(db)
	if s.NTP != nil {
		n := normalizedNTP(*s.NTP)
		// These are the generating inputs exercised by the two fleet images.
		// Their templates do not implement arbitrary admin/DHCP/server-role
		// transitions; never turn inert changes into RuntimeVerified evidence.
		if n.AdminState != "enabled" || n.DHCP != "enabled" || n.ServerRole != "disabled" {
			return nil, ErrNative
		}
		if out["NTP"] == nil {
			out["NTP"] = map[string]map[string]string{}
		}
		if out["NTP"]["global"] == nil {
			out["NTP"]["global"] = map[string]string{}
		}
		g := out["NTP"]["global"]
		if g["authentication"] == "enabled" {
			return nil, ErrNative
		}
		g["admin_state"], g["dhcp"], g["server_role"], g["src_intf"], g["vrf"], g["authentication"] = n.AdminState, n.DHCP, n.ServerRole, n.SourceInterface, "default", "disabled"
		// This profile owns configured server membership only. Authentication,
		// pools or per-server options need their own typed API before adoption.
		for _, fields := range out["NTP_SERVER"] {
			for f, v := range fields {
				if f != "NULL" || v != "NULL" {
					return nil, ErrNative
				}
			}
		}
		out["NTP_SERVER"] = map[string]map[string]string{}
		for _, v := range s.NTP.Servers {
			out["NTP_SERVER"][v] = map[string]string{"NULL": "NULL"}
		}
	}
	if s.SNMP != nil {
		if len(out["SNMP_USER"]) > 0 {
			return nil, ErrNative
		}
		for _, fields := range out["SNMP_COMMUNITY"] {
			if len(fields) != 1 || fields["TYPE"] != "RO" {
				return nil, ErrNative
			}
		}
		if out["SNMP"] == nil {
			out["SNMP"] = map[string]map[string]string{}
		}
		out["SNMP"]["LOCATION"] = map[string]string{"Location": s.SNMP.Location}
		// SONiC's native CONTACT generator emits <key> <value>.
		// Split at the first space to preserve the declared displayed text.
		name, value, _ := strings.Cut(s.SNMP.Contact, " ")
		if name != "" {
			out["SNMP"]["CONTACT"] = map[string]string{name: value}
		}
		out["SNMP_COMMUNITY"] = map[string]map[string]string{}
		if s.SNMP.Community != "" {
			out["SNMP_COMMUNITY"][string(s.SNMP.Community)] = map[string]string{"TYPE": "RO"}
		}
	}
	return out, nil
}
func scopedEqual(a, b Database, tables ...string) bool {
	for _, t := range tables {
		if !reflect.DeepEqual(a[t], b[t]) && !(len(a[t]) == 0 && len(b[t]) == 0) {
			return false
		}
	}
	return true
}
func managementRuntimeMatches(m Management, addresses, routes []byte) bool {
	var links []struct {
		IfName  string   `json:"ifname"`
		Address string   `json:"address"`
		Flags   []string `json:"flags"`
		Info    []struct {
			Local     string `json:"local"`
			PrefixLen int    `json:"prefixlen"`
			Scope     string `json:"scope"`
		} `json:"addr_info"`
	}
	var rs []struct {
		Destination string `json:"dst"`
		Gateway     string `json:"gateway"`
		Device      string `json:"dev"`
		Metric      int    `json:"metric"`
		Table       any    `json:"table"`
	}
	if json.Unmarshal(addresses, &links) != nil || json.Unmarshal(routes, &rs) != nil || len(links) != 1 || links[0].IfName != "eth0" || !slices.Contains(links[0].Flags, "UP") || (m.MAC != "" && links[0].Address != m.MAC) {
		return false
	}
	want := map[string]bool{}
	for _, a := range m.Addresses {
		want[a.Prefix] = true
	}
	for _, a := range links[0].Info {
		if a.Scope != "global" {
			continue
		}
		p := a.Local + "/" + strconv.Itoa(a.PrefixLen)
		if !want[p] {
			return false
		}
		delete(want, p)
	}
	if len(want) != 0 {
		return false
	}
	for _, a := range m.Addresses {
		p, _ := netip.ParsePrefix(a.Prefix)
		connected := false
		for _, r := range rs {
			if r.Destination == p.Masked().String() && r.Device == "eth0" && r.Gateway == "" && (r.Table == "default" || r.Table == float64(253)) {
				connected = true
			}
		}
		if !connected {
			return false
		}
		if a.Gateway == "" {
			continue
		}
		found := false
		for _, r := range rs {
			if r.Destination == "default" && r.Gateway == a.Gateway && r.Device == "eth0" && r.Metric == 201 && (r.Table == "default" || r.Table == float64(253)) {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	// Reject unexpected management defaults too, including the old gateway.
	for _, r := range rs {
		if r.Destination != "default" || r.Device != "eth0" {
			continue
		}
		found := false
		for _, a := range m.Addresses {
			if r.Gateway == a.Gateway {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func family(prefix string) string {
	p, _ := netip.ParsePrefix(prefix)
	if p.Addr().Is4() {
		return "-4"
	}
	return "-6"
}
