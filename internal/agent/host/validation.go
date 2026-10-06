// SPDX-License-Identifier: Apache-2.0
package host

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"reflect"
	"regexp"
	"strings"
)

var ErrInvalid = errors.New("invalid typed host configuration")
var safeID = regexp.MustCompile(`^[A-Za-z0-9_.:/@-]{1,256}$`)
var serverName = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)

// StrictDecode rejects unknown AND duplicate fields at every nesting level.
func StrictDecode(data []byte, out any) error {
	if len(data) == 0 || len(data) > 64<<10 {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	var value func() error
	value = func() error {
		t, err := d.Token()
		if err != nil {
			return err
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					if e != nil {
						return e
					}
					s, ok := k.(string)
					if !ok || seen[s] {
						return ErrInvalid
					}
					seen[s] = true
					if e = value(); e != nil {
						return e
					}
				}
			case '[':
				for d.More() {
					if e := value(); e != nil {
						return e
					}
				}
			default:
				return ErrInvalid
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if err := value(); err != nil {
		return ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInvalid
	}
	var tree any
	if json.Unmarshal(data, &tree) != nil || !canonicalFields(tree, reflect.TypeOf(out)) {
		return ErrInvalid
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) || d.Decode(out) != nil {
		return ErrInvalid
	}
	return nil
}

func canonicalFields(value any, t reflect.Type) bool {
	if t == nil {
		return false
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return true
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" {
				continue
			}
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = f.Name
			}
			fields[name] = f.Type
		}
		for key, v := range object {
			field, ok := fields[key]
			if !ok || !canonicalFields(v, field) {
				return false
			}
		}
	case reflect.Slice, reflect.Array:
		if values, ok := value.([]any); ok {
			for _, v := range values {
				if !canonicalFields(v, t.Elem()) {
					return false
				}
			}
		}
	case reflect.Map:
		if values, ok := value.(map[string]any); ok {
			for _, v := range values {
				if !canonicalFields(v, t.Elem()) {
					return false
				}
			}
		}
	}
	return true
}
func DecodeRequest(data []byte) (Request, error) {
	var r Request
	if err := StrictDecode(data, &r); err != nil {
		return r, err
	}
	return r, ValidateRequest(r)
}
func ValidateRequest(r Request) error {
	if !safeID.MatchString(r.Owner) || !safeID.MatchString(r.Target) || !safeID.MatchString(r.Revision) {
		return ErrInvalid
	}
	switch r.Kind {
	case "Management":
		if r.Management == nil || r.System != nil || r.RollbackSeconds < 30 || r.RollbackSeconds > 600 {
			return ErrInvalid
		}
		return ValidateManagement(*r.Management)
	case "System":
		if r.System == nil || r.Management != nil || r.RollbackSeconds != 0 {
			return ErrInvalid
		}
		return ValidateSystem(*r.System)
	default:
		return ErrInvalid
	}
}
func ValidateManagement(m Management) error {
	if m.Interface != "eth0" || len(m.Addresses) < 1 || len(m.Addresses) > 8 {
		return ErrInvalid
	}
	if m.MAC != "" {
		mac, e := net.ParseMAC(m.MAC)
		if e != nil || len(mac) != 6 || mac.String() != m.MAC || mac[0]&1 != 0 || m.MAC == "00:00:00:00:00:00" {
			return ErrInvalid
		}
	}
	seen := map[netip.Addr]bool{}
	gateways := map[bool]string{}
	for _, a := range m.Addresses {
		p, e := netip.ParsePrefix(a.Prefix)
		if e != nil || p.String() != a.Prefix || p.Addr().Is4In6() || !p.Addr().IsGlobalUnicast() || seen[p.Addr()] {
			return ErrInvalid
		}
		seen[p.Addr()] = true
		if a.Gateway != "" {
			g, e := netip.ParseAddr(a.Gateway)
			if e != nil || g.String() != a.Gateway || g.Is4In6() || !g.IsGlobalUnicast() || g.Is4() != p.Addr().Is4() || !p.Contains(g) || g == p.Addr() {
				return ErrInvalid
			}
			if gateways[g.Is4()] != "" {
				return ErrInvalid
			}
			gateways[g.Is4()] = a.Gateway
		}
	}
	return nil
}
func ValidateSystem(s System) error {
	if s.NTP == nil && s.SNMP == nil {
		return ErrInvalid
	}
	if s.NTP != nil {
		n := normalizedNTP(*s.NTP)
		for _, v := range []string{n.AdminState, n.DHCP, n.ServerRole} {
			if v != "enabled" && v != "disabled" {
				return ErrInvalid
			}
		}
		if n.SourceInterface != "eth0" {
			return ErrInvalid
		}
		if len(s.NTP.Servers) > 16 {
			return ErrInvalid
		}
		seen := map[string]bool{}
		for _, v := range s.NTP.Servers {
			a, e := netip.ParseAddr(v)
			if (e != nil && !serverName.MatchString(v)) || (e == nil && (!a.IsGlobalUnicast() || a.Is4In6())) || seen[v] {
				return ErrInvalid
			}
			seen[v] = true
		}
	}
	if s.SNMP != nil {
		v := s.SNMP
		if !safeText(v.Location, 256) || !safeText(v.Contact, 256) || len(v.Community) > 128 {
			return ErrInvalid
		}
		for _, c := range string(v.Community) {
			if c < 33 || c > 126 || strings.ContainsRune(`"'\\#`, c) {
				return ErrInvalid
			}
		}
	}
	return nil
}
func normalizedNTP(n NTP) NTP {
	if n.AdminState == "" {
		n.AdminState = "enabled"
	}
	if n.DHCP == "" {
		n.DHCP = "enabled"
	}
	if n.ServerRole == "" {
		n.ServerRole = "disabled"
	}
	if n.SourceInterface == "" {
		n.SourceInterface = "eth0"
	}
	return n
}

func safeText(s string, max int) bool {
	if len(s) > max {
		return false
	}
	for _, c := range s {
		if c < 32 || c > 126 || strings.ContainsRune(`"'\\`, c) {
			return false
		}
	}
	return true
}
