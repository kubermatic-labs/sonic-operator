// SPDX-License-Identifier: Apache-2.0
package host

import (
	"net/netip"
	"reflect"
	"slices"
	"strings"
)

type ntpNativeProfile struct{ template, output, service string }

func validateNTPImage(p NativeProfile, n *NTP) error {
	if n == nil || p.NTPBackend != "ntpsec" {
		return nil
	}
	for _, server := range n.Servers {
		if _, err := netip.ParseAddr(server); err != nil {
			return ErrInvalid
		}
	}
	return nil
}

func (n *Native) ntpProfile(p NativeProfile) (ntpNativeProfile, error) {
	profile := ntpNativeProfile{chronyTemplate, "/etc/chrony/chrony.conf", "chrony.service"}
	digest := p.ChronySHA256
	switch p.NTPBackend {
	case "chrony":
	case "ntpsec":
		profile = ntpNativeProfile{"/usr/share/sonic/templates/ntp.conf.j2", "/etc/ntpsec/ntp.conf", "ntpsec.service"}
		digest = p.NTPsecSHA256
	default:
		return profile, ErrNative
	}
	b, e := n.read(profile.template)
	if e != nil || !hashMatches(b, digest) {
		return profile, ErrNative
	}
	return profile, nil
}
func ntpsecSourcesMatch(want []string, data []byte) bool {
	text := strings.TrimSpace(string(data))
	if text == "No association ID's returned" || text == "server=localhost No association IDs returned" {
		return len(want) == 0
	}
	var got []string
	header := false
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "====") {
			header = true
			continue
		}
		if !header {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 9 {
			return false
		}
		value := strings.TrimLeft(fields[0], "*+#-ox.")
		ip, e := netip.ParseAddr(value)
		if e != nil {
			return false
		}
		got = append(got, ip.String())
	}
	if !header {
		return false
	}
	want = slices.Clone(want)
	slices.Sort(want)
	slices.Sort(got)
	return reflect.DeepEqual(want, got) || (len(want) == 0 && len(got) == 0)
}
