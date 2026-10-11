// SPDX-License-Identifier: Apache-2.0
package host

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
)

type ntpNativeProfile struct{ template, output, service string }

// chronyStepFile is the only conf.d drop-in the agent owns. The qualified
// chrony.conf.j2 ships makestep commented out and includes conf.d, so platforms
// whose RTC cannot be read at boot need it declared here.
const chronyStepFile = "/etc/chrony/conf.d/sonic-operator-makestep.conf"

// chronyStepContent returns the exact drop-in bytes, or nil when not declared.
func chronyStepContent(m *NTPMakeStep) []byte {
	if m == nil {
		return nil
	}
	return fmt.Appendf(nil, "# Managed by sonic-operator (SwitchSystem spec.ntp.makeStep). Do not edit.\nmakestep %d %d\n", m.ThresholdSeconds, m.Limit)
}

func validateNTPImage(p NativeProfile, n *NTP) error {
	if n == nil || p.NTPBackend != "ntpsec" {
		return nil
	}
	if n.MakeStep != nil {
		return ErrInvalid
	}
	for _, server := range n.Servers {
		if _, err := netip.ParseAddr(server); err != nil {
			return ErrInvalid
		}
	}
	return nil
}

// chronyStepPersisted reports whether the drop-in on disk is exactly declared.
func (n *Native) chronyStepPersisted(m *NTPMakeStep) bool {
	b, e := n.read(chronyStepFile)
	if m == nil {
		return errors.Is(e, os.ErrNotExist)
	}
	return e == nil && bytes.Equal(b, chronyStepContent(m))
}

// writeChronyStep converges the drop-in before chronyd is (re)activated.
func (n *Native) writeChronyStep(m *NTPMakeStep) error {
	if m != nil {
		return n.write(chronyStepFile, chronyStepContent(m), 0644)
	}
	if n.RemoveFile != nil {
		return n.RemoveFile(chronyStepFile)
	}
	if info, e := os.Lstat(chronyStepFile); errors.Is(e, os.ErrNotExist) {
		return nil
	} else if e != nil || !info.Mode().IsRegular() {
		return ErrNative
	}
	if os.Remove(chronyStepFile) != nil {
		return ErrNative
	}
	d, e := os.Open(filepath.Dir(chronyStepFile))
	if e != nil {
		return ErrNative
	}
	defer func() { _ = d.Close() }()
	if d.Sync() != nil {
		return ErrNative
	}
	return nil
}

// chronyStepLoaded compares the probe's drop-in evidence with the declaration.
func chronyStepLoaded(mode string, q Request, v daemonEvidence) bool {
	var want []byte
	if mode == "chrony" && q.System != nil && q.System.NTP != nil {
		want = chronyStepContent(q.System.NTP.MakeStep)
	}
	if want == nil {
		return v.StepFile == nil && v.StepDigest == ""
	}
	return v.StepFile != nil && v.StepFile.Inode != 0 && hashMatches(want, v.StepDigest)
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
