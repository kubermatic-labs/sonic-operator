// SPDX-License-Identifier: Apache-2.0
package host

import "testing"

func TestNTPsecRuntimeSources(t *testing.T) {
	data := []byte("     remote           refid      st t when poll reach   delay   offset   jitter\n==============================================================================\n*10.0.0.1       .GPS.            1 u   11   64  377    0.123    0.234    0.001\n")
	if !ntpsecSourcesMatch([]string{"10.0.0.1"}, data) || ntpsecSourcesMatch([]string{"10.0.0.2"}, data) {
		t.Fatal("native ntpsec source evidence incorrectly matched")
	}
	if !ntpsecSourcesMatch(nil, []byte("No association ID's returned\n")) {
		t.Fatal("existing zero-server configuration rejected")
	}
}

func TestNTPsecInstalledEmptySourceResponse(t *testing.T) {
	// Exact read-only output from SONiC 202411.1216684-48c2d4c3e.
	actual := []byte("server=localhost No association IDs returned\n")
	if !ntpsecSourcesMatch(nil, actual) || ntpsecSourcesMatch([]string{"192.0.2.123"}, actual) {
		t.Fatal("installed NTPsec empty-source response incorrectly classified")
	}
	for _, bad := range []string{"", "server=localhost request timed out", "No association IDs returned garbage"} {
		if ntpsecSourcesMatch(nil, []byte(bad)) {
			t.Fatal("unrecognized response became native readiness")
		}
	}
}
