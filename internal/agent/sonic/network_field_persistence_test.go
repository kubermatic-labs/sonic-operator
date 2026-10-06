// SPDX-License-Identifier: Apache-2.0

package sonic

import "testing"

func TestNetworkSavedFields(t *testing.T) {
	t.Parallel()
	want := vlanChangeDB{"LOOPBACK_INTERFACE|Loopback0": {"NULL": "NULL"}, "LOOPBACK_INTERFACE|Loopback0|10.1.0.1/32": {"NULL": "NULL"}}
	for _, tc := range []struct {
		name, data       string
		matches, invalid bool
	}{
		{"empty native objects", `{"LOOPBACK_INTERFACE":{"Loopback0":{},"Loopback0|10.1.0.1/32":{}}}`, true, false},
		{"explicit placeholders", `{"LOOPBACK_INTERFACE":{"Loopback0":{"NULL":"NULL"},"Loopback0|10.1.0.1/32":{"NULL":"NULL"}}}`, true, false},
		{"missing prefix", `{"LOOPBACK_INTERFACE":{"Loopback0":{}}}`, false, false},
		{"saved VRF mismatch", `{"LOOPBACK_INTERFACE":{"Loopback0":{"vrf_name":"VrfBlue"},"Loopback0|10.1.0.1/32":{}}}`, false, false},
		{"saved VNET mismatch", `{"LOOPBACK_INTERFACE":{"Loopback0":{"vnet_name":"VnetBlue"},"Loopback0|10.1.0.1/32":{}}}`, false, false},
		{"malformed", `{`, false, true},
		{"null row", `{"LOOPBACK_INTERFACE":{"Loopback0":null,"Loopback0|10.1.0.1/32":{}}}`, false, true},
		{"duplicate row", `{"LOOPBACK_INTERFACE":{"Loopback0":{},"Loopback0":{},"Loopback0|10.1.0.1/32":{}}}`, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := networkSavedFields([]byte(tc.data), want)
			if got != tc.matches || (err != nil) != tc.invalid {
				t.Fatalf("matches=%v err=%v", got, err)
			}
		})
	}
}
