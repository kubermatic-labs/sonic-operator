// SPDX-License-Identifier: Apache-2.0

package controller

import "testing"

func TestNetworkLoopbackDesired(t *testing.T) {
	for _, tc := range []struct {
		name  string
		valid bool
	}{
		{"Loopback0", true}, {"Loopback4095", true}, {"Loopback4096", false}, {"Loopback00", false}, {"lo", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obj, _, _, _, _ := networkFixture(t, "L3Interface", `{"name":"`+tc.name+`","addresses":["10.1.0.1/32"]}`)
			_, target, err := networkDesired("L3Interface", obj)
			if (err == nil) != tc.valid || tc.valid && target != tc.name {
				t.Fatalf("target=%s err=%v", target, err)
			}
		})
	}
}
