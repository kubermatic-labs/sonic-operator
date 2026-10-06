// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"strings"
	"testing"
)

const traditionalRuntimeFixture = `frr version 10.0.1
frr defaults traditional
hostname switch
log syslog informational
log facility local4
no zebra nexthop kernel enable
fpm address 127.0.0.1
no fpm use-next-hop-groups
agentx
no service integrated-vtysh-config
ip prefix-list PL_LoopbackV4 seq 5 permit 10.1.0.1/32
router bgp 65100
 bgp router-id 10.1.0.1
 bgp suppress-fib-pending
 bgp log-neighbor-changes
 no bgp ebgp-requires-policy
 no bgp default ipv4-unicast
 bgp bestpath as-path multipath-relax
 address-family ipv4 unicast
  network 10.1.0.1/32
 exit-address-family
exit
route-map RM_SET_SRC permit 10
 set src 10.1.0.1
exit
ip protocol bgp route-map RM_SET_SRC
ip nht resolve-via-default
ipv6 nht resolve-via-default
end
`

func TestTraditionalBGPPolicy(t *testing.T) {
	t.Parallel()
	s := routingBGPSpec{LocalASN: 65100, RouterID: "10.1.0.1", Prefixes: []string{"10.1.0.1/32"}, VRF: "default"}
	for _, tc := range []struct {
		name, config  string
		want, invalid bool
	}{
		{"exact current policy", traditionalRuntimeFixture, true, false},
		{"router ID drift", strings.ReplaceAll(traditionalRuntimeFixture, "bgp router-id 10.1.0.1", "bgp router-id 10.1.0.2"), false, false},
		{"missing source", strings.ReplaceAll(traditionalRuntimeFixture, " set src 10.1.0.1\n", ""), false, false},
		{"missing separated readback", strings.ReplaceAll(traditionalRuntimeFixture, "no service integrated-vtysh-config\n", ""), false, false},
		{"neighbor", strings.ReplaceAll(traditionalRuntimeFixture, " bgp router-id", " neighbor 10.1.0.2 remote-as 65101\n bgp router-id"), false, true},
		{"unrelated route-map", traditionalRuntimeFixture + "route-map OTHER permit 10\n", false, true},
		{"redistribution", strings.ReplaceAll(traditionalRuntimeFixture, "  network", "  redistribute connected\n  network"), false, true},
		{"duplicate network", strings.ReplaceAll(traditionalRuntimeFixture, "  network 10.1.0.1/32", "  network 10.1.0.1/32\n  network 10.1.0.2/32"), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := traditionalPolicy(map[string]string{"running": tc.config}, s, true)
			if got != tc.want || (err != nil) != tc.invalid {
				t.Fatalf("matched=%v invalid=%v err=%v", got, tc.invalid, err)
			}
		})
	}
}
