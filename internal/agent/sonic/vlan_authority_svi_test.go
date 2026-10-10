// SPDX-License-Identifier: Apache-2.0
package sonic

import (
	"strings"
	"testing"
)

// An L3 interface (SVI) on a VLAN is owned by SwitchL3Interface. VLAN
// authority must coexist with it, but must not delete a VLAN that still has one.
func TestVLANAuthorityCoexistsWithVLANInterface(t *testing.T) {
	t.Parallel()
	base := func() vlanChangeDB {
		return vlanChangeDB{
			"PORT|Ethernet8":                        {"lanes": "37", "speed": "25000", "admin_status": "up"},
			"VLAN|Vlan200":                          {"vlanid": "200"},
			"VLAN_MEMBER|Vlan200|Ethernet8":         {"tagging_mode": "tagged"},
			"VLAN_INTERFACE|Vlan200":                {"NULL": "NULL"},
			"VLAN_INTERFACE|Vlan200|10.20.3.1/24":   {"NULL": "NULL"},
			"VLAN|Vlan210":                          {"vlanid": "210"},
			"VLAN_INTERFACE|Vlan210":                {"vrf_name": "default"},
			"VLAN_INTERFACE|Vlan210|10.21.3.1/24":   {"NULL": "NULL"},
			"VLAN_INTERFACE|Vlan210|2001:db8::1/64": {"NULL": "NULL"},
		}
	}
	keep := vlanChangeDB{"VLAN|Vlan200": {"vlanid": "200"}, "VLAN_MEMBER|Vlan200|Ethernet8": {"tagging_mode": "tagged"}}
	if err := vlanAuthoritySafe(base(), 200, keep); err != nil {
		t.Fatalf("SVI on the managed VLAN blocked authority: %v", err)
	}
	if err := vlanAuthoritySafe(base(), 210, vlanChangeDB{"VLAN|Vlan210": {"vlanid": "210"}}); err != nil {
		t.Fatalf("SVI with VRF binding and IPv6 blocked authority: %v", err)
	}
	if err := vlanAuthoritySafe(base(), 200, vlanChangeDB{}); err == nil || !strings.Contains(err.Error(), "L3 interface") {
		t.Fatalf("VLAN with an SVI deleted: %v", err)
	}
	for name, mutate := range map[string]func(vlanChangeDB){
		"malformed address": func(db vlanChangeDB) { db["VLAN_INTERFACE|Vlan200|10.20.3.1"] = map[string]string{"NULL": "NULL"} },
		"unknown field":     func(db vlanChangeDB) { db["VLAN_INTERFACE|Vlan200"] = map[string]string{"proxy_arp": "enabled"} },
		"address with fields": func(db vlanChangeDB) {
			db["VLAN_INTERFACE|Vlan200|10.20.3.1/24"] = map[string]string{"secondary": "true"}
		},
		"malformed VLAN": func(db vlanChangeDB) { db["VLAN_INTERFACE|Vlan0200"] = map[string]string{"NULL": "NULL"} },
		"extra key part": func(db vlanChangeDB) { db["VLAN_INTERFACE|Vlan200|10.20.3.1/24|x"] = map[string]string{"NULL": "NULL"} },
	} {
		db := base()
		mutate(db)
		if err := vlanAuthoritySafe(db, 200, keep); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
