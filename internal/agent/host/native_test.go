// SPDX-License-Identifier: Apache-2.0
package host

import (
	"reflect"
	"testing"
)

func TestManagementPlanPreservesUnknownFieldsAndOtherInterfaces(t *testing.T) {
	db := Database{"MGMT_INTERFACE": {"eth0|10.0.0.11/24": {"gwaddr": "10.0.0.1"}, "eth1|192.0.2.2/24": {"gwaddr": "192.0.2.1"}}, "DEVICE_METADATA": {"localhost": {"mac": "00:11:22:33:44:55"}}, "SNMP_COMMUNITY": {"never-disclose": {"TYPE": "RO"}}}
	m := validManagement()
	m.Addresses[0].Prefix = "10.0.0.99/24"
	after, err := managementDatabase(db, m)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := after["MGMT_INTERFACE"]["eth0|10.0.0.11/24"]; ok {
		t.Fatal("old address retained")
	}
	if !reflect.DeepEqual(after["DEVICE_METADATA"], db["DEVICE_METADATA"]) || !reflect.DeepEqual(after["SNMP_COMMUNITY"], db["SNMP_COMMUNITY"]) || !reflect.DeepEqual(after["MGMT_INTERFACE"]["eth1|192.0.2.2/24"], db["MGMT_INTERFACE"]["eth1|192.0.2.2/24"]) {
		t.Fatal("unowned fields changed")
	}
	db["MGMT_INTERFACE"]["eth0|10.0.0.11/24"]["forced_mgmt_routes"] = "10.3.0.0/16"
	if _, err = managementDatabase(db, m); err == nil {
		t.Fatal("deleted unsupported management route")
	}
}
func TestNativeRuntimeRequiresAddressesRoutesAndActiveMAC(t *testing.T) {
	m := validManagement()
	addresses := []byte(`[{"ifname":"eth0","address":"02:00:00:00:00:11","flags":["UP"],"addr_info":[{"local":"10.0.0.11","prefixlen":24,"scope":"global"}]}]`)
	routes := []byte(`[{"dst":"default","gateway":"10.0.0.1","dev":"eth0","metric":201,"table":"default"},{"dst":"10.0.0.0/24","dev":"eth0","table":"default"}]`)
	if !managementRuntimeMatches(m, addresses, routes) {
		t.Fatal("valid native state rejected")
	}
	if managementRuntimeMatches(m, addresses, []byte(`[{"dst":"default","gateway":"10.0.0.1","dev":"eth0","metric":201,"table":"default"}]`)) {
		t.Fatal("missing connected policy-table route was ignored")
	}
	for _, bad := range []Management{{Interface: "eth0", Addresses: []Address{{Prefix: "10.0.0.99/24", Gateway: "10.0.0.1"}}, MAC: m.MAC}, {Interface: "eth0", Addresses: m.Addresses, MAC: "02:00:00:00:00:99"}, {Interface: "eth0", Addresses: []Address{{Prefix: "10.0.0.11/24", Gateway: "10.0.0.2"}}, MAC: m.MAC}} {
		if managementRuntimeMatches(bad, addresses, routes) {
			t.Fatal("inert Redis match could mask native drift")
		}
	}
}
func TestSystemTypedPlanAndCredentialBoundary(t *testing.T) {
	db := Database{"SNMP": {"LOCATION": {"Location": "old"}}, "SNMP_COMMUNITY": {"old-private-value": {"TYPE": "RO"}}, "NTP": {"global": {"src_intf": "eth0"}}, "PORT": {"Ethernet0": {"admin_status": "up"}}}
	s := System{NTP: &NTP{Servers: []string{"10.0.0.1"}}, SNMP: &SNMP{Location: "rack A", Contact: "ops", Community: Credential("new-private-value")}}
	after, err := systemDatabase(db, s)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after["PORT"], db["PORT"]) {
		t.Fatal("unowned system fields changed")
	}
	if _, ok := after["SNMP_COMMUNITY"]["old-private-value"]; ok {
		t.Fatal("old owned credential remained")
	}
	if len(after["SNMP_COMMUNITY"]) != 1 {
		t.Fatal("new credential not installed")
	}
}

func TestSystemOwnsConfiguredNTPGlobalInputs(t *testing.T) {
	db := Database{"NTP": {"global": {"admin_state": "disabled", "dhcp": "disabled", "authentication": "disabled", "src_intf": "eth0", "server_role": "disabled", "vrf": "default", "vendor_field": "preserved"}}}
	after, err := systemDatabase(db, System{NTP: &NTP{Servers: []string{}}})
	if err != nil {
		t.Fatal(err)
	}
	if after["NTP"]["global"]["admin_state"] != "enabled" || after["NTP"]["global"]["dhcp"] != "enabled" || after["NTP"]["global"]["vendor_field"] != "preserved" {
		t.Fatal("configured global NTP was not owned")
	}
}
