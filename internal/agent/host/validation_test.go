// SPDX-License-Identifier: Apache-2.0
package host

import (
	"encoding/json"
	"testing"
)

func validManagement() Management {
	return Management{Interface: "eth0", Addresses: []Address{{Prefix: "10.0.0.11/24", Gateway: "10.0.0.1"}}, MAC: "02:00:00:00:00:11"}
}

func TestManagementValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Management)
		valid  bool
	}{
		{"host bits", func(*Management) {}, true},
		{"interface allowlist", func(m *Management) { m.Interface = "Ethernet0" }, false},
		{"multicast mac", func(m *Management) { m.MAC = "01:00:00:00:00:11" }, false},
		{"zero mac", func(m *Management) { m.MAC = "00:00:00:00:00:00" }, false},
		{"gateway family", func(m *Management) { m.Addresses[0].Gateway = "::1" }, false},
		{"gateway subnet", func(m *Management) { m.Addresses[0].Gateway = "10.5.0.1" }, false},
		{"duplicate", func(m *Management) { m.Addresses = append(m.Addresses, m.Addresses[0]) }, false},
		{"empty addresses", func(m *Management) { m.Addresses = nil }, false},
		{"injection", func(m *Management) { m.Addresses[0].Prefix = "10.0.0.11/24; reboot" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := validManagement()
			tc.mutate(&m)
			if (ValidateManagement(m) == nil) != tc.valid {
				t.Fatal("unexpected validation outcome")
			}
		})
	}
}

func TestStrictRequestAndCredentialRedaction(t *testing.T) {
	for _, input := range []string{`{"kind":"Management","rawCommand":"reboot"}`, `{"kind":"Management","kind":"System"}`, `null`, `{} {}`} {
		if _, err := DecodeRequest([]byte(input)); err == nil {
			t.Fatalf("accepted invalid envelope %s", input)
		}
	}
	s := System{NTP: &NTP{Servers: []string{"10.0.0.1"}}, SNMP: &SNMP{Location: "rack A", Contact: "ops", Community: Credential("private-test-value")}}
	if err := ValidateSystem(s); err != nil {
		t.Fatal(err)
	}
	if got := s.SNMP.Community.String(); got != "[redacted]" {
		t.Fatal("credential formatter disclosed value")
	}
	data, err := json.Marshal(s)
	if err != nil || len(data) == 0 {
		t.Fatal("private wire encoding failed")
	}
	s.SNMP.Community = Credential("bad\nrocommunity injected")
	if err := ValidateSystem(s); err == nil {
		t.Fatal("accepted config injection")
	}
	s = System{NTP: &NTP{Servers: []string{"--help"}}}
	if ValidateSystem(s) == nil {
		t.Fatal("accepted option injection")
	}
}

func TestSNMPLocationCanBeOwnedWithoutInventingACommunity(t *testing.T) {
	s := System{SNMP: &SNMP{Location: "public"}}
	if err := ValidateSystem(s); err != nil {
		t.Fatal("location-only ownership requires an unnecessary credential:", err)
	}
	db, e := systemDatabase(Database{"SNMP": {"LOCATION": {"Location": "public"}}}, s)
	if e != nil || len(db["SNMP_COMMUNITY"]) != 0 {
		t.Fatal("location-only ownership introduced credentials")
	}
}
