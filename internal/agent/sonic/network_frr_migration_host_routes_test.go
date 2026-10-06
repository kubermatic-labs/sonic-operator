// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"strings"
	"testing"
)

const migrationHostAddresses = `[{"ifname":"eth0","addr_info":[{"family":"inet","local":"10.3.109.166","prefixlen":8,"scope":"global","dynamic":true},{"family":"inet6","local":"2001:db8:100::10","prefixlen":64,"scope":"global","dynamic":true},{"family":"inet6","local":"fe80::10","prefixlen":64,"scope":"link"}]},{"ifname":"Ethernet4","addr_info":[{"family":"inet6","local":"fe80::20","prefixlen":64,"scope":"link"}]},{"ifname":"Vlan100","addr_info":[{"family":"inet6","local":"fe80::30","prefixlen":64,"scope":"link"}]}]`

func TestFRRMigrationVerifiedHostRoutes(t *testing.T) {
	db := frrMigrationTestDB()
	db["PORT|Ethernet4"] = map[string]string{"admin_status": "up"}
	db["VLAN|Vlan100"] = map[string]string{"vlanid": "100"}
	host, err := frrMigrationHostAddresses([]byte(migrationHostAddresses), db)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, raw     string
		kernel, valid bool
	}{
		{"DHCP default", `[{"dst":"default","dev":"eth0","gateway":"10.0.0.1"}]`, true, true},
		{"RA default", `[{"dst":"default","dev":"eth0","gateway":"fe80::1","protocol":"ra"}]`, true, true},
		{"SLAAC connected", `[{"dst":"2001:db8:100::/64","dev":"eth0","protocol":"kernel"}]`, true, true},
		{"port link local", `[{"dst":"fe80::/64","dev":"Ethernet4","protocol":"kernel"}]`, true, true},
		{"VLAN link local address", `[{"dst":"fe80::30","dev":"Vlan100","type":"local","protocol":"kernel","table":"local"}]`, true, true},
		{"port multicast", `[{"dst":"ff00::/8","dev":"Ethernet4","type":"multicast","protocol":"kernel","table":"local"}]`, true, true},
		{"FRR default", `{"default":{"0.0.0.0/0":[{"prefix":"0.0.0.0/0","protocol":"kernel","nexthops":[{"interfaceName":"eth0","ip":"10.0.0.1"}]}]}}`, false, true},
		{"FRR link local", `{"default":{"fe80::/64":[{"prefix":"fe80::/64","protocol":"connected","nexthops":[{"interfaceName":"Ethernet4"}]}]}}`, false, true},
		{"data-plane default", `[{"dst":"default","dev":"Ethernet4","gateway":"10.0.0.1"}]`, true, false},
		{"unknown port", `[{"dst":"fe80::/64","dev":"Ethernet999","protocol":"kernel"}]`, true, false},
		{"unassigned address", `[{"dst":"fe80::99","dev":"Ethernet4","type":"local","protocol":"kernel","table":"local"}]`, true, false},
		{"data-plane connected", `[{"dst":"192.0.2.0/24","dev":"Ethernet4","protocol":"kernel"}]`, true, false},
		{"unrelated mgmt subnet", `[{"dst":"192.0.2.0/24","dev":"eth0","protocol":"kernel"}]`, true, false},
		{"mgmt static", `[{"dst":"default","dev":"eth0","gateway":"10.0.0.1","protocol":"static"}]`, true, false},
		{"non-onlink gateway", `[{"dst":"default","dev":"eth0","gateway":"192.0.2.1"}]`, true, false},
		{"RA via port", `[{"dst":"default","dev":"Ethernet4","gateway":"fe80::1","protocol":"ra"}]`, true, false},
		{"FRR static", `{"default":{"0.0.0.0/0":[{"prefix":"0.0.0.0/0","protocol":"static","nexthops":[{"interfaceName":"eth0","ip":"10.0.0.1"}]}]}}`, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := frrMigrationValidateRoutes([]byte(tc.raw), tc.kernel, db, host)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
		})
	}
	a := `{"default":{"0.0.0.0/0":[{"prefix":"0.0.0.0/0","protocol":"kernel","nexthops":[{"interfaceName":"eth0","ip":"10.0.0.1"}]}]}}`
	first, err := frrMigrationValidateRoutes([]byte(a), false, db, host)
	if err != nil {
		t.Fatal(err)
	}
	second, err := frrMigrationValidateRoutes([]byte(strings.ReplaceAll(a, "10.0.0.1", "10.0.0.2")), false, db, host)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("gateway change absent from approval fingerprint")
	}
}

func TestFRRMigrationHostAddressEvidenceRejectsUnsafe(t *testing.T) {
	for _, raw := range []string{`null`, `[]`, strings.Replace(migrationHostAddresses, `"local":"10.3.109.166"`, `"local":"10.3.109.166","local":"10.0.0.2"`, 1), strings.Replace(migrationHostAddresses, `"prefixlen":8`, `"prefixlen":0`, 1)} {
		if _, err := frrMigrationHostAddresses([]byte(raw), frrMigrationTestDB()); err == nil {
			t.Fatal("invalid host address evidence accepted")
		}
	}
}

func TestFRRMigrationHostAddressesIgnoreUnrelatedPIM(t *testing.T) {
	raw := strings.TrimSuffix(migrationHostAddresses, "]") + `,{"ifname":"pimreg","link":null,"addr_info":[]}]`
	if _, err := frrMigrationHostAddresses([]byte(raw), frrMigrationTestDB()); err != nil {
		t.Fatal(err)
	}
}
