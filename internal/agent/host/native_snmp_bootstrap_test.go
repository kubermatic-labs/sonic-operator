// SPDX-License-Identifier: Apache-2.0
package host

import (
	"strings"
	"testing"
)

func TestSNMPBootstrapPreventsRetiredCommunityResurrection(t *testing.T) {
	desired := SNMP{Location: "rack A", Community: Credential("new-fixture-community")}
	old := []byte("snmp_rocommunity: old-fixture-community\nsnmp_location: rack A\n")
	if snmpBootstrapMatches(old, desired) {
		t.Fatal("old startup community would be silently reimported")
	}
	generated, err := snmpBootstrap(desired)
	if err != nil {
		t.Fatal(err)
	}
	if !snmpBootstrapMatches(generated, desired) || strings.Contains(string(generated), "old-fixture-community") {
		t.Fatal("typed startup input is not reproducible")
	}
	if !snmpBootstrapMatches([]byte("snmp_location: public\n"), SNMP{Location: "public"}) {
		t.Fatal("current no-community input should be adopted without rewriting")
	}
	for _, bad := range []string{"snmp_rocommunity: x\nsnmp_rocommunity: y\n", "snmp_location: public\nunknown: value\n", "snmp_location: public\nsnmp_rwcommunity: x\n"} {
		if snmpBootstrapMatches([]byte(bad), SNMP{Location: "public"}) {
			t.Fatal("unqualified startup input accepted")
		}
	}
	for _, bad := range []string{"null", "snmp_location: 123\n", "snmp_location: on\n"} {
		if _, err := decodeSNMPBootstrap([]byte(bad)); err == nil {
			t.Fatal("startup data with non-string FullLoader semantics accepted")
		}
	}
}

func TestSNMPApplyPersistsTypedStartupInputBeforeRestart(t *testing.T) {
	f := newSystemFixture(t)
	q := f.request(SNMP{Location: "rack A", Community: Credential("new-fixture-community")})
	result, err := f.engine.Ensure(t.Context(), q, "connection")
	if err != nil || !result.Ready() || f.restarts != 1 {
		t.Fatal("typed startup/activation did not converge", err)
	}
}
