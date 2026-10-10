// SPDX-License-Identifier: Apache-2.0
package host

import (
	"strings"
	"testing"
)

func TestSNMPv3UserLifecycleNeverKeepsStalePersistedKeys(t *testing.T) {
	f := newSystemFixture(t)
	user := fixtureUSMUser(SNMPAuthPriv)
	q := f.request(SNMP{Location: "public", Users: []SNMPUser{user}})
	if result, err := f.engine.Ensure(t.Context(), q, "writer"); err != nil || !result.Ready() {
		t.Fatal("SNMPv3 user activation failed", err)
	}
	if f.scrubs != 0 || f.usm["monitor"].AuthPassword != user.AuthPassword || strings.Join(f.persistedUsers(), ",") != "monitor" {
		t.Fatal("first activation did not load exactly the declared user")
	}

	// A plain restart would re-persist the old key, which Net-SNMP reads after
	// the rendered CreateUser line; the rotation must stop, scrub and start.
	rotated := user
	rotated.AuthPassword, rotated.PrivPassword = "auth-fixture-2", "priv-fixture-2"
	q = f.request(SNMP{Location: "public", Users: []SNMPUser{rotated}})
	q.Revision = "2"
	if result, err := f.engine.Ensure(t.Context(), q, "writer"); err != nil || !result.Ready() {
		t.Fatal("SNMPv3 passphrase rotation did not converge", err)
	}
	if f.scrubs != 1 || f.usm["monitor"].AuthPassword != "auth-fixture-2" || f.usm["monitor"].PrivPassword != "priv-fixture-2" {
		t.Fatal("rotated passphrases were shadowed by persisted keys")
	}

	q = f.request(SNMP{Location: "public"})
	q.Revision = "3"
	if result, err := f.engine.Ensure(t.Context(), q, "writer"); err != nil || !result.Ready() {
		t.Fatal("SNMPv3 user removal did not converge", err)
	}
	if f.scrubs != 2 || len(f.usm) != 0 || len(f.persistedUsers()) != 0 || len(f.db["SNMP_USER"]) != 0 {
		t.Fatal("removed user survived in native or persisted state")
	}
	if !strings.Contains(string(f.persistent), "engineBoots 1") {
		t.Fatal("scrub discarded unrelated engine state")
	}
}

func TestPersistedRetiredUserBlocksRuntimeProof(t *testing.T) {
	f := newSystemFixture(t)
	q := f.request(SNMP{Location: "public", Users: []SNMPUser{fixtureUSMUser(SNMPAuthNoPriv)}})
	if result, err := f.engine.Ensure(t.Context(), q, "writer"); err != nil || !result.Ready() {
		t.Fatal(err)
	}
	f.persistent = append(f.persistent, []byte("usmUser 1 3 0x80 0x72657469726564 0x72657469726564 NULL .1 0x00 .2 0x \"\"\n")...)
	if result, err := f.engine.Get(t.Context(), q, "read"); err != nil || result.RuntimeVerified {
		t.Fatal("persisted retired user certified as runtime-verified")
	}
}

func TestStoppedContainerWithPersistedUsersIsScrubbedBeforeStart(t *testing.T) {
	f := newSystemFixture(t)
	q := f.request(SNMP{Location: "public", Users: []SNMPUser{fixtureUSMUser(SNMPAuthPriv)}})
	if result, err := f.engine.Ensure(t.Context(), q, "writer"); err != nil || !result.Ready() {
		t.Fatal(err)
	}
	f.persist()
	f.running = false
	q = f.request(SNMP{Location: "public"})
	q.Revision = "2"
	if result, err := f.engine.Ensure(t.Context(), q, "writer"); err != nil || !result.Ready() {
		t.Fatal("stopped container with persisted users did not recover", err)
	}
	if f.scrubs != 1 || len(f.usm) != 0 {
		t.Fatal("stopped container resurrected a removed user")
	}
}
