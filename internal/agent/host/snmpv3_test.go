// SPDX-License-Identifier: Apache-2.0
package host

import (
	"bytes"
	"context"
	"encoding/asn1"
	"encoding/hex"
	"testing"
)

// fakeUSMAgent is an authoritative SNMPv3 engine for tests. users holds the
// credentials the agent has loaded, which may differ from the declared ones.
type fakeUSMAgent struct {
	engineID          []byte
	boots, time       int
	users             map[string]SNMPUser
	location, contact string
	tamper            string
}

func (a *fakeUSMAgent) exchange(_ context.Context, packet []byte) ([]byte, error) {
	var m snmpV3Message
	var params usmParameters
	if rest, e := asn1.Unmarshal(packet, &m); e != nil || len(rest) != 0 || m.Version != 3 {
		return nil, ErrNative
	}
	if _, e := asn1.Unmarshal(m.Security, &params); e != nil {
		return nil, ErrNative
	}
	engine := usmEngine{ID: a.engineID, Boots: a.boots, Time: a.time}
	if len(params.EngineID) == 0 {
		return a.report(m.Header.ID)
	}
	u, ok := a.users[string(params.User)]
	if !ok || !bytes.Equal(params.EngineID, a.engineID) {
		return a.report(m.Header.ID)
	}
	authKey := usmLocalizeKey(usmPasswordKey([]byte(u.AuthPassword)), a.engineID)
	var privKey []byte
	if u.SecurityLevel == SNMPAuthPriv {
		privKey = usmLocalizeKey(usmPasswordKey([]byte(u.PrivPassword)), a.engineID)[:16]
	}
	start, end, ok := usmAuthBounds(packet)
	zeroed := bytes.Clone(packet)
	clear(zeroed[start:end])
	if !ok || !bytes.Equal(usmHMAC(authKey, zeroed), packet[start:end]) {
		return a.report(m.Header.ID) // usmStatsWrongDigests
	}
	plain := m.Data.FullBytes
	if privKey != nil {
		var encrypted []byte
		if _, e := asn1.Unmarshal(m.Data.FullBytes, &encrypted); e != nil {
			return a.report(m.Header.ID)
		}
		plain, _ = usmAESCFB(privKey, usmAESIV(params.Boots, params.Time, params.Priv), encrypted, true)
	}
	var scoped snmpScopedPDU
	if _, e := asn1.Unmarshal(plain, &scoped); e != nil {
		return a.report(m.Header.ID) // usmStatsDecryptionErrors
	}
	body, _ := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: scoped.PDU.Bytes})
	var pdu snmpPDU
	if _, e := asn1.Unmarshal(body, &pdu); e != nil || len(pdu.Variables) != 2 {
		return nil, ErrNative
	}
	pdu.Variables[0].Value = asn1.RawValue{Tag: asn1.TagOctetString, Bytes: []byte(a.location)}
	pdu.Variables[1].Value = asn1.RawValue{Tag: asn1.TagOctetString, Bytes: []byte(a.contact)}
	if a.tamper == "request-id" {
		pdu.ID++
	}
	body, _ = asn1.Marshal(pdu)
	var sequence asn1.RawValue
	_, _ = asn1.Unmarshal(body, &sequence)
	response := asn1.RawValue{Class: 2, Tag: 2, IsCompound: true, Bytes: sequence.Bytes}
	if a.tamper == "plaintext" {
		privKey = nil
	}
	out, e := usmRequest(m.Header.ID, engine, u.Name, authKey, privKey, response)
	if e != nil {
		return nil, e
	}
	if a.tamper == "digest" {
		out[len(out)-1] ^= 0xff
	}
	return out, nil
}

func (a *fakeUSMAgent) report(msgID int) ([]byte, error) {
	pdu, _ := snmpGetPDU(0, nil)
	pdu.Tag = 8
	scoped, _ := asn1.Marshal(snmpScopedPDU{ContextEngineID: a.engineID, ContextName: []byte{}, PDU: pdu})
	security, _ := asn1.Marshal(usmParameters{EngineID: a.engineID, Boots: a.boots, Time: a.time, User: []byte{}, Auth: []byte{}, Priv: []byte{}})
	return asn1.Marshal(snmpV3Message{Version: 3, Header: snmpV3Header{ID: msgID, MaxSize: 65507, Flags: []byte{0}, SecurityModel: usmSecurityModel}, Security: security, Data: asn1.RawValue{FullBytes: scoped}})
}

func fixtureUSMUser(level string) SNMPUser {
	u := SNMPUser{Name: "monitor", SecurityLevel: level, AuthProtocol: "SHA", AuthPassword: Credential("auth-fixture-1")}
	if level == SNMPAuthPriv {
		u.PrivProtocol, u.PrivPassword = "AES", Credential("priv-fixture-1")
	}
	return u
}

func TestUSMKeyLocalizationMatchesRFC3414(t *testing.T) {
	engineID, _ := hex.DecodeString("000000000000000000000002")
	ku := usmPasswordKey([]byte("maplesyrup"))
	if hex.EncodeToString(ku) != "9fb5cc0381497b3793528939ff788d5d79145211" {
		t.Fatalf("password to key: %x", ku)
	}
	if kul := usmLocalizeKey(ku, engineID); hex.EncodeToString(kul) != "6695febc9288e36282235fc7151f128497b38f3f" {
		t.Fatalf("localized key: %x", kul)
	}
}

func TestUSMAESCFBMatchesNISTVector(t *testing.T) {
	key, _ := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	iv, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	// One full block plus a partial block exercises the RFC 3826 tail handling.
	plain, _ := hex.DecodeString("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c")
	encrypted, err := usmAESCFB(key, iv, plain, false)
	if err != nil || hex.EncodeToString(encrypted) != "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93f" {
		t.Fatalf("encrypt: %x", encrypted)
	}
	decrypted, err := usmAESCFB(key, iv, encrypted, true)
	if err != nil || !bytes.Equal(decrypted, plain) {
		t.Fatal("decrypt did not invert encrypt")
	}
}

func TestSNMPv3ReadbackProvesLoadedCredentials(t *testing.T) {
	s := SNMP{Location: "fixture-rack", Contact: "fixture-contact"}
	for _, tc := range []struct {
		name   string
		level  string
		mutate func(*fakeUSMAgent)
		ok     bool
	}{
		{"authPriv", SNMPAuthPriv, nil, true},
		{"authNoPriv", SNMPAuthNoPriv, nil, true},
		{"stale-auth", SNMPAuthPriv, func(a *fakeUSMAgent) {
			u := a.users["monitor"]
			u.AuthPassword = "auth-retired"
			a.users["monitor"] = u
		}, false},
		{"stale-priv", SNMPAuthPriv, func(a *fakeUSMAgent) {
			u := a.users["monitor"]
			u.PrivPassword = "priv-retired"
			a.users["monitor"] = u
		}, false},
		{"unknown-user", SNMPAuthPriv, func(a *fakeUSMAgent) { delete(a.users, "monitor") }, false},
		{"digest", SNMPAuthPriv, func(a *fakeUSMAgent) { a.tamper = "digest" }, false},
		{"downgraded", SNMPAuthPriv, func(a *fakeUSMAgent) { a.tamper = "plaintext" }, false},
		{"request-id", SNMPAuthNoPriv, func(a *fakeUSMAgent) { a.tamper = "request-id" }, false},
		{"location", SNMPAuthPriv, func(a *fakeUSMAgent) { a.location = "wrong-rack" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := fixtureUSMUser(tc.level)
			agent := &fakeUSMAgent{engineID: []byte{0x80, 0, 0x1f, 0x88, 0x80, 1, 2, 3, 4}, boots: 7, time: 1234, users: map[string]SNMPUser{u.Name: u}, location: s.Location, contact: s.Contact}
			if tc.mutate != nil {
				tc.mutate(agent)
			}
			if err := probeSNMPv3Exchange(context.Background(), s, u, agent.exchange); (err == nil) != tc.ok {
				t.Fatalf("SNMPv3 proof incorrect: %v", err)
			}
		})
	}
}

func TestSNMPUserValidation(t *testing.T) {
	valid := fixtureUSMUser(SNMPAuthPriv)
	if err := ValidateSystem(System{SNMP: &SNMP{Location: "rack", Users: []SNMPUser{valid, fixtureUSMUser(SNMPAuthNoPriv)}}}); err != ErrInvalid {
		t.Fatal("duplicate user names accepted")
	}
	if err := ValidateSystem(System{SNMP: &SNMP{Location: "rack", Users: []SNMPUser{valid}}}); err != nil {
		t.Fatal(err)
	}
	if got := valid.AuthPassword.String(); got != "[redacted]" {
		t.Fatal("passphrase formatting not redacted")
	}
	for name, mutate := range map[string]func(*SNMPUser){
		"short-name":       func(u *SNMPUser) { u.Name = "abc" },
		"name-space":       func(u *SNMPUser) { u.Name = "mon itor" },
		"short-auth":       func(u *SNMPUser) { u.AuthPassword = "short" },
		"auth-newline":     func(u *SNMPUser) { u.AuthPassword = "auth-fixture\nrwuser x" },
		"auth-quote":       func(u *SNMPUser) { u.AuthPassword = `auth"fixture` },
		"auth-colon":       func(u *SNMPUser) { u.AuthPassword = "auth:fixture" },
		"auth-md5":         func(u *SNMPUser) { u.AuthProtocol = "MD5" },
		"priv-des":         func(u *SNMPUser) { u.PrivProtocol = "DES" },
		"priv-missing":     func(u *SNMPUser) { u.PrivPassword = "" },
		"noauth":           func(u *SNMPUser) { u.SecurityLevel = "noAuthNoPriv" },
		"authnopriv-extra": func(u *SNMPUser) { u.SecurityLevel = SNMPAuthNoPriv },
	} {
		u := valid
		mutate(&u)
		if ValidateSystem(System{SNMP: &SNMP{Location: "rack", Users: []SNMPUser{u}}}) != ErrInvalid {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestSNMPUsersOwnNativeTable(t *testing.T) {
	u := fixtureUSMUser(SNMPAuthPriv)
	plain := fixtureUSMUser(SNMPAuthNoPriv)
	plain.Name = "auditor"
	db := Database{"SNMP_USER": {"retired": {"SNMP_USER_TYPE": "Priv", "SNMP_USER_PERMISSION": "RO", "SNMP_USER_AUTH_TYPE": "SHA", "SNMP_USER_AUTH_PASSWORD": "old-fixture-1", "SNMP_USER_ENCRYPTION_TYPE": "AES", "SNMP_USER_ENCRYPTION_PASSWORD": "old-fixture-2"}}}
	after, err := systemDatabase(db, System{SNMP: &SNMP{Location: "rack", Users: []SNMPUser{u, plain}}})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]map[string]string{
		"monitor": {"SNMP_USER_TYPE": "Priv", "SNMP_USER_PERMISSION": "RO", "SNMP_USER_AUTH_TYPE": "SHA", "SNMP_USER_AUTH_PASSWORD": "auth-fixture-1", "SNMP_USER_ENCRYPTION_TYPE": "AES", "SNMP_USER_ENCRYPTION_PASSWORD": "priv-fixture-1"},
		"auditor": {"SNMP_USER_TYPE": "AuthNoPriv", "SNMP_USER_PERMISSION": "RO", "SNMP_USER_AUTH_TYPE": "SHA", "SNMP_USER_AUTH_PASSWORD": "auth-fixture-1", "SNMP_USER_ENCRYPTION_TYPE": "", "SNMP_USER_ENCRYPTION_PASSWORD": ""},
	}
	if !scopedEqual(after, Database{"SNMP_USER": want}, "SNMP_USER") {
		t.Fatalf("unexpected SNMP_USER rows: %v", after["SNMP_USER"])
	}
	if after, err = systemDatabase(db, System{SNMP: &SNMP{Location: "rack"}}); err != nil || len(after["SNMP_USER"]) != 0 {
		t.Fatal("omitted users must remove retired native users")
	}
	for _, foreign := range []map[string]string{
		{"SNMP_USER_TYPE": "Priv", "SNMP_USER_PERMISSION": "RW"},
		{"SNMP_USER_TYPE": "Priv", "SNMP_USER_PERMISSION": "RO", "SNMP_USER_CONTEXT": "x"},
	} {
		if _, err = systemDatabase(Database{"SNMP_USER": {"foreign": foreign}}, System{SNMP: &SNMP{Location: "rack"}}); err != ErrNative {
			t.Fatal("unadoptable native user replaced")
		}
	}
}

func TestPersistedUSMUsersAreScrubbedOnly(t *testing.T) {
	data := []byte("#\n# net-snmp persistent data file.\n#\nusmUser 1 3 0x80001f88 0x6d6f6e69746f72 0x6d6f6e69746f72 NULL .1.3.6.1.6.3.10.1.1.3 0xaa .1.3.6.1.6.3.10.1.2.4 0xbb \"\"\nsetserialno 1\nengineBoots 4\noldEngineID 0x80001f88\n")
	scrubbed := scrubUSMUsers(data)
	if bytes.Contains(scrubbed, []byte("usmUser")) || !bytes.Contains(scrubbed, []byte("engineBoots 4\noldEngineID 0x80001f88\n")) || !bytes.HasPrefix(scrubbed, []byte("#\n# net-snmp")) {
		t.Fatalf("scrub changed unrelated state: %q", scrubbed)
	}
	if (snmpPersistent{header: nil, data: data}).hasUsers() {
		t.Fatal("absent persistent file reported users")
	}
}
