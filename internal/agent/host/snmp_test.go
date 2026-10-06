// SPDX-License-Identifier: Apache-2.0
package host

import (
	"context"
	"encoding/asn1"
	"testing"
)

func TestSNMPReadbackRejectsStaleOrWrongCredentialResponse(t *testing.T) {
	for _, mode := range []string{"valid", "stale", "credential", "location"} {
		err := probeSNMPExchange(context.Background(), SNMP{Location: "fixture-rack", Community: Credential("fixture-only")}, func(_ context.Context, packet []byte) ([]byte, error) {
			var req snmpMessage
			if _, e := asn1.Unmarshal(packet, &req); e != nil {
				t.Fatal("invalid request frame")
			}
			body, _ := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: req.PDU.Bytes})
			var pdu snmpPDU
			if _, e := asn1.Unmarshal(body, &pdu); e != nil {
				t.Fatal("invalid request PDU")
			}
			pdu.Variables[0].Value = asn1.RawValue{Tag: asn1.TagOctetString, Bytes: []byte("fixture-rack")}
			pdu.Variables[1].Value = asn1.RawValue{Tag: asn1.TagOctetString, Bytes: []byte("fixture-contact")}
			if mode == "stale" {
				pdu.ID++
			}
			if mode == "credential" {
				req.Community = []byte("wrong-fixture")
			}
			if mode == "location" {
				pdu.Variables[0].Value.Bytes = []byte("wrong-rack")
			}
			body, _ = asn1.Marshal(pdu)
			var sequence asn1.RawValue
			_, _ = asn1.Unmarshal(body, &sequence)
			return asn1.Marshal(snmpMessage{Version: 1, Community: req.Community, PDU: asn1.RawValue{Class: 2, Tag: 2, IsCompound: true, Bytes: sequence.Bytes}})
		})
		if (err == nil) != (mode == "valid") {
			t.Fatal("SNMP response transaction proof incorrect")
		}
	}
}
