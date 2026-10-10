// SPDX-License-Identifier: Apache-2.0
package host

import (
	"context"
	"crypto/rand"
	"encoding/asn1"
	"encoding/binary"
	"net"
	"strings"
	"time"
)

type snmpVariable struct {
	OID   asn1.ObjectIdentifier
	Value asn1.RawValue
}
type snmpPDU struct {
	ID        int
	Error     int
	Index     int
	Variables []snmpVariable
}
type snmpMessage struct {
	Version   int
	Community []byte
	PDU       asn1.RawValue
}

var snmpSystemOIDs = []asn1.ObjectIdentifier{{1, 3, 6, 1, 2, 1, 1, 6, 0}, {1, 3, 6, 1, 2, 1, 1, 4, 0}}

func snmpUDPExchange(address string) func(context.Context, []byte) ([]byte, error) {
	return func(ctx context.Context, packet []byte) ([]byte, error) {
		d := net.Dialer{Timeout: 2 * time.Second}
		conn, e := d.DialContext(ctx, "udp", address)
		if e != nil {
			return nil, ErrNative
		}
		defer func() { _ = conn.Close() }()
		deadline := time.Now().Add(2 * time.Second)
		if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
			deadline = dl
		}
		if conn.SetDeadline(deadline) != nil {
			return nil, ErrNative
		}
		if _, e = conn.Write(packet); e != nil {
			return nil, ErrNative
		}
		data := make([]byte, 4096)
		size, e := conn.Read(data)
		if e != nil {
			return nil, ErrNative
		}
		return data[:size], nil
	}
}
func probeSNMP(ctx context.Context, s SNMP, address string) error {
	return probeSNMPExchange(ctx, s, snmpUDPExchange(address))
}
func snmpRandomID() (int, error) {
	var nonce [4]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return 0, ErrNative
	}
	return int(binary.BigEndian.Uint32(nonce[:]) & 0x7fffffff), nil
}

// snmpGetPDU returns a context-tagged GetRequest (tag 0) for oids.
func snmpGetPDU(id int, oids []asn1.ObjectIdentifier) (asn1.RawValue, error) {
	pdu := snmpPDU{ID: id}
	for _, oid := range oids {
		pdu.Variables = append(pdu.Variables, snmpVariable{OID: oid, Value: asn1.RawValue{Tag: asn1.TagNull}})
	}
	body, e := asn1.Marshal(pdu)
	if e != nil {
		return asn1.RawValue{}, ErrNative
	}
	var sequence asn1.RawValue
	if _, e = asn1.Unmarshal(body, &sequence); e != nil {
		return asn1.RawValue{}, ErrNative
	}
	return asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: sequence.Bytes}, nil
}

// snmpCheckSystemResponse accepts only a Response PDU (tag 2) for request id
// that returns the declared location and, when owned, contact.
func snmpCheckSystemResponse(pdu asn1.RawValue, id int, s SNMP) error {
	if pdu.Class != 2 || pdu.Tag != 2 {
		return ErrNative
	}
	body, e := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: pdu.Bytes})
	if e != nil {
		return ErrNative
	}
	var result snmpPDU
	rest, e := asn1.Unmarshal(body, &result)
	if e != nil || len(rest) != 0 || result.ID != id || result.Error != 0 || len(result.Variables) != len(snmpSystemOIDs) {
		return ErrNative
	}
	for i, v := range result.Variables {
		if !v.OID.Equal(snmpSystemOIDs[i]) || v.Value.Tag != asn1.TagOctetString || v.Value.Class != 0 {
			return ErrNative
		}
	}
	if string(result.Variables[0].Value.Bytes) != s.Location || (s.Contact != "" && strings.TrimSpace(string(result.Variables[1].Value.Bytes)) != strings.TrimSpace(s.Contact)) {
		return ErrNative
	}
	return nil
}
func probeSNMPExchange(ctx context.Context, s SNMP, exchange func(context.Context, []byte) ([]byte, error)) error {
	id, e := snmpRandomID()
	if e != nil {
		return e
	}
	pdu, e := snmpGetPDU(id, snmpSystemOIDs)
	if e != nil {
		return e
	}
	packet, e := asn1.Marshal(snmpMessage{Version: 1, Community: []byte(s.Community), PDU: pdu})
	if e != nil {
		return ErrNative
	}
	data, e := exchange(ctx, packet)
	if e != nil {
		return ErrNative
	}
	var response snmpMessage
	rest, e := asn1.Unmarshal(data, &response)
	if e != nil || len(rest) != 0 || response.Version != 1 || string(response.Community) != string(s.Community) {
		return ErrNative
	}
	return snmpCheckSystemResponse(response.PDU, id, s)
}
