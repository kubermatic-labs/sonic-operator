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

func probeSNMP(ctx context.Context, s SNMP, address string) error {
	return probeSNMPExchange(ctx, s, func(ctx context.Context, packet []byte) ([]byte, error) {
		d := net.Dialer{Timeout: 2 * time.Second}
		conn, e := d.DialContext(ctx, "udp", address)
		if e != nil {
			return nil, ErrNative
		}
		defer conn.Close()
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
	})
}
func probeSNMPExchange(ctx context.Context, s SNMP, exchange func(context.Context, []byte) ([]byte, error)) error {
	var nonce [4]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return ErrNative
	}
	id := int(binary.BigEndian.Uint32(nonce[:]) & 0x7fffffff)
	oids := []asn1.ObjectIdentifier{{1, 3, 6, 1, 2, 1, 1, 6, 0}, {1, 3, 6, 1, 2, 1, 1, 4, 0}}
	pdu := snmpPDU{ID: id}
	for _, oid := range oids {
		pdu.Variables = append(pdu.Variables, snmpVariable{OID: oid, Value: asn1.RawValue{Tag: asn1.TagNull}})
	}
	body, e := asn1.Marshal(pdu)
	if e != nil {
		return ErrNative
	}
	var sequence asn1.RawValue
	if _, e = asn1.Unmarshal(body, &sequence); e != nil {
		return ErrNative
	}
	packet, e := asn1.Marshal(snmpMessage{Version: 1, Community: []byte(s.Community), PDU: asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: sequence.Bytes}})
	if e != nil {
		return ErrNative
	}
	data, e := exchange(ctx, packet)
	if e != nil {
		return ErrNative
	}
	var response snmpMessage
	rest, e := asn1.Unmarshal(data, &response)
	if e != nil || len(rest) != 0 || response.Version != 1 || string(response.Community) != string(s.Community) || response.PDU.Class != 2 || response.PDU.Tag != 2 {
		return ErrNative
	}
	body, e = asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: response.PDU.Bytes})
	if e != nil {
		return ErrNative
	}
	var result snmpPDU
	rest, e = asn1.Unmarshal(body, &result)
	if e != nil || len(rest) != 0 || result.ID != id || result.Error != 0 || len(result.Variables) != 2 {
		return ErrNative
	}
	for i, v := range result.Variables {
		if !v.OID.Equal(oids[i]) || v.Value.Tag != asn1.TagOctetString || v.Value.Class != 0 {
			return ErrNative
		}
	}
	if string(result.Variables[0].Value.Bytes) != s.Location || (s.Contact != "" && strings.TrimSpace(string(result.Variables[1].Value.Bytes)) != strings.TrimSpace(s.Contact)) {
		return ErrNative
	}
	return nil
}
