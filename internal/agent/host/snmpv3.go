// SPDX-License-Identifier: Apache-2.0
package host

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/asn1"
	"encoding/binary"
)

// Minimal RFC 3412/3414/3826 USM client: engine discovery followed by one
// authenticated (and, for authPriv, AES-128-CFB encrypted) GET. It proves the
// running agent loaded each declared user with the declared passphrases.
// Keys and passphrases stay in memory; nothing is logged or persisted.

const (
	usmFlagAuth       = 0x01
	usmFlagPriv       = 0x02
	usmFlagReportable = 0x04
	usmSecurityModel  = 3
	usmAuthLength     = 12
)

type snmpV3Header struct {
	ID            int
	MaxSize       int
	Flags         []byte
	SecurityModel int
}
type snmpV3Message struct {
	Version  int
	Header   snmpV3Header
	Security []byte
	Data     asn1.RawValue
}
type usmParameters struct {
	EngineID []byte
	Boots    int
	Time     int
	User     []byte
	Auth     []byte
	Priv     []byte
}
type snmpScopedPDU struct {
	ContextEngineID []byte
	ContextName     []byte
	PDU             asn1.RawValue
}

type usmEngine struct {
	ID          []byte
	Boots, Time int
}

func probeSNMPv3(ctx context.Context, s SNMP, u SNMPUser, address string) error {
	return probeSNMPv3Exchange(ctx, s, u, snmpUDPExchange(address))
}
func probeSNMPv3Exchange(ctx context.Context, s SNMP, u SNMPUser, exchange func(context.Context, []byte) ([]byte, error)) error {
	if validateSNMPUsers([]SNMPUser{u}) != nil {
		return ErrInvalid
	}
	engine, e := usmDiscover(ctx, exchange)
	if e != nil {
		return e
	}
	authKey := usmLocalizeKey(usmPasswordKey([]byte(u.AuthPassword)), engine.ID)
	var privKey []byte
	if u.SecurityLevel == SNMPAuthPriv {
		privKey = usmLocalizeKey(usmPasswordKey([]byte(u.PrivPassword)), engine.ID)[:16]
	}
	msgID, e := snmpRandomID()
	if e != nil {
		return e
	}
	requestID, e := snmpRandomID()
	if e != nil {
		return e
	}
	pdu, e := snmpGetPDU(requestID, snmpSystemOIDs)
	if e != nil {
		return e
	}
	packet, e := usmRequest(msgID, engine, u.Name, authKey, privKey, pdu)
	if e != nil {
		return e
	}
	data, e := exchange(ctx, packet)
	if e != nil {
		return ErrNative
	}
	response, e := usmResponse(data, msgID, engine, u.Name, authKey, privKey)
	if e != nil {
		return e
	}
	return snmpCheckSystemResponse(response.PDU, requestID, s)
}

// usmDiscover sends an unauthenticated, reportable empty GET; the agent answers
// with a Report carrying its authoritative engine ID, boots and time.
func usmDiscover(ctx context.Context, exchange func(context.Context, []byte) ([]byte, error)) (usmEngine, error) {
	var engine usmEngine
	msgID, e := snmpRandomID()
	if e != nil {
		return engine, e
	}
	requestID, e := snmpRandomID()
	if e != nil {
		return engine, e
	}
	pdu, e := snmpGetPDU(requestID, nil)
	if e != nil {
		return engine, e
	}
	scoped, e := asn1.Marshal(snmpScopedPDU{ContextEngineID: []byte{}, ContextName: []byte{}, PDU: pdu})
	if e != nil {
		return engine, ErrNative
	}
	security, e := asn1.Marshal(usmParameters{EngineID: []byte{}, User: []byte{}, Auth: []byte{}, Priv: []byte{}})
	if e != nil {
		return engine, ErrNative
	}
	packet, e := asn1.Marshal(snmpV3Message{Version: 3, Header: snmpV3Header{ID: msgID, MaxSize: 65507, Flags: []byte{usmFlagReportable}, SecurityModel: usmSecurityModel}, Security: security, Data: asn1.RawValue{FullBytes: scoped}})
	if e != nil {
		return engine, ErrNative
	}
	data, e := exchange(ctx, packet)
	if e != nil {
		return engine, ErrNative
	}
	m, params, e := usmDecode(data, msgID)
	if e != nil || len(m.Header.Flags) != 1 || m.Header.Flags[0]&(usmFlagAuth|usmFlagPriv) != 0 {
		return engine, ErrNative
	}
	var report snmpScopedPDU
	if rest, e := asn1.Unmarshal(m.Data.FullBytes, &report); e != nil || len(rest) != 0 || report.PDU.Class != 2 || report.PDU.Tag != 8 {
		return engine, ErrNative
	}
	if len(params.EngineID) < 5 || len(params.EngineID) > 32 || params.Boots < 0 || params.Time < 0 {
		return engine, ErrNative
	}
	return usmEngine{ID: params.EngineID, Boots: params.Boots, Time: params.Time}, nil
}

func usmDecode(data []byte, msgID int) (snmpV3Message, usmParameters, error) {
	var m snmpV3Message
	var params usmParameters
	rest, e := asn1.Unmarshal(data, &m)
	if e != nil || len(rest) != 0 || m.Version != 3 || m.Header.ID != msgID || m.Header.SecurityModel != usmSecurityModel {
		return m, params, ErrNative
	}
	if rest, e = asn1.Unmarshal(m.Security, &params); e != nil || len(rest) != 0 {
		return m, params, ErrNative
	}
	return m, params, nil
}

func usmRequest(msgID int, engine usmEngine, user string, authKey, privKey []byte, pdu asn1.RawValue) ([]byte, error) {
	scoped, e := asn1.Marshal(snmpScopedPDU{ContextEngineID: engine.ID, ContextName: []byte{}, PDU: pdu})
	if e != nil {
		return nil, ErrNative
	}
	flags := byte(usmFlagAuth | usmFlagReportable)
	salt := []byte{}
	data := scoped
	if privKey != nil {
		flags |= usmFlagPriv
		salt = make([]byte, 8)
		if _, e = rand.Read(salt); e != nil {
			return nil, ErrNative
		}
		encrypted, e := usmAESCFB(privKey, usmAESIV(engine.Boots, engine.Time, salt), scoped, false)
		if e != nil {
			return nil, e
		}
		if data, e = asn1.Marshal(encrypted); e != nil {
			return nil, ErrNative
		}
	}
	security, e := asn1.Marshal(usmParameters{EngineID: engine.ID, Boots: engine.Boots, Time: engine.Time, User: []byte(user), Auth: make([]byte, usmAuthLength), Priv: salt})
	if e != nil {
		return nil, ErrNative
	}
	packet, e := asn1.Marshal(snmpV3Message{Version: 3, Header: snmpV3Header{ID: msgID, MaxSize: 65507, Flags: []byte{flags}, SecurityModel: usmSecurityModel}, Security: security, Data: asn1.RawValue{FullBytes: data}})
	if e != nil {
		return nil, ErrNative
	}
	start, end, ok := usmAuthBounds(packet)
	if !ok || end-start != usmAuthLength {
		return nil, ErrNative
	}
	copy(packet[start:end], usmHMAC(authKey, packet))
	return packet, nil
}

// usmResponse accepts only an authenticated (and encrypted, for authPriv)
// response from the discovered engine for the requesting user.
func usmResponse(data []byte, msgID int, engine usmEngine, user string, authKey, privKey []byte) (snmpScopedPDU, error) {
	var scoped snmpScopedPDU
	m, params, e := usmDecode(data, msgID)
	if e != nil || len(m.Header.Flags) != 1 || m.Header.Flags[0]&usmFlagAuth == 0 || (privKey != nil) != (m.Header.Flags[0]&usmFlagPriv != 0) {
		return scoped, ErrNative
	}
	if !bytes.Equal(params.EngineID, engine.ID) || string(params.User) != user || len(params.Auth) != usmAuthLength {
		return scoped, ErrNative
	}
	start, end, ok := usmAuthBounds(data)
	if !ok || end-start != usmAuthLength {
		return scoped, ErrNative
	}
	zeroed := bytes.Clone(data)
	clear(zeroed[start:end])
	if !hmac.Equal(usmHMAC(authKey, zeroed), data[start:end]) {
		return scoped, ErrNative
	}
	plain := m.Data.FullBytes
	if privKey != nil {
		var encrypted []byte
		if rest, e := asn1.Unmarshal(m.Data.FullBytes, &encrypted); e != nil || len(rest) != 0 || len(params.Priv) != 8 {
			return scoped, ErrNative
		}
		if plain, e = usmAESCFB(privKey, usmAESIV(params.Boots, params.Time, params.Priv), encrypted, true); e != nil {
			return scoped, e
		}
	}
	// Decrypted scoped PDUs may carry block padding from some agents; only the
	// leading element is meaningful. Plaintext must be exact.
	rest, e := asn1.Unmarshal(plain, &scoped)
	if e != nil || (privKey == nil && len(rest) != 0) || !bytes.Equal(scoped.ContextEngineID, engine.ID) {
		return scoped, ErrNative
	}
	return scoped, nil
}

// usmAuthBounds walks the BER structure to msgAuthenticationParameters, so
// authentication covers the exact received encoding rather than a re-encoding.
func usmAuthBounds(msg []byte) (int, int, bool) {
	start, end, ok := berElement(msg, 0)
	if !ok || msg[0] != 0x30 || end != len(msg) {
		return 0, 0, false
	}
	off := start
	for range 2 { // msgVersion, msgGlobalData
		if _, off, ok = berElement(msg, off); !ok {
			return 0, 0, false
		}
	}
	if off >= len(msg) || msg[off] != 0x04 {
		return 0, 0, false
	}
	start, end, ok = berElement(msg, off)
	if !ok || start >= end || msg[start] != 0x30 {
		return 0, 0, false
	}
	inner, innerEnd, ok := berElement(msg, start)
	if !ok || innerEnd != end {
		return 0, 0, false
	}
	off = inner
	for range 4 { // engine ID, boots, time, user name
		if _, off, ok = berElement(msg, off); !ok || off > innerEnd {
			return 0, 0, false
		}
	}
	if off >= innerEnd || msg[off] != 0x04 {
		return 0, 0, false
	}
	start, end, ok = berElement(msg, off)
	return start, end, ok && end <= innerEnd
}

// berElement returns the content bounds of the low-tag-number TLV at off.
func berElement(b []byte, off int) (int, int, bool) {
	if off < 0 || off+2 > len(b) || b[off]&0x1f == 0x1f {
		return 0, 0, false
	}
	length, start := int(b[off+1]), off+2
	if length&0x80 != 0 {
		n := length & 0x7f
		if n == 0 || n > 3 || start+n > len(b) {
			return 0, 0, false
		}
		length = 0
		for _, c := range b[start : start+n] {
			length = length<<8 | int(c)
		}
		start += n
	}
	end := start + length
	return start, end, end <= len(b)
}

// usmPasswordKey is the RFC 3414 A.2.2 password-to-key transform for SHA.
func usmPasswordKey(password []byte) []byte {
	h := sha1.New()
	var block [64]byte
	for i, n := 0, 0; n < 1<<20; n += len(block) {
		for j := range block {
			block[j] = password[i%len(password)]
			i++
		}
		h.Write(block[:])
	}
	return h.Sum(nil)
}
func usmLocalizeKey(ku, engineID []byte) []byte {
	h := sha1.New()
	h.Write(ku)
	h.Write(engineID)
	h.Write(ku)
	return h.Sum(nil)
}
func usmHMAC(key, msg []byte) []byte {
	mac := hmac.New(sha1.New, key)
	mac.Write(msg)
	return mac.Sum(nil)[:usmAuthLength]
}

// usmAESIV is the RFC 3826 IV: engine boots, engine time, then the 64-bit salt.
func usmAESIV(boots, engineTime int, salt []byte) []byte {
	iv := make([]byte, 16)
	binary.BigEndian.PutUint32(iv[0:4], uint32(boots))
	binary.BigEndian.PutUint32(iv[4:8], uint32(engineTime))
	copy(iv[8:], salt)
	return iv
}

// usmAESCFB implements full-block (128-bit) CFB with a final partial block.
func usmAESCFB(key, iv, in []byte, decrypt bool) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil || len(iv) != aes.BlockSize {
		return nil, ErrNative
	}
	out := make([]byte, len(in))
	register := bytes.Clone(iv)
	stream := make([]byte, aes.BlockSize)
	for i := 0; i < len(in); i += aes.BlockSize {
		block.Encrypt(stream, register)
		n := min(aes.BlockSize, len(in)-i)
		for j := range n {
			out[i+j] = in[i+j] ^ stream[j]
		}
		if decrypt {
			copy(register, in[i:i+n])
		} else {
			copy(register, out[i:i+n])
		}
	}
	return out, nil
}
