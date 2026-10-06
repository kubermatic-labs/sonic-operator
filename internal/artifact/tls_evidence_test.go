// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ironcore-dev/sonic-operator/internal/agent/transport"
)

func signedIdentity(t *testing.T, ca Bundle, server bool) ([]byte, []byte) {
	t.Helper()
	block, _ := pem.Decode(ca.Files[0].Data)
	issuer, _ := x509.ParseCertificate(block.Bytes)
	keyBlock, _ := pem.Decode(ca.Files[1].Data)
	signer, _ := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	usage := x509.ExtKeyUsageClientAuth
	if server {
		usage = x509.ExtKeyUsageServerAuth
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), DNSNames: []string{"switch"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}
func TestEqualDiskTLSAdoptionCannotCertifyStillLoadedA(t *testing.T) {
	e, root := testEngine(t)
	a := certificateBundle(t)
	clientCA := certificateBundle(t)
	certB, keyB := signedIdentity(t, a, true)
	b := a
	b.Files = append([]File(nil), a.Files...)
	b.Files[0].Data = certB
	b.Files[1].Data = keyB
	b.Files[2].Data = clientCA.Files[2].Data
	for i := range b.Files {
		b.Files[i].SHA256 = Digest(b.Files[i].Data)
	}
	paths := map[string]string{}
	write := func(bundle Bundle) {
		for _, f := range bundle.Files {
			p, _, _ := Destination(f.Slot)
			p = filepath.Join(root, p)
			paths[f.Slot] = p
			if err := os.WriteFile(p, f.Data, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	write(a)
	cfgA, proofA, err := transport.LoadTLSConfigWithEvidence(paths["AgentCertificate"], paths["AgentKey"], paths["AgentCA"])
	if err != nil {
		t.Fatal(err)
	}
	cfgA.ClientCAs = cfgA.RootCAs
	cfgA.ClientAuth = tls.RequireAndVerifyClientCert
	clientCertA, clientKeyA := signedIdentity(t, a, false)
	clientCertB, clientKeyB := signedIdentity(t, clientCA, false)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(a.Files[0].Data)
	client := func(cert, key []byte) *tls.Config {
		pair, _ := tls.X509KeyPair(cert, key)
		return &tls.Config{RootCAs: roots, ServerName: "switch", Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	}
	start := func(cfg *tls.Config) net.Listener {
		listener, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			for {
				connection, err := listener.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) { defer c.Close(); c.(*tls.Conn).Handshake() }(connection)
			}
		}()
		return listener
	}
	listener := start(cfgA)
	defer func() { listener.Close() }()
	write(b)
	proofA.PID = 1
	proofA.BootID = "boot"
	proofA.StartTicks = "one"
	if loadedTLSMatches(*proofA, 1, "boot", "one", b.Files[0].SHA256, b.Files[2].SHA256) {
		t.Fatal("disk B was mistaken for loaded B")
	}
	e.PlanTLS = func(Bundle) (bool, error) { return true, nil }
	e.RecoveryInput = func(slot string) ([]byte, os.FileMode, bool, error) {
		for _, f := range a.Files {
			if f.Slot == slot {
				return f.Data, 0600, true, nil
			}
		}
		return nil, 0, false, nil
	}
	activeClient := client(clientCertA, clientKeyA)
	expectedBlock, _ := pem.Decode(certB)
	e.Health = func() error {
		connection, err := tls.Dial("tcp", listener.Addr().String(), activeClient)
		if err != nil {
			return err
		}
		defer connection.Close()
		if Digest(connection.ConnectionState().PeerCertificates[0].Raw) != Digest(expectedBlock.Bytes) {
			return os.ErrInvalid
		}
		return nil
	}
	now := time.Now()
	completeAgentFixture(t, e, &b)
	r, err := e.Ensure(b, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Tick(now); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Confirm(b, r.Token, now); err == nil {
		t.Fatal("still-loaded certificate A confirmed as B")
	}
	cfgB, proofB, err := transport.LoadTLSConfigWithEvidence(paths["AgentCertificate"], paths["AgentKey"], paths["AgentCA"])
	if err != nil {
		t.Fatal(err)
	}
	cfgB.ClientCAs = cfgB.RootCAs
	cfgB.ClientAuth = tls.RequireAndVerifyClientCert
	listener.Close()
	listener = start(cfgB)
	activeClient = client(clientCertB, clientKeyB)
	proofB.PID = 2
	proofB.BootID = "boot"
	proofB.StartTicks = "two"
	if !loadedTLSMatches(*proofB, 2, "boot", "two", b.Files[0].SHA256, b.Files[2].SHA256) {
		t.Fatal("actual new loader identity not verified")
	}
	if _, err := e.Confirm(b, r.Token, now); err != nil {
		t.Fatal(err)
	}
}
