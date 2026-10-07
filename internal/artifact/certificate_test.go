// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func certificateBundle(t *testing.T) Bundle {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "switch"}, DNSNames: []string{"switch"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	crt := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	secret := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	b := testBundle()
	b.Files = nil
	b.Activation = "AgentRestart"
	for _, f := range []File{{Slot: "AgentCertificate", Data: crt}, {Slot: "AgentKey", Data: secret}, {Slot: "AgentCA", Data: crt}} {
		f.SHA256 = Digest(f.Data)
		b.Files = append(b.Files, f)
	}
	return b
}
func TestCertificateRenewalRollbackAndPrivacy(t *testing.T) {
	e, root := testEngine(t)
	b := certificateBundle(t)
	completeAgentFixture(t, e, &b)
	now := time.Now()
	r, err := e.Ensure(b, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Tick(now); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Confirm(b, r.Token, now); err != nil {
		t.Fatal(err)
	}
	next := certificateBundle(t)
	completeAgentFixture(t, e, &next)
	next.Generation = 2
	r, err = e.Ensure(next, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Tick(now); err != nil {
		t.Fatal(err)
	}
	journal, err := os.ReadFile(filepath.Join(root, "host/artifacts/journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range next.Files {
		if bytes.Contains(journal, file.Data) || bytes.Contains(journal, []byte("PRIVATE KEY")) {
			t.Fatal("secret material in journal")
		}
	}
	if err := e.Tick(now.Add(6 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, "etc/sonic-operator-agent/tls.key"))
	if err != nil || !bytes.Equal(got, b.Files[1].Data) {
		t.Fatal("renewal failed to recover old key")
	}
	if _, err := e.Confirm(next, r.Token, now); err == nil {
		t.Fatal("confirmed expired renewal")
	}
}
func TestInstallModesIgnoreSupervisorUmask(t *testing.T) {
	previous := syscall.Umask(0077)
	defer syscall.Umask(previous)
	e, root := testEngine(t)
	b := testBundle()
	now := time.Now()
	if _, err := e.Ensure(b, now); err != nil {
		t.Fatal(err)
	}
	if err := e.Tick(now); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(root, "usr/share/sonic/device/test/platform.json"))
	if err != nil || info.Mode().Perm() != 0644 {
		t.Fatalf("wrong installed mode: %v %v", info, err)
	}
}

func TestFailedRenewalRetainsPreviousBootManifest(t *testing.T) {
	e, root := testEngine(t)
	boot := "one"
	e.BootID = func() string { return boot }
	b := certificateBundle(t)
	completeAgentFixture(t, e, &b)
	now := time.Now()
	r, err := e.Ensure(b, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Tick(now); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Confirm(b, r.Token, now); err != nil {
		t.Fatal(err)
	}
	next := certificateBundle(t)
	completeAgentFixture(t, e, &next)
	next.Generation = 2
	if _, err := e.Ensure(next, now); err != nil {
		t.Fatal(err)
	}
	if err := e.Tick(now); err != nil {
		t.Fatal(err)
	}
	if err := e.Tick(now.Add(6 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, "etc/sonic-operator-agent/tls.key")
	_ = os.Remove(p)
	boot = "two"
	if err := e.RestoreBoot(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(p)
	if err != nil || !bytes.Equal(got, b.Files[1].Data) {
		t.Fatal("failed update discarded confirmed boot manifest")
	}
}

func TestCertificateCandidateIncludesIntermediateChain(t *testing.T) {
	var certificates [][]byte
	var parent *x509.Certificate
	var signer *ecdsa.PrivateKey
	var leafKey []byte
	for i := range 3 {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)), Subject: pkix.Name{CommonName: "chain"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: i < 2, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if parent == nil {
			parent = template
			signer = key
		}
		der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
		if err != nil {
			t.Fatal(err)
		}
		parent, err = x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		signer = key
		certificates = append(certificates, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		leafKey, err = x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
	}
	b := testBundle()
	b.Files = []File{{Slot: "AgentCertificate", Data: append(certificates[2], certificates[1]...)}, {Slot: "AgentKey", Data: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafKey})}, {Slot: "AgentCA", Data: certificates[0]}}
	for i := range b.Files {
		b.Files[i].SHA256 = Digest(b.Files[i].Data)
	}
	e, _ := testEngine(t)
	completeAgentFixture(t, e, &b)
	if _, err := e.Ensure(b, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestServerIssuerCanDifferFromClientTrustCA(t *testing.T) {
	b := certificateBundle(t)
	clientTrust := certificateBundle(t)
	b.Files[2] = clientTrust.Files[2]
	e, _ := testEngine(t)
	completeAgentFixture(t, e, &b)
	if _, err := e.Ensure(b, time.Now()); err != nil {
		t.Fatalf("client trust CA incorrectly constrained the server issuer: %v", err)
	}
}

func TestTLSDistributionRequiresActualConfiguredPaths(t *testing.T) {
	args := []byte("agent\x00--tls-cert-file=/unmanaged/tls.crt\x00--tls-key-file=/etc/sonic-operator-agent/tls.key\x00--tls-client-ca-file=/etc/sonic-operator-agent/ca.crt\x00")
	if err := verifyAgentTLSArguments(args); err == nil {
		t.Fatal("unused managed certificate files reported as runtime ready")
	}
	args = bytes.ReplaceAll(args, []byte("/unmanaged/tls.crt"), []byte("/etc/sonic-operator-agent/tls.crt"))
	if err := verifyAgentTLSArguments(args); err != nil {
		t.Fatal(err)
	}
}
