//go:build integration

// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package agent_server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	agentclient "github.com/ironcore-dev/sonic-operator/internal/agent/agent_client/client"
	switchAgent "github.com/ironcore-dev/sonic-operator/internal/agent/interface"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type testCertificate struct {
	cert              *x509.Certificate
	key               *ecdsa.PrivateKey
	certFile, keyFile string
}

func issueCertificate(t *testing.T, ca *testCertificate, usage x509.ExtKeyUsage) testCertificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "agent test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	parent, signer := template, key
	if ca == nil {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	} else {
		parent, signer = ca.cert, ca.key
		template.ExtKeyUsage = []x509.ExtKeyUsage{usage}
		if usage == x509.ExtKeyUsageServerAuth {
			template.DNSNames = []string{"agent.test"}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	c := testCertificate{cert: cert, key: key, certFile: filepath.Join(dir, "cert.pem"), keyFile: filepath.Join(dir, "key.pem")}
	if err := os.WriteFile(c.certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	return c
}

type securityBackend struct {
	switchAgent.SwitchAgent
	reads, writes atomic.Int32
}

func (b *securityBackend) GetDeviceInfo(context.Context) (*agent.SwitchDevice, *agent.Status) {
	b.reads.Add(1)
	return &agent.SwitchDevice{Hwsku: "test-switch"}, nil
}

func (b *securityBackend) SaveConfig(context.Context) *agent.Status {
	b.writes.Add(1)
	return nil
}

func (b *securityBackend) SetInterfaceAdminStatus(_ context.Context, iface *agent.Interface) (*agent.Interface, *agent.Status) {
	b.writes.Add(1)
	return &agent.Interface{Name: iface.Name, NativeName: "Ethernet4", AdminStatus: iface.AdminStatus}, nil
}

func TestAdminStatusConfirmationRoundTrip(t *testing.T) {
	serverCA := issueCertificate(t, nil, 0)
	clientCA := issueCertificate(t, nil, 0)
	serverCert := issueCertificate(t, &serverCA, x509.ExtKeyUsageServerAuth)
	clientCert := issueCertificate(t, &clientCA, x509.ExtKeyUsageClientAuth)
	t.Setenv("SONIC_AGENT_TLS_CA_FILE", serverCA.certFile)
	t.Setenv("SONIC_AGENT_TLS_CERT_FILE", clientCert.certFile)
	t.Setenv("SONIC_AGENT_TLS_KEY_FILE", clientCert.keyFile)
	t.Setenv("SONIC_AGENT_TLS_SERVER_NAME", "agent.test")
	for _, tt := range []struct {
		name     string
		readOnly bool
	}{
		{"read-only denies write", true}, {"explicit write mode confirms native name", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, err := newGRPCServer(serverCert.certFile, serverCert.keyFile, clientCA.certFile, tt.readOnly)
			if err != nil {
				t.Fatal(err)
			}
			backend := &securityBackend{}
			pb.RegisterSwitchAgentServiceServer(s, NewProxyServer(backend))
			lis, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				s.Stop()
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() { defer close(done); _ = s.Serve(lis) }()
			t.Cleanup(func() { s.Stop(); _ = lis.Close(); <-done })
			c, err := agentclient.NewDefaultSwitchAgentClient(lis.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = c.(interface{ Close() error }).Close() })
			confirmed, err := c.SetInterfaceAdminStatus(context.Background(), &agent.Interface{Name: "eth1-0", AdminStatus: agent.StatusUp})
			if tt.readOnly {
				if status.Code(err) != codes.PermissionDenied || backend.writes.Load() != 0 {
					t.Fatalf("write not blocked: %v, calls=%d", err, backend.writes.Load())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if confirmed == nil || confirmed.NativeName != "Ethernet4" || confirmed.AdminStatus != agent.StatusUp || backend.writes.Load() != 1 {
				t.Fatalf("incorrect confirmation: %+v, calls=%d", confirmed, backend.writes.Load())
			}
		})
	}
}

func TestMTLSReadOnlyServer(t *testing.T) {
	serverCA := issueCertificate(t, nil, 0)
	clientCA := issueCertificate(t, nil, 0)
	serverCert := issueCertificate(t, &serverCA, x509.ExtKeyUsageServerAuth)
	clientCert := issueCertificate(t, &clientCA, x509.ExtKeyUsageClientAuth)
	untrustedCert := issueCertificate(t, &serverCA, x509.ExtKeyUsageClientAuth)
	s, err := newGRPCServer(serverCert.certFile, serverCert.keyFile, clientCA.certFile, true)
	if err != nil {
		t.Fatal(err)
	}
	backend := &securityBackend{}
	pb.RegisterSwitchAgentServiceServer(s, NewProxyServer(backend))
	for name := range s.GetServiceInfo() {
		if strings.Contains(name, "reflection") {
			t.Fatalf("reflection enabled: %s", name)
		}
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Serve(lis) }()
	t.Cleanup(func() { s.Stop(); _ = lis.Close(); <-done })
	roots := x509.NewCertPool()
	roots.AddCert(serverCA.cert)
	for _, tt := range []struct {
		name       string
		cert       *testCertificate
		plaintext  bool
		maxVersion uint16
		allowed    bool
	}{
		{name: "authenticated", cert: &clientCert, allowed: true},
		{name: "authenticated TLS 1.2", cert: &clientCert, maxVersion: tls.VersionTLS12, allowed: true},
		{name: "absent certificate"},
		{name: "server CA is not client CA", cert: &untrustedCert},
		{name: "plaintext", plaintext: true},
		{name: "TLS 1.1", cert: &clientCert, maxVersion: tls.VersionTLS11},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var creds credentials.TransportCredentials
			if tt.plaintext {
				creds = insecure.NewCredentials()
			} else {
				cfg := &tls.Config{RootCAs: roots, ServerName: "agent.test", MinVersion: tls.VersionTLS10, MaxVersion: tt.maxVersion}
				if tt.cert != nil {
					cert, err := tls.LoadX509KeyPair(tt.cert.certFile, tt.cert.keyFile)
					if err != nil {
						t.Fatal(err)
					}
					cfg.Certificates = []tls.Certificate{cert}
				}
				creds = credentials.NewTLS(cfg)
			}
			conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(creds))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			before := backend.reads.Load()
			resp, err := pb.NewSwitchAgentServiceClient(conn).GetDeviceInfo(ctx, &pb.GetDeviceInfoRequest{})
			if !tt.allowed {
				if err == nil || backend.reads.Load() != before {
					t.Fatalf("unauthenticated call reached backend: %v", err)
				}
				return
			}
			if err != nil || resp.GetHwsku() != "test-switch" {
				t.Fatalf("authenticated read: %v, %v", resp, err)
			}
			for _, method := range []string{
				pb.SwitchAgentService_SaveConfig_FullMethodName,
				pb.SwitchAgentService_SetInterfaceAdminStatus_FullMethodName,
				pb.SwitchAgentService_SetInterfaceAliasName_FullMethodName,
				"/switchagent.v1.SwitchAgentService/Unknown",
			} {
				if err := conn.Invoke(ctx, method, &pb.SaveConfigRequest{}, &pb.SaveConfigResponse{}); status.Code(err) != codes.PermissionDenied {
					t.Errorf("%s: got %v, want PermissionDenied", method, err)
				}
			}
			if backend.writes.Load() != 0 {
				t.Fatal("write reached backend")
			}
		})
	}

	t.Setenv("SONIC_AGENT_TLS_CA_FILE", serverCA.certFile)
	t.Setenv("SONIC_AGENT_TLS_CERT_FILE", clientCert.certFile)
	t.Setenv("SONIC_AGENT_TLS_KEY_FILE", clientCert.keyFile)
	t.Setenv("SONIC_AGENT_TLS_SERVER_NAME", "agent.test")
	c, err := agentclient.NewDefaultSwitchAgentClient(lis.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	closer, ok := c.(interface{ Close() error })
	if !ok {
		t.Fatal("client lacks Close")
	}
	t.Cleanup(func() { _ = closer.Close() })
	device, err := c.GetDeviceInfo(context.Background())
	if err != nil || device.Hwsku != "test-switch" {
		t.Fatalf("environment TLS client: %v, %v", device, err)
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetDeviceInfo(context.Background()); err == nil {
		t.Fatal("closed client reconnected")
	}

	t.Setenv("SONIC_AGENT_TLS_SERVER_NAME", "wrong.test")
	c, err = agentclient.NewDefaultSwitchAgentClient(lis.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.(interface{ Close() error }).Close()
	if _, err := c.GetDeviceInfo(context.Background()); err == nil {
		t.Fatal("wrong server identity accepted")
	}
}

func TestInvalidTLSConfiguration(t *testing.T) {
	ca := issueCertificate(t, nil, 0)
	cert := issueCertificate(t, &ca, x509.ExtKeyUsageServerAuth)
	other := issueCertificate(t, &ca, x509.ExtKeyUsageClientAuth)
	bad := filepath.Join(t.TempDir(), "invalid.pem")
	if err := os.WriteFile(bad, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ name, cert, key, ca string }{
		{"missing cert", "", cert.keyFile, ca.certFile},
		{"missing key", cert.certFile, "", ca.certFile},
		{"missing CA", cert.certFile, cert.keyFile, ""},
		{"unreadable CA", cert.certFile, cert.keyFile, bad + "-missing"},
		{"bad CA", cert.certFile, cert.keyFile, bad},
		{"bad cert", bad, cert.keyFile, ca.certFile},
		{"bad key", cert.certFile, bad, ca.certFile},
		{"mismatched key", cert.certFile, other.keyFile, ca.certFile},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, readOnly := range []bool{true, false} {
				s, err := newGRPCServer(tt.cert, tt.key, tt.ca, readOnly)
				if s != nil {
					s.Stop()
				}
				if err == nil {
					t.Fatal("server accepted invalid TLS config")
				}
			}
			t.Setenv("SONIC_AGENT_TLS_CA_FILE", tt.ca)
			t.Setenv("SONIC_AGENT_TLS_CERT_FILE", tt.cert)
			t.Setenv("SONIC_AGENT_TLS_KEY_FILE", tt.key)
			if _, err := agentclient.NewDefaultSwitchAgentClient("localhost:50051", 0); err == nil {
				t.Fatal("client accepted invalid TLS config")
			}
		})
	}
}
