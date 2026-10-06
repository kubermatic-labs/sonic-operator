//go:build integration

// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package agent_server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	agentclient "github.com/ironcore-dev/sonic-operator/internal/agent/agent_client/client"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type breakoutMTLSBackend struct {
	breakoutBackend
	mu        sync.Mutex
	remaining time.Duration
}

func (b *breakoutMTLSBackend) GetPortBreakout(ctx context.Context, port string) (*agent.PortBreakout, *agent.Status) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.breakoutBackend.GetPortBreakout(ctx, port)
}

func (b *breakoutMTLSBackend) ReconcilePortBreakout(ctx context.Context, request *agent.PortBreakoutRequest) (*agent.PortBreakout, *agent.Status) {
	b.mu.Lock()
	defer b.mu.Unlock()
	deadline, _ := ctx.Deadline()
	b.remaining = time.Until(deadline)
	return b.breakoutBackend.ReconcilePortBreakout(ctx, request)
}

func TestPortBreakoutMTLS(t *testing.T) {
	serverCA := issueCertificate(t, nil, 0)
	clientCA := issueCertificate(t, nil, 0)
	serverCert := issueCertificate(t, &serverCA, x509.ExtKeyUsageServerAuth)
	clientCert := issueCertificate(t, &clientCA, x509.ExtKeyUsageClientAuth)
	untrustedCert := issueCertificate(t, &serverCA, x509.ExtKeyUsageClientAuth)
	untrustedPair, err := tls.LoadX509KeyPair(untrustedCert.certFile, untrustedCert.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SONIC_AGENT_TLS_CA_FILE", serverCA.certFile)
	t.Setenv("SONIC_AGENT_TLS_CERT_FILE", clientCert.certFile)
	t.Setenv("SONIC_AGENT_TLS_KEY_FILE", clientCert.keyFile)
	t.Setenv("SONIC_AGENT_TLS_SERVER_NAME", "agent.test")
	request := &agent.PortBreakoutRequest{Port: "Ethernet0", Mode: "4x25G", ChildAdminState: "down"}
	want := &agent.PortBreakout{Port: "Ethernet0", Mode: "4x25G", SupportedModes: []string{"1x100G", "4x25G"}, Children: []agent.PortBreakoutChild{{Name: "Ethernet0", Lanes: "1", Speed: "25000", AdminState: "down", MTU: "9100"}, {Name: "Ethernet1", Lanes: "2", Speed: "25000", AdminState: "down", MTU: "9100"}}, RuntimeVerified: true, PersistenceVerified: false, Pending: true, Message: "save pending"}
	for _, tt := range []struct {
		name                                   string
		readOnly, allow, legacy, authoritative bool
		configurationVerified                  bool
	}{
		{name: "legacy constructor defaults disabled", legacy: true},
		{name: "explicit false denies"},
		{name: "read-only despite opt-in", readOnly: true, allow: true},
		{name: "both guards deny", readOnly: true},
		{name: "explicit write opt-in", allow: true},
		{name: "both write opt-ins", allow: true, authoritative: true},
		{name: "configuration unverified round trip", allow: true, configurationVerified: false},
		{name: "configuration verified round trip", allow: true, configurationVerified: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result := *want
			result.ConfigurationVerified = tt.configurationVerified
			want := &result
			s, err := newGRPCServerWithBreakout(serverCert.certFile, serverCert.keyFile, clientCA.certFile, tt.readOnly, tt.authoritative, tt.allow)
			if tt.legacy {
				if s != nil {
					s.Stop()
				}
				s, err = newGRPCServer(serverCert.certFile, serverCert.keyFile, clientCA.certFile, false, true)
			}
			if err != nil {
				t.Fatal(err)
			}
			b := &breakoutMTLSBackend{breakoutBackend: breakoutBackend{result: want}}
			pb.RegisterSwitchAgentServiceServer(s, NewProxyServer(b))
			lis, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				s.Stop()
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() { defer close(done); _ = s.Serve(lis) }()
			t.Cleanup(func() { s.Stop(); _ = lis.Close(); <-done })
			base, err := agentclient.NewDefaultSwitchAgentClient(lis.Addr().String(), 4*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = base.(interface{ Close() error }).Close() })
			c, ok := base.(agentclient.PortBreakoutClient)
			if !ok {
				t.Fatal("missing optional PortBreakoutClient")
			}
			_, authorityErr := base.(agentclient.VLANAuthorityClient).ReconcileVLANAuthority(t.Context(), &agent.VLANAuthorityRequest{OwnerID: "owner", VLAN: &agent.VLAN{ID: 100}})
			wantAuthorityCode := codes.PermissionDenied
			if (tt.authoritative && !tt.readOnly) || tt.legacy {
				// This backend lacks authority support, but the independent gate allows dispatch.
				wantAuthorityCode = codes.Unimplemented
			}
			if status.Code(authorityErr) != wantAuthorityCode {
				t.Fatalf("authority gate changed: %v, want %v", authorityErr, wantAuthorityCode)
			}
			if got, err := c.GetPortBreakout(t.Context(), request.Port); err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("read=%+v, err=%v", got, err)
			}
			got, err := c.ReconcilePortBreakout(t.Context(), request)
			b.mu.Lock()
			calls, received, remaining := b.calls, b.request, b.remaining
			b.mu.Unlock()
			if tt.allow && !tt.readOnly {
				if err != nil || !reflect.DeepEqual(got, want) || calls != 2 || !reflect.DeepEqual(received, request) {
					t.Fatalf("result=%+v err=%v calls=%d request=%+v", got, err, calls, received)
				}
				if remaining < 175*time.Second || remaining > 180*time.Second {
					t.Fatalf("breakout deadline=%v", remaining)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
				defer cancel()
				if _, err := c.ReconcilePortBreakout(ctx, request); err != nil {
					t.Fatal(err)
				}
				b.mu.Lock()
				remaining = b.remaining
				b.mu.Unlock()
				if remaining <= 0 || remaining > 2*time.Second {
					t.Fatalf("shorter caller deadline lost: %v", remaining)
				}
			} else if status.Code(err) != codes.PermissionDenied || calls != 1 || got != nil {
				t.Fatalf("write reached backend: calls=%d result=%+v error=%v", calls, got, err)
			}

			// Even with writes enabled, unauthenticated peers must never reach native execution.
			roots := x509.NewCertPool()
			roots.AddCert(serverCA.cert)
			for _, peer := range []struct {
				name  string
				creds credentials.TransportCredentials
			}{
				{"plaintext", insecure.NewCredentials()},
				{"missing client certificate", credentials.NewTLS(&tls.Config{RootCAs: roots, ServerName: "agent.test", MinVersion: tls.VersionTLS12})},
				{"untrusted client certificate", credentials.NewTLS(&tls.Config{RootCAs: roots, Certificates: []tls.Certificate{untrustedPair}, ServerName: "agent.test", MinVersion: tls.VersionTLS12})},
			} {
				t.Run(peer.name, func(t *testing.T) {
					b.mu.Lock()
					before := b.calls
					b.mu.Unlock()
					conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(peer.creds))
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
					ctx, cancel := context.WithTimeout(t.Context(), time.Second)
					defer cancel()
					_, err = pb.NewSwitchAgentServiceClient(conn).ReconcilePortBreakout(ctx, &pb.PortBreakoutRequest{Port: "Ethernet0", Mode: "4x25G", ChildAdminState: "down"})
					b.mu.Lock()
					after := b.calls
					b.mu.Unlock()
					if err == nil || before != after {
						t.Fatalf("unauthenticated write: error=%v calls=%d -> %d", err, before, after)
					}
				})
			}
		})
	}
}
