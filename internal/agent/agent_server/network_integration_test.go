//go:build integration

// SPDX-License-Identifier: Apache-2.0

package agent_server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"sync/atomic"
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

type networkMTLSBackend struct {
	networkBackend
	calls atomic.Int32
}

func (b *networkMTLSBackend) GetNetworkResource(ctx context.Context, r *agent.NetworkRequest) (*agent.NetworkResult, *agent.Status) {
	b.calls.Add(1)
	return b.networkBackend.GetNetworkResource(ctx, r)
}
func (b *networkMTLSBackend) EnsureNetworkResource(ctx context.Context, r *agent.NetworkRequest) (*agent.NetworkResult, *agent.Status) {
	b.calls.Add(1)
	return b.networkBackend.EnsureNetworkResource(ctx, r)
}
func (b *networkMTLSBackend) RecoverNetworkResource(ctx context.Context, r *agent.NetworkRequest) (*agent.NetworkResult, *agent.Status) {
	b.calls.Add(1)
	return b.networkBackend.GetNetworkResource(ctx, r)
}

func TestNetworkMTLS(t *testing.T) {
	serverCA := issueCertificate(t, nil, 0)
	clientCA := issueCertificate(t, nil, 0)
	serverCert := issueCertificate(t, &serverCA, x509.ExtKeyUsageServerAuth)
	clientCert := issueCertificate(t, &clientCA, x509.ExtKeyUsageClientAuth)
	t.Setenv("SONIC_AGENT_TLS_CA_FILE", serverCA.certFile)
	t.Setenv("SONIC_AGENT_TLS_CERT_FILE", clientCert.certFile)
	t.Setenv("SONIC_AGENT_TLS_KEY_FILE", clientCert.keyFile)
	t.Setenv("SONIC_AGENT_TLS_SERVER_NAME", "agent.test")
	for _, tc := range []struct {
		name            string
		readOnly, allow bool
	}{
		{"disabled", false, false}, {"read-only", true, true}, {"allowed", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := newGRPCServerWithNetwork(serverCert.certFile, serverCert.keyFile, clientCA.certFile, tc.readOnly, false, false, tc.allow)
			if err != nil {
				t.Fatal(err)
			}
			b := &networkMTLSBackend{networkBackend: networkBackend{result: &agent.NetworkResult{Exists: true, ConfigurationVerified: true, Observed: json.RawMessage(`{"state":"down"}`)}}}
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
			c := base.(agentclient.NetworkClient)
			r := &agent.NetworkRequest{Kind: "VRF", OwnerID: "uid", Spec: json.RawMessage(`{"name":"VrfTest"}`)}
			out, err := c.GetNetworkResource(t.Context(), r)
			if err != nil || !out.ConfigurationVerified {
				t.Fatalf("Get: %+v %v", out, err)
			}
			out, err = c.EnsureNetworkResource(t.Context(), r)
			if tc.allow && !tc.readOnly {
				if err != nil || !out.ConfigurationVerified || b.calls.Load() != 2 {
					t.Fatalf("Ensure: %+v %v", out, err)
				}
			} else if status.Code(err) != codes.PermissionDenied || b.calls.Load() != 1 {
				t.Fatalf("gate bypass: %v calls=%d", err, b.calls.Load())
			}
			beforeRecovery := b.calls.Load()
			out, err = base.(agentclient.NetworkRecoveryClient).RecoverNetworkResource(t.Context(), r)
			if tc.allow && !tc.readOnly {
				if err != nil || out == nil || b.calls.Load() != beforeRecovery+1 {
					t.Fatalf("Recover: %+v %v", out, err)
				}
			} else if status.Code(err) != codes.PermissionDenied || b.calls.Load() != beforeRecovery {
				t.Fatalf("recovery gate bypass: %v", err)
			}
			roots := x509.NewCertPool()
			roots.AddCert(serverCA.cert)
			for _, peer := range []struct {
				name  string
				creds credentials.TransportCredentials
			}{
				{"plaintext", insecure.NewCredentials()},
				{"no client certificate", credentials.NewTLS(&tls.Config{RootCAs: roots, ServerName: "agent.test", MinVersion: tls.VersionTLS12})},
			} {
				t.Run(peer.name, func(t *testing.T) {
					before := b.calls.Load()
					conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(peer.creds))
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
					ctx, cancel := context.WithTimeout(t.Context(), time.Second)
					defer cancel()
					_, err = pb.NewSwitchAgentServiceClient(conn).EnsureNetworkResource(ctx, &pb.NetworkRequest{Kind: r.Kind, OwnerId: r.OwnerID, SpecJson: r.Spec})
					if err == nil || b.calls.Load() != before {
						t.Fatal("unauthenticated network access")
					}
					_, err = pb.NewSwitchAgentServiceClient(conn).RecoverNetworkResource(ctx, &pb.NetworkRequest{Kind: r.Kind, OwnerId: r.OwnerID, SpecJson: r.Spec})
					if err == nil || b.calls.Load() != before {
						t.Fatal("unauthenticated network recovery")
					}
				})
			}
		})
	}
}
