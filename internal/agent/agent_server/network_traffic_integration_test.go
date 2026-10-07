//go:build integration

// SPDX-License-Identifier: Apache-2.0

package agent_server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	agentclient "github.com/ironcore-dev/sonic-operator/internal/agent/agent_client/client"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

func TestTrafficPolicyMTLS(t *testing.T) {
	serverCA := issueCertificate(t, nil, 0)
	clientCA := issueCertificate(t, nil, 0)
	serverCert := issueCertificate(t, &serverCA, x509.ExtKeyUsageServerAuth)
	clientCert := issueCertificate(t, &clientCA, x509.ExtKeyUsageClientAuth)
	t.Setenv("SONIC_AGENT_TLS_CA_FILE", serverCA.certFile)
	t.Setenv("SONIC_AGENT_TLS_CERT_FILE", clientCert.certFile)
	t.Setenv("SONIC_AGENT_TLS_KEY_FILE", clientCert.keyFile)
	t.Setenv("SONIC_AGENT_TLS_SERVER_NAME", "agent.test")
	roots := x509.NewCertPool()
	roots.AddCert(serverCA.cert)
	cert, err := tls.LoadX509KeyPair(clientCert.certFile, clientCert.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name                               string
		readOnly, network, traffic, legacy bool
	}{
		{name: "disabled"},
		{name: "network only", network: true},
		{name: "traffic only", traffic: true},
		{name: "enabled", network: true, traffic: true},
		{name: "read only disabled", readOnly: true},
		{name: "read only network", readOnly: true, network: true},
		{name: "read only traffic", readOnly: true, traffic: true},
		{name: "read only enabled", readOnly: true, network: true, traffic: true},
		{name: "legacy constructor", network: true, legacy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var s *grpc.Server
			var err error
			if tc.legacy {
				s, err = newGRPCServerWithFRRMigration(serverCert.certFile, serverCert.keyFile, clientCA.certFile, tc.readOnly, false, false, tc.network, true)
			} else {
				s, err = newGRPCServerWithTrafficPolicy(serverCert.certFile, serverCert.keyFile, clientCA.certFile, tc.readOnly, false, false, tc.network, false, tc.traffic)
			}
			if err != nil {
				t.Fatal(err)
			}
			b := &networkMTLSBackend{networkBackend: networkBackend{result: &agent.NetworkResult{ConfigurationVerified: true, Observed: json.RawMessage(`{"applied":false}`)}}}
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
			for _, kind := range []string{"BufferPool", "BufferProfile", "BufferPG", "BufferQueue", "ACLPolicy", "ACLBinding", "QoSMap", "Scheduler", "QoSBinding", "VRF", "FRRMigration"} {
				t.Run(kind, func(t *testing.T) {
					b.result.BufferRepairEligible = kind == "BufferProfile"
					b.result.Exists = kind == "BufferProfile"
					r := &agent.NetworkRequest{Kind: kind, Spec: json.RawMessage(`{}`)}
					before := b.calls.Load()
					if out, err := c.GetNetworkResource(t.Context(), r); err != nil || out == nil || out.RuntimeVerified || out.BufferRepairEligible != (kind == "BufferProfile") || b.calls.Load() != before+1 {
						t.Fatalf("observation: %+v %v calls=%d", out, err, b.calls.Load())
					}
					r.OwnerID = "uid"
					allowed := tc.network && !tc.readOnly && (kind == "VRF" || (kind == "FRRMigration" && tc.legacy) || (kind != "FRRMigration" && tc.traffic))
					for _, op := range []struct {
						name string
						call func(context.Context, *agent.NetworkRequest) (*agent.NetworkResult, error)
					}{
						{"ensure", c.EnsureNetworkResource},
						{"recover", base.(agentclient.NetworkRecoveryClient).RecoverNetworkResource},
					} {
						t.Run(op.name, func(t *testing.T) {
							before := b.calls.Load()
							out, err := op.call(t.Context(), r)
							if allowed {
								if err != nil || out == nil || !out.ConfigurationVerified || b.calls.Load() != before+1 {
									t.Fatalf("allowed call: %+v %v", out, err)
								}
							} else if status.Code(err) != codes.PermissionDenied || b.calls.Load() != before {
								t.Fatalf("gate bypass: %v calls=%d", err, b.calls.Load())
							}
							if tc.network && !tc.readOnly && !tc.traffic && kind != "VRF" && kind != "FRRMigration" && !strings.Contains(status.Convert(err).Message(), "--allow-traffic-policy=true") {
								t.Fatalf("missing traffic opt-in guidance: %v", err)
							}
						})
					}
				})
			}
			conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
				RootCAs: roots, Certificates: []tls.Certificate{cert}, ServerName: "agent.test", MinVersion: tls.VersionTLS12,
			})))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			wire := pb.NewSwitchAgentServiceClient(conn)
			for _, invalid := range []struct{ name, kind, spec string }{
				{"malformed", "ACLPolicy", `{"name":`},
				{"array", "QoSBinding", `[]`},
				{"null", "Scheduler", `null`},
				{"lowercase", "aclpolicy", `{}`},
				{"suffix", "ACLBinding ", `{}`},
				{"raw redis", "CONFIG_DB", `{}`},
			} {
				t.Run(invalid.name, func(t *testing.T) {
					want := codes.InvalidArgument
					if !tc.network || tc.readOnly || (!tc.traffic && (invalid.kind == "ACLPolicy" || invalid.kind == "QoSBinding" || invalid.kind == "Scheduler")) {
						want = codes.PermissionDenied
					}
					ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
					defer cancel()
					for _, call := range []func(context.Context, *pb.NetworkRequest, ...grpc.CallOption) (*pb.NetworkResponse, error){wire.EnsureNetworkResource, wire.RecoverNetworkResource} {
						before := b.calls.Load()
						_, err := call(ctx, &pb.NetworkRequest{Kind: invalid.kind, OwnerId: "uid", SpecJson: []byte(invalid.spec)})
						if status.Code(err) != want || b.calls.Load() != before {
							t.Fatalf("invalid request: %v want=%v calls=%d", err, want, b.calls.Load())
						}
					}
				})
			}
		})
	}
}
