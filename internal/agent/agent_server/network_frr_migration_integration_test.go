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

func TestFRRMigrationMTLS(t *testing.T) {
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
		name                                 string
		readOnly, network, migration, legacy bool
	}{
		{name: "all disabled"},
		{name: "network only", network: true},
		{name: "migration only", migration: true},
		{name: "both enabled", network: true, migration: true},
		{name: "read-only all disabled", readOnly: true},
		{name: "read-only network only", readOnly: true, network: true},
		{name: "read-only migration only", readOnly: true, migration: true},
		{name: "read-only both enabled", readOnly: true, network: true, migration: true},
		{name: "legacy constructor defaults disabled", network: true, legacy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var s *grpc.Server
			var err error
			if tc.legacy {
				s, err = newGRPCServerWithNetwork(serverCert.certFile, serverCert.keyFile, clientCA.certFile, tc.readOnly, false, false, tc.network)
			} else {
				s, err = newGRPCServerWithFRRMigration(serverCert.certFile, serverCert.keyFile, clientCA.certFile, tc.readOnly, false, false, tc.network, tc.migration)
			}
			if err != nil {
				t.Fatal(err)
			}
			observed := json.RawMessage(`{"classification":"empty-traditional","adoptionDigest":"` + strings.Repeat("a", 64) + `"}`)
			b := &networkMTLSBackend{networkBackend: networkBackend{result: &agent.NetworkResult{Observed: observed}}}
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
			r := &agent.NetworkRequest{Kind: "FRRMigration", Spec: json.RawMessage(`{"mode":"Unified"}`)}
			out, err := c.GetNetworkResource(t.Context(), r)
			if err != nil || out == nil || string(out.Observed) != string(observed) || b.calls.Load() != 1 {
				t.Fatalf("preview without owner or approval: %+v %v calls=%d", out, err, b.calls.Load())
			}
			r.OwnerID = "uid"
			r.Spec = json.RawMessage(`{"mode":"Unified","approvedDigest":"` + strings.Repeat("a", 64) + `"}`)
			allowed := tc.network && tc.migration && !tc.readOnly
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
						if err != nil || out == nil || b.calls.Load() != before+1 {
							t.Fatalf("allowed mutation: %+v %v calls=%d", out, err, b.calls.Load())
						}
					} else if status.Code(err) != codes.PermissionDenied || b.calls.Load() != before {
						t.Fatalf("gate bypass: %v calls=%d", err, b.calls.Load())
					}
					if tc.network && !tc.readOnly && !tc.migration && !strings.Contains(status.Convert(err).Message(), "--allow-frr-migration=true") {
						t.Fatalf("missing migration opt-in guidance: %v", err)
					}
					// Other network kinds depend only on the existing network/read-only gates.
					before = b.calls.Load()
					out, err = op.call(t.Context(), &agent.NetworkRequest{Kind: "VRF", OwnerID: "uid", Spec: json.RawMessage(`{"name":"VrfTest"}`)})
					if tc.network && !tc.readOnly {
						if err != nil || out == nil || b.calls.Load() != before+1 {
							t.Fatalf("ordinary network mutation: %+v %v", out, err)
						}
					} else if status.Code(err) != codes.PermissionDenied || b.calls.Load() != before {
						t.Fatalf("ordinary network gate bypass: %v", err)
					}
				})
			}

			// Raw protobuf calls bypass client validation, exercising the actual server boundary.
			conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
				RootCAs: roots, Certificates: []tls.Certificate{cert}, ServerName: "agent.test", MinVersion: tls.VersionTLS12,
			})))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			wire := pb.NewSwitchAgentServiceClient(conn)
			for _, invalid := range []struct {
				name, kind, spec string
			}{
				{"malformed JSON", "FRRMigration", `{"mode":`},
				{"array spec", "FRRMigration", `[]`},
				{"null spec", "FRRMigration", `null`},
				{"missing spec", "FRRMigration", ``},
				{"lowercase kind", "frrmigration", `{"mode":"Unified"}`},
				{"mixed case kind", "FrrMigration", `{"mode":"Unified"}`},
				{"uppercase kind", "FRRMIGRATION", `{"mode":"Unified"}`},
				{"space suffix", "FRRMigration ", `{"mode":"Unified"}`},
			} {
				t.Run(invalid.name, func(t *testing.T) {
					want := codes.InvalidArgument
					if !tc.network || tc.readOnly || (invalid.kind == "FRRMigration" && !tc.migration) {
						want = codes.PermissionDenied
					}
					ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
					defer cancel()
					for _, call := range []func(context.Context, *pb.NetworkRequest, ...grpc.CallOption) (*pb.NetworkResponse, error){wire.EnsureNetworkResource, wire.RecoverNetworkResource} {
						before := b.calls.Load()
						_, err := call(ctx, &pb.NetworkRequest{Kind: invalid.kind, OwnerId: "uid", SpecJson: []byte(invalid.spec)})
						if status.Code(err) != want || b.calls.Load() != before {
							t.Fatalf("invalid request: err=%v want=%v calls=%d", err, want, b.calls.Load())
						}
					}
				})
			}
		})
	}
}
