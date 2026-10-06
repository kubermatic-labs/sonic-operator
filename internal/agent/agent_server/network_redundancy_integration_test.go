//go:build integration

// SPDX-License-Identifier: Apache-2.0

package agent_server

import (
	"context"
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
	"google.golang.org/grpc/status"
)

func TestRedundancyMTLS(t *testing.T) {
	serverCA := issueCertificate(t, nil, 0)
	clientCA := issueCertificate(t, nil, 0)
	serverCert := issueCertificate(t, &serverCA, x509.ExtKeyUsageServerAuth)
	clientCert := issueCertificate(t, &clientCA, x509.ExtKeyUsageClientAuth)
	t.Setenv("SONIC_AGENT_TLS_CA_FILE", serverCA.certFile)
	t.Setenv("SONIC_AGENT_TLS_CERT_FILE", clientCert.certFile)
	t.Setenv("SONIC_AGENT_TLS_KEY_FILE", clientCert.keyFile)
	t.Setenv("SONIC_AGENT_TLS_SERVER_NAME", "agent.test")
	for _, tc := range []struct {
		name                                              string
		readOnly, network, redundancy, traffic, migration bool
		legacy                                            string
	}{
		{name: "disabled"},
		{name: "network only", network: true},
		{name: "redundancy only", redundancy: true},
		{name: "enabled", network: true, redundancy: true},
		{name: "read only", readOnly: true},
		{name: "read only network", readOnly: true, network: true},
		{name: "read only redundancy", readOnly: true, redundancy: true},
		{name: "read only enabled", readOnly: true, network: true, redundancy: true},
		{name: "other opt ins", network: true, traffic: true, migration: true},
		{name: "all opt ins", network: true, redundancy: true, traffic: true, migration: true},
		{name: "legacy traffic", network: true, traffic: true, migration: true, legacy: "traffic"},
		{name: "legacy migration", network: true, migration: true, legacy: "migration"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var s *grpc.Server
			var err error
			switch tc.legacy {
			case "traffic":
				s, err = newGRPCServerWithTrafficPolicy(serverCert.certFile, serverCert.keyFile, clientCA.certFile, tc.readOnly, false, false, tc.network, tc.migration, tc.traffic)
			case "migration":
				s, err = newGRPCServerWithFRRMigration(serverCert.certFile, serverCert.keyFile, clientCA.certFile, tc.readOnly, false, false, tc.network, tc.migration)
			default:
				s, err = newGRPCServerWithRedundancy(serverCert.certFile, serverCert.keyFile, clientCA.certFile, tc.readOnly, false, false, tc.network, tc.migration, tc.traffic, tc.redundancy)
			}
			if err != nil {
				t.Fatal(err)
			}
			b := &networkMTLSBackend{networkBackend: networkBackend{result: &agent.NetworkResult{ConfigurationVerified: true}}}
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
			for _, kind := range []string{"MLAG", "VXLANTunnel", "VLANVNI", "EVPNPeer", "VRF", "FRRMigration", "ACLPolicy", "ACLBinding", "QoSMap", "Scheduler", "QoSBinding"} {
				t.Run(kind, func(t *testing.T) {
					r := &agent.NetworkRequest{Kind: kind, Spec: json.RawMessage(`{}`)}
					before := b.calls.Load()
					if out, err := c.GetNetworkResource(t.Context(), r); err != nil || out == nil || b.calls.Load() != before+1 {
						t.Fatalf("read: %+v %v", out, err)
					}
					r.OwnerID = "uid"
					optIn := tc.redundancy
					switch kind {
					case "VRF":
						optIn = true
					case "FRRMigration":
						optIn = tc.migration
					case "ACLPolicy", "ACLBinding", "QoSMap", "Scheduler", "QoSBinding":
						optIn = tc.traffic
					}
					for _, op := range []struct {
						name string
						call func(context.Context, *agent.NetworkRequest) (*agent.NetworkResult, error)
					}{{"ensure", c.EnsureNetworkResource}, {"recover", base.(agentclient.NetworkRecoveryClient).RecoverNetworkResource}} {
						t.Run(op.name, func(t *testing.T) {
							before := b.calls.Load()
							out, err := op.call(t.Context(), r)
							if tc.network && !tc.readOnly && optIn {
								if err != nil || out == nil || b.calls.Load() != before+1 {
									t.Fatalf("allowed: %+v %v", out, err)
								}
							} else if status.Code(err) != codes.PermissionDenied || b.calls.Load() != before {
								t.Fatalf("gate bypass: %v", err)
							}
							if tc.network && !tc.readOnly && !tc.redundancy && (kind == "MLAG" || kind == "VXLANTunnel" || kind == "VLANVNI" || kind == "EVPNPeer") && !strings.Contains(status.Convert(err).Message(), "--allow-redundancy=true") {
								t.Fatalf("missing opt-in guidance: %v", err)
							}
						})
					}
				})
			}
		})
	}
}
