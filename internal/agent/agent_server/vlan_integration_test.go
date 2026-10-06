//go:build integration

// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package agent_server

import (
	"crypto/x509"
	"net"
	"reflect"
	"testing"
	"time"

	agentclient "github.com/ironcore-dev/sonic-operator/internal/agent/agent_client/client"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestVLANMTLSRoundTrip(t *testing.T) {
	serverCA := issueCertificate(t, nil, 0)
	clientCA := issueCertificate(t, nil, 0)
	serverCert := issueCertificate(t, &serverCA, x509.ExtKeyUsageServerAuth)
	clientCert := issueCertificate(t, &clientCA, x509.ExtKeyUsageClientAuth)
	t.Setenv("SONIC_AGENT_TLS_CA_FILE", serverCA.certFile)
	t.Setenv("SONIC_AGENT_TLS_CERT_FILE", clientCert.certFile)
	t.Setenv("SONIC_AGENT_TLS_KEY_FILE", clientCert.keyFile)
	t.Setenv("SONIC_AGENT_TLS_SERVER_NAME", "agent.test")
	want := &agent.VLAN{ID: 100, Members: []agent.VLANMember{
		{InterfaceName: "Ethernet0", TaggingMode: "untagged"},
		{InterfaceName: "Ethernet129", TaggingMode: "tagged"},
	}}
	for _, tt := range []struct {
		name     string
		readOnly bool
	}{
		{name: "read-only permits observation and blocks ensure", readOnly: true},
		{name: "write mode roundtrips VLAN"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, err := newGRPCServer(serverCert.certFile, serverCert.keyFile, clientCA.certFile, tt.readOnly)
			if err != nil {
				t.Fatal(err)
			}
			backend := &vlanBackend{vlan: want}
			pb.RegisterSwitchAgentServiceServer(s, NewProxyServer(backend))
			lis, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				s.Stop()
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() { defer close(done); _ = s.Serve(lis) }()
			t.Cleanup(func() { s.Stop(); _ = lis.Close(); <-done })
			c, err := agentclient.NewDefaultSwitchAgentClient(lis.Addr().String(), 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = c.(interface{ Close() error }).Close() })
			vlanClient, ok := c.(agentclient.VLANClient)
			if !ok {
				t.Fatal("default client does not expose VLANClient")
			}
			got, err := vlanClient.GetVLAN(t.Context(), 100)
			if err != nil || !reflect.DeepEqual(got, want) || backend.reads.Load() != 1 {
				t.Fatalf("read failed: %+v, %v, calls=%d", got, err, backend.reads.Load())
			}
			if backend.gotID != 100 {
				t.Fatalf("backend received ID %d", backend.gotID)
			}
			got, err = vlanClient.EnsureVLAN(t.Context(), want)
			if tt.readOnly {
				if status.Code(err) != codes.PermissionDenied || got != nil || backend.writes.Load() != 0 {
					t.Fatalf("write not blocked: %+v, %v, calls=%d", got, err, backend.writes.Load())
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, want) || backend.writes.Load() != 1 {
				t.Fatalf("write failed: %+v, %v, calls=%d", got, err, backend.writes.Load())
			}
			if !reflect.DeepEqual(backend.gotVLAN, want) {
				t.Fatalf("incorrect backend DTO: %+v", backend.gotVLAN)
			}
		})
	}
}
