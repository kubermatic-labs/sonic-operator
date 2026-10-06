//go:build integration

// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package agent_server

import (
	"context"
	"crypto/x509"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	agentclient "github.com/ironcore-dev/sonic-operator/internal/agent/agent_client/client"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type authorityMTLSBackend struct {
	authorityBackend
	mu sync.Mutex
}

func (b *authorityMTLSBackend) GetVLANAuthority(ctx context.Context, id uint32) (*agent.VLANAuthorityResult, *agent.Status) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.authorityBackend.GetVLANAuthority(ctx, id)
}

func (b *authorityMTLSBackend) ReconcileVLANAuthority(ctx context.Context, r *agent.VLANAuthorityRequest) (*agent.VLANAuthorityResult, *agent.Status) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.authorityBackend.ReconcileVLANAuthority(ctx, r)
}

func (b *authorityMTLSBackend) ReleaseVLANAuthority(ctx context.Context, id uint32, owner string) *agent.Status {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.authorityBackend.ReleaseVLANAuthority(ctx, id, owner)
}

func TestVLANAuthorityMTLS(t *testing.T) {
	serverCA := issueCertificate(t, nil, 0)
	clientCA := issueCertificate(t, nil, 0)
	serverCert := issueCertificate(t, &serverCA, x509.ExtKeyUsageServerAuth)
	clientCert := issueCertificate(t, &clientCA, x509.ExtKeyUsageClientAuth)
	t.Setenv("SONIC_AGENT_TLS_CA_FILE", serverCA.certFile)
	t.Setenv("SONIC_AGENT_TLS_CERT_FILE", clientCert.certFile)
	t.Setenv("SONIC_AGENT_TLS_KEY_FILE", clientCert.keyFile)
	t.Setenv("SONIC_AGENT_TLS_SERVER_NAME", "agent.test")
	request := &agent.VLANAuthorityRequest{OwnerID: "cr-uid", VLAN: &agent.VLAN{ID: 100, Members: []agent.VLANMember{{InterfaceName: "Ethernet0", TaggingMode: "untagged"}}}, AdoptionDigest: "reviewed-digest", Delete: true}
	for _, tt := range []struct {
		name      string
		readOnly  bool
		allow     []bool
		wantWrite bool
	}{
		{name: "omitted option denies independently of read-only"},
		{name: "explicit false denies", allow: []bool{false}},
		{name: "read-only denies despite opt-in", readOnly: true, allow: []bool{true}},
		{name: "both guards deny", readOnly: true},
		{name: "ambiguous options fail closed", allow: []bool{true, true}},
		{name: "explicit write opt-in", allow: []bool{true}, wantWrite: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, ownership := range []struct {
				name  string
				known bool
				owner string
			}{
				{"absent unknown ownership", false, ""},
				{"absent known unowned", true, ""},
				{"absent known owned", true, request.OwnerID},
			} {
				t.Run(ownership.name, func(t *testing.T) {
					s, err := newGRPCServer(serverCert.certFile, serverCert.keyFile, clientCA.certFile, tt.readOnly, tt.allow...)
					if err != nil {
						t.Fatal(err)
					}
					want := &agent.VLANAuthorityResult{Digest: "absent-digest", OwnerID: ownership.owner, OwnershipKnown: ownership.known, RuntimeVerified: true, PersistenceVerified: false}
					b := &authorityMTLSBackend{authorityBackend: authorityBackend{result: want}}
					pb.RegisterSwitchAgentServiceServer(s, NewProxyServer(b))
					lis, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						s.Stop()
						t.Fatal(err)
					}
					done := make(chan struct{})
					go func() { defer close(done); _ = s.Serve(lis) }()
					t.Cleanup(func() { s.Stop(); _ = lis.Close(); <-done })
					base, err := agentclient.NewDefaultSwitchAgentClient(lis.Addr().String(), 3*time.Second)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = base.(interface{ Close() error }).Close() })
					c, ok := base.(agentclient.VLANAuthorityClient)
					if !ok {
						t.Fatal("missing optional VLANAuthorityClient")
					}
					got, err := c.GetVLANAuthority(t.Context(), 100)
					if err != nil || !reflect.DeepEqual(got, want) {
						t.Fatalf("read=%+v, error=%v", got, err)
					}
					got, reconcileErr := c.ReconcileVLANAuthority(t.Context(), request)
					releaseErr := c.ReleaseVLANAuthority(t.Context(), 100, request.OwnerID)
					b.mu.Lock()
					defer b.mu.Unlock()
					if tt.wantWrite {
						if reconcileErr != nil || releaseErr != nil || !reflect.DeepEqual(got, want) {
							t.Fatalf("write=%+v, reconcile=%v release=%v", got, reconcileErr, releaseErr)
						}
						if b.calls != 3 || !reflect.DeepEqual(b.request, request) || b.owner != request.OwnerID {
							t.Fatalf("incorrect backend calls: %+v", b.authorityBackend)
						}
					} else {
						if status.Code(reconcileErr) != codes.PermissionDenied || status.Code(releaseErr) != codes.PermissionDenied || got != nil || b.calls != 1 {
							t.Fatalf("write reached backend: calls=%d reconcile=%v release=%v", b.calls, reconcileErr, releaseErr)
						}
					}
					if b.id != 100 {
						t.Fatalf("VLAN ID=%d", b.id)
					}
				})
			}
		})
	}
}
