// SPDX-License-Identifier: Apache-2.0
package agent_server

import (
	"context"
	"testing"

	hp "github.com/ironcore-dev/sonic-operator/internal/agent/hostproto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"
)

func TestHostWriteGateBeforeDecode(t *testing.T) {
	s := &hostServer{writes: false}
	if _, e := s.Ensure(context.Background(), &hp.HostRequest{ConfigurationJson: []byte("secret malformed")}); status.Code(e) != codes.PermissionDenied {
		t.Fatalf("gate: %v", e)
	}
	if _, e := s.Confirm(context.Background(), &hp.HostConfirmation{}); status.Code(e) != codes.PermissionDenied {
		t.Fatalf("confirm gate: %v", e)
	}
}
func TestHostConnectionIdentityIsTransportScoped(t *testing.T) {
	h := hostConnectionStats{}
	a := h.TagConn(context.Background(), &stats.ConnTagInfo{})
	b := h.TagConn(context.Background(), &stats.ConnTagInfo{})
	if hostConnection(a) == "" || hostConnection(a) == hostConnection(b) {
		t.Fatal("connection identities not unique")
	}
	if hostConnection(h.TagRPC(a, &stats.RPCTagInfo{})) != hostConnection(a) {
		t.Fatal("RPC lost transport binding")
	}
	if hostConnection(context.Background()) != "" {
		t.Fatal("absent transport proof accepted")
	}
}
