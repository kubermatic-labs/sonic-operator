// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package agent_server

import (
	"context"
	"reflect"
	"sync/atomic"
	"testing"

	agenterrors "github.com/ironcore-dev/sonic-operator/internal/agent/errors"
	switchAgent "github.com/ironcore-dev/sonic-operator/internal/agent/interface"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestVLANReadOnlyAllowlist(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		allowed bool
	}{
		{name: "GetVLAN", allowed: true},
		{name: "EnsureVLAN"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			_, err := readOnlyInterceptor(t.Context(), nil, &grpc.UnaryServerInfo{
				FullMethod: "/switchagent.v1.SwitchAgentService/" + tt.name,
			}, func(context.Context, any) (any, error) {
				called = true
				return nil, nil
			})
			if tt.allowed {
				if err != nil || !called {
					t.Fatalf("read rejected: %v, called=%v", err, called)
				}
			} else if status.Code(err) != codes.PermissionDenied || called {
				t.Fatalf("write not blocked: %v, called=%v", err, called)
			}
		})
	}
}

type vlanBackend struct {
	switchAgent.SwitchAgent
	vlan          *agent.VLAN
	resultStatus  *agent.Status
	reads, writes atomic.Int32
	gotID         uint32
	gotVLAN       *agent.VLAN
}

func (b *vlanBackend) GetVLAN(_ context.Context, id uint32) (*agent.VLAN, *agent.Status) {
	b.gotID = id
	b.reads.Add(1)
	return b.vlan, b.resultStatus
}

func (b *vlanBackend) EnsureVLAN(_ context.Context, vlan *agent.VLAN) (*agent.VLAN, *agent.Status) {
	b.gotVLAN = vlan
	b.writes.Add(1)
	return b.vlan, b.resultStatus
}

func TestVLANServerResponses(t *testing.T) {
	t.Parallel()
	want := &agent.VLAN{ID: 100, Members: []agent.VLANMember{
		{InterfaceName: "Ethernet0", TaggingMode: "untagged"},
		{InterfaceName: "Ethernet129", TaggingMode: "tagged"},
	}}
	wire := &pb.VLAN{Id: 100, Members: []*pb.VLANMember{
		{InterfaceName: "Ethernet0", TaggingMode: "untagged"},
		{InterfaceName: "Ethernet129", TaggingMode: "tagged"},
	}}
	for _, tt := range []struct {
		name         string
		vlan         *agent.VLAN
		resultStatus *agent.Status
		code         codes.Code
	}{
		{name: "success", vlan: want},
		{name: "explicit success status", vlan: want, resultStatus: &agent.Status{}},
		{name: "application error", vlan: want, resultStatus: &agent.Status{Code: agenterrors.NOT_FOUND, Message: "VLAN absent"}},
		{name: "nil result", code: codes.Internal},
		{name: "nil result with success status", resultStatus: &agent.Status{}, code: codes.Internal},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := &vlanBackend{vlan: tt.vlan, resultStatus: tt.resultStatus}
			s := NewProxyServer(b)
			for _, method := range []struct {
				name string
				call func() (*pb.Status, *pb.VLAN, error)
			}{
				{"GetVLAN", func() (*pb.Status, *pb.VLAN, error) {
					r, err := s.GetVLAN(t.Context(), &pb.GetVLANRequest{VlanId: 100})
					return r.GetStatus(), r.GetVlan(), err
				}},
				{"EnsureVLAN", func() (*pb.Status, *pb.VLAN, error) {
					r, err := s.EnsureVLAN(t.Context(), &pb.EnsureVLANRequest{Vlan: wire})
					return r.GetStatus(), r.GetVlan(), err
				}},
			} {
				t.Run(method.name, func(t *testing.T) {
					st, got, err := method.call()
					if status.Code(err) != tt.code {
						t.Fatalf("error = %v, want %v", err, tt.code)
					}
					if err != nil {
						return
					}
					if st == nil {
						t.Fatal("missing status")
					}
					if tt.resultStatus != nil && tt.resultStatus.Code != 0 {
						if st.Code != tt.resultStatus.Code || st.Message != tt.resultStatus.Message || got != nil {
							t.Fatalf("application error lost: %v, %v", st, got)
						}
						return
					}
					if st.Code != 0 || got.GetId() != 100 || len(got.GetMembers()) != 2 {
						t.Fatalf("incorrect response: %v, %v", st, got)
					}
					for i, m := range got.Members {
						if m.GetInterfaceName() != want.Members[i].InterfaceName || m.GetTaggingMode() != want.Members[i].TaggingMode {
							t.Fatalf("incorrect member: %v", m)
						}
					}
				})
			}
			if b.gotID != 100 || !reflect.DeepEqual(b.gotVLAN, want) {
				t.Fatalf("incorrect backend arguments: id=%d vlan=%+v", b.gotID, b.gotVLAN)
			}
		})
	}
}

func TestVLANServerUnsupported(t *testing.T) {
	t.Parallel()
	for _, backend := range []switchAgent.SwitchAgent{nil, nilReadBackend{}} {
		s := NewProxyServer(backend)
		if _, err := s.GetVLAN(t.Context(), &pb.GetVLANRequest{VlanId: 100}); status.Code(err) != codes.Unimplemented {
			t.Fatalf("unsupported GetVLAN: %v", err)
		}
		if _, err := s.EnsureVLAN(t.Context(), &pb.EnsureVLANRequest{Vlan: &pb.VLAN{Id: 100}}); status.Code(err) != codes.Unimplemented {
			t.Fatalf("unsupported EnsureVLAN: %v", err)
		}
	}
}

func TestVLANServerInvalidRequests(t *testing.T) {
	t.Parallel()
	b := &vlanBackend{}
	s := NewProxyServer(b)
	if _, err := s.GetVLAN(t.Context(), nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil GetVLAN request: %v", err)
	}
	for _, tt := range []struct {
		name    string
		request *pb.EnsureVLANRequest
	}{
		{name: "nil request"},
		{name: "nil VLAN", request: &pb.EnsureVLANRequest{}},
		{name: "nil member", request: &pb.EnsureVLANRequest{Vlan: &pb.VLAN{Id: 100, Members: []*pb.VLANMember{nil}}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := s.EnsureVLAN(t.Context(), tt.request); status.Code(err) != codes.InvalidArgument {
				t.Fatalf("invalid EnsureVLAN request: %v", err)
			}
		})
	}
	if b.reads.Load() != 0 || b.writes.Load() != 0 {
		t.Fatal("invalid request reached backend")
	}
}
