// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package agent_server

import (
	"context"
	"flag"
	"testing"

	switchAgent "github.com/ironcore-dev/sonic-operator/internal/agent/interface"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestSecureFlagDefaults(t *testing.T) {
	for _, tt := range []struct{ name, want string }{
		{"bind-address", "127.0.0.1"}, {"port", "50051"}, {"read-only", "true"},
		{"tls-cert-file", ""}, {"tls-key-file", ""}, {"tls-client-ca-file", ""},
		{"allow-authoritative-vlans", "false"}, {"vlan-authority-journal-dir", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := flag.Lookup(tt.name)
			if f == nil {
				t.Fatalf("missing flag --%s", tt.name)
			}
			if f.DefValue != tt.want {
				t.Errorf("default = %q, want %q", f.DefValue, tt.want)
			}
		})
	}
}

type nilReadBackend struct {
	switchAgent.SwitchAgent
}

func (nilReadBackend) GetDeviceInfo(context.Context) (*agent.SwitchDevice, *agent.Status) {
	return nil, nil
}

func (nilReadBackend) ListInterfaces(context.Context) (*agent.InterfaceList, *agent.Status) {
	return nil, nil
}

func (nilReadBackend) ListPorts(context.Context) (*agent.PortList, *agent.Status) {
	return nil, nil
}

func (nilReadBackend) GetInterface(context.Context, *agent.Interface) (*agent.Interface, *agent.Status) {
	return nil, nil
}

func (nilReadBackend) GetInterfaceNeighbor(context.Context, *agent.Interface) (*agent.InterfaceNeighbor, *agent.Status) {
	return nil, nil
}

func TestNilBackendReadsDoNotPanic(t *testing.T) {
	s := NewProxyServer(nilReadBackend{})
	for _, tt := range []struct {
		name string
		call func() error
	}{
		{"GetDeviceInfo", func() error { _, err := s.GetDeviceInfo(context.Background(), &pb.GetDeviceInfoRequest{}); return err }},
		{"ListInterfaces", func() error {
			_, err := s.ListInterfaces(context.Background(), &pb.ListInterfacesRequest{})
			return err
		}},
		{"ListPorts", func() error { _, err := s.ListPorts(context.Background(), &pb.ListPortsRequest{}); return err }},
		{"GetInterface", func() error { _, err := s.GetInterface(context.Background(), &pb.GetInterfaceRequest{}); return err }},
		{"GetInterfaceNeighbor", func() error {
			_, err := s.GetInterfaceNeighbor(context.Background(), &pb.GetInterfaceNeighborRequest{})
			return err
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("nil backend response panicked: %v", r)
				}
			}()
			if err := tt.call(); status.Code(err) != codes.Internal {
				t.Fatalf("error = %v, want Internal", err)
			}
		})
	}
}

func TestReadOnlyAllowlist(t *testing.T) {
	reads := map[string]bool{
		pb.SwitchAgentService_GetDeviceInfo_FullMethodName:        true,
		pb.SwitchAgentService_ListInterfaces_FullMethodName:       true,
		pb.SwitchAgentService_ListPorts_FullMethodName:            true,
		pb.SwitchAgentService_GetInterface_FullMethodName:         true,
		pb.SwitchAgentService_GetInterfaceNeighbor_FullMethodName: true,
		pb.SwitchAgentService_GetVLAN_FullMethodName:              true,
		pb.SwitchAgentService_GetVLANAuthority_FullMethodName:     true,
	}
	methods := []string{"/switchagent.v1.SwitchAgentService/GetFutureRead", "/other.Service/GetDeviceInfo"}
	for _, m := range pb.SwitchAgentService_ServiceDesc.Methods {
		methods = append(methods, "/"+pb.SwitchAgentService_ServiceDesc.ServiceName+"/"+m.MethodName)
	}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			called := false
			_, err := readOnlyInterceptor(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: method}, func(context.Context, any) (any, error) {
				called = true
				return nil, nil
			})
			if reads[method] {
				if err != nil || !called {
					t.Fatalf("read rejected: %v", err)
				}
			} else if status.Code(err) != codes.PermissionDenied || called {
				t.Fatalf("unapproved RPC: error=%v, backend invoked=%v", err, called)
			}
		})
	}
}
