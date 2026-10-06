// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type breakoutResponseClient struct {
	pb.SwitchAgentServiceClient
	response   *pb.PortBreakoutResponse
	err        error
	request    *pb.PortBreakoutRequest
	getRequest *pb.GetPortBreakoutRequest
}

func (c *breakoutResponseClient) GetPortBreakout(_ context.Context, r *pb.GetPortBreakoutRequest, _ ...grpc.CallOption) (*pb.PortBreakoutResponse, error) {
	c.getRequest = r
	return c.response, c.err
}

func (c *breakoutResponseClient) ReconcilePortBreakout(_ context.Context, r *pb.PortBreakoutRequest, _ ...grpc.CallOption) (*pb.PortBreakoutResponse, error) {
	c.request = r
	return c.response, c.err
}

func TestPortBreakoutClientResponses(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name      string
		response  *pb.PortBreakoutResponse
		err       error
		wantError string
	}{
		{name: "complete result", response: &pb.PortBreakoutResponse{Status: &pb.Status{}, Result: &pb.PortBreakout{Port: "Ethernet0", Mode: "4x25G", SupportedModes: []string{"1x100G", "4x25G"}, Children: []*pb.PortBreakoutChild{{Name: "Ethernet0", Lanes: "1", Speed: "25000", AdminState: "down", Mtu: "9100"}}, RuntimeVerified: true, PersistenceVerified: true, Pending: true, Message: "recovery details"}}},
		{name: "unverified result", response: &pb.PortBreakoutResponse{Status: &pb.Status{}, Result: &pb.PortBreakout{Port: "Ethernet0"}}},
		{name: "nil response", wantError: "missing status"},
		{name: "nil status", response: &pb.PortBreakoutResponse{}, wantError: "missing status"},
		{name: "nil result", response: &pb.PortBreakoutResponse{Status: &pb.Status{}}, wantError: "missing result"},
		{name: "nil child", response: &pb.PortBreakoutResponse{Status: &pb.Status{}, Result: &pb.PortBreakout{Children: []*pb.PortBreakoutChild{nil}}}, wantError: "nil child"},
		{name: "backend error", response: &pb.PortBreakoutResponse{Status: &pb.Status{Code: 409, Message: "pending breakout"}}, wantError: "pending breakout"},
		{name: "transport error", err: status.Error(codes.PermissionDenied, "breakout disabled"), wantError: "breakout disabled"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			wire := &breakoutResponseClient{response: tt.response, err: tt.err}
			var c PortBreakoutClient = &defaultSwitchAgentClient{client: wire}
			for _, method := range []struct {
				name string
				call func() (*agent.PortBreakout, error)
			}{
				{"get", func() (*agent.PortBreakout, error) { return c.GetPortBreakout(t.Context(), "Ethernet0") }},
				{"reconcile", func() (*agent.PortBreakout, error) {
					return c.ReconcilePortBreakout(t.Context(), &agent.PortBreakoutRequest{Port: "Ethernet0", Mode: "4x25G", ChildAdminState: "down"})
				}},
			} {
				t.Run(method.name, func(t *testing.T) {
					got, err := method.call()
					if tt.wantError != "" {
						if err == nil || got != nil || !strings.Contains(err.Error(), tt.wantError) {
							t.Fatalf("result=%+v err=%v, want %q", got, err, tt.wantError)
						}
						if tt.err != nil && !errors.Is(err, tt.err) {
							t.Fatalf("lost transport error: %v", err)
						}
						return
					}
					r := tt.response.Result
					want := &agent.PortBreakout{Port: r.Port, Mode: r.Mode, SupportedModes: r.SupportedModes, Children: make([]agent.PortBreakoutChild, len(r.Children)), RuntimeVerified: r.RuntimeVerified, PersistenceVerified: r.PersistenceVerified, Pending: r.Pending, Message: r.Message}
					for i, child := range r.Children {
						want.Children[i] = agent.PortBreakoutChild{Name: child.Name, Lanes: child.Lanes, Speed: child.Speed, AdminState: child.AdminState, MTU: child.Mtu}
					}
					if err != nil || !reflect.DeepEqual(got, want) {
						t.Fatalf("result=%+v error=%v, want %+v", got, err, want)
					}
				})
			}
			if wire.getRequest.GetPort() != "Ethernet0" || !proto.Equal(wire.request, &pb.PortBreakoutRequest{Port: "Ethernet0", Mode: "4x25G", ChildAdminState: "down"}) {
				t.Fatalf("lost requests: %v %v", wire.getRequest, wire.request)
			}
		})
	}
}

func TestPortBreakoutClientInvalidRequests(t *testing.T) {
	t.Parallel()
	c := &defaultSwitchAgentClient{}
	for _, tt := range []struct {
		name    string
		request *agent.PortBreakoutRequest
	}{
		{"nil", nil}, {"empty port", &agent.PortBreakoutRequest{Mode: "4x25G", ChildAdminState: "down"}},
		{"empty mode", &agent.PortBreakoutRequest{Port: "Ethernet0", ChildAdminState: "down"}},
		{"invalid state", &agent.PortBreakoutRequest{Port: "Ethernet0", Mode: "4x25G", ChildAdminState: "Up"}},
		{"missing state", &agent.PortBreakoutRequest{Port: "Ethernet0", Mode: "4x25G"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if r, err := c.ReconcilePortBreakout(t.Context(), tt.request); err == nil || r != nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
	if r, err := c.GetPortBreakout(t.Context(), ""); err == nil || r != nil {
		t.Fatal("empty port accepted")
	}
}

func TestPortBreakoutTimeout(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name, method         string
		caller, normal, want time.Duration
	}{
		{"reconcile", pb.SwitchAgentService_ReconcilePortBreakout_FullMethodName, 0, 4 * time.Second, 180 * time.Second},
		{"shorter caller", pb.SwitchAgentService_ReconcilePortBreakout_FullMethodName, time.Second, 4 * time.Second, time.Second},
		{"longer caller", pb.SwitchAgentService_ReconcilePortBreakout_FullMethodName, 300 * time.Second, 4 * time.Second, 180 * time.Second},
		{"larger normal timeout still bounded", pb.SwitchAgentService_ReconcilePortBreakout_FullMethodName, 0, 300 * time.Second, 180 * time.Second},
		{"read remains normal", pb.SwitchAgentService_GetPortBreakout_FullMethodName, 0, 4 * time.Second, 4 * time.Second},
		{"authority remains normal", pb.SwitchAgentService_ReconcileVLANAuthority_FullMethodName, 0, 4 * time.Second, 4 * time.Second},
		{"unknown service remains normal", "/other.Service/ReconcilePortBreakout", 0, 4 * time.Second, 4 * time.Second},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			if tt.caller > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tt.caller)
				defer cancel()
			}
			var invoked context.Context
			wantErr := errors.New("invoker error")
			err := rpcTimeoutInterceptor(tt.normal)(ctx, tt.method, nil, nil, nil, func(ctx context.Context, _ string, _, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
				invoked = ctx
				deadline, ok := ctx.Deadline()
				remaining := time.Until(deadline)
				if !ok || remaining > tt.want || remaining < tt.want-time.Second/2 {
					t.Fatalf("remaining=%v, want %v", remaining, tt.want)
				}
				return wantErr
			})
			if !errors.Is(err, wantErr) || invoked == nil || invoked.Err() != context.Canceled {
				t.Fatalf("error=%v context=%v", err, invoked)
			}
		})
	}
}
