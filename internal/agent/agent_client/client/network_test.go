// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
	"google.golang.org/grpc"
)

type networkResponseClient struct {
	pb.SwitchAgentServiceClient
	response *pb.NetworkResponse
}

func (c networkResponseClient) GetNetworkResource(context.Context, *pb.NetworkRequest, ...grpc.CallOption) (*pb.NetworkResponse, error) {
	return c.response, nil
}
func (c networkResponseClient) EnsureNetworkResource(context.Context, *pb.NetworkRequest, ...grpc.CallOption) (*pb.NetworkResponse, error) {
	return c.response, nil
}
func (c networkResponseClient) RecoverNetworkResource(context.Context, *pb.NetworkRequest, ...grpc.CallOption) (*pb.NetworkResponse, error) {
	return c.response, nil
}

func TestNetworkClientResponses(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name                  string
		response              *pb.NetworkResponse
		wantError, wantResult bool
	}{
		{"nil", nil, true, false},
		{"missing status", &pb.NetworkResponse{}, true, false},
		{"missing result", &pb.NetworkResponse{Status: &pb.Status{}}, true, false},
		{"invalid observation", &pb.NetworkResponse{Status: &pb.Status{}, Result: &pb.NetworkResult{ObservedJson: []byte("bad")}}, true, false},
		{"success", &pb.NetworkResponse{Status: &pb.Status{}, Result: &pb.NetworkResult{ConfigurationVerified: true, ObservedJson: []byte(`{}`)}}, false, true},
		{"save failed retains evidence", &pb.NetworkResponse{Status: &pb.Status{Code: 500}, Result: &pb.NetworkResult{ConfigurationVerified: true}}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &defaultSwitchAgentClient{client: networkResponseClient{response: tc.response}}
			r := &agent.NetworkRequest{Kind: "VRF", OwnerID: "uid", Spec: json.RawMessage(`{"name":"VrfTest"}`)}
			for _, call := range []func(context.Context, *agent.NetworkRequest) (*agent.NetworkResult, error){c.GetNetworkResource, c.EnsureNetworkResource, c.RecoverNetworkResource} {
				out, err := call(t.Context(), r)
				if (err != nil) != tc.wantError || (out != nil) != tc.wantResult {
					t.Fatalf("result=%+v err=%v", out, err)
				}
				if out != nil && !out.ConfigurationVerified {
					t.Fatal("configuration evidence lost")
				}
			}
		})
	}
}

func TestNetworkTimeouts(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, method string
		caller, want time.Duration
	}{
		{"get", pb.SwitchAgentService_GetNetworkResource_FullMethodName, 0, 15 * time.Second},
		{"ensure", pb.SwitchAgentService_EnsureNetworkResource_FullMethodName, 0, 120 * time.Second},
		{"recover", pb.SwitchAgentService_RecoverNetworkResource_FullMethodName, 0, 120 * time.Second},
		{"recover short caller", pb.SwitchAgentService_RecoverNetworkResource_FullMethodName, time.Second, time.Second},
		{"short caller", pb.SwitchAgentService_EnsureNetworkResource_FullMethodName, time.Second, time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			if tc.caller > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tc.caller)
				defer cancel()
			}
			err := rpcTimeoutInterceptor(4*time.Second)(ctx, tc.method, nil, nil, nil, func(ctx context.Context, _ string, _, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
				deadline, ok := ctx.Deadline()
				remaining := time.Until(deadline)
				if !ok || remaining > tc.want || remaining < tc.want-time.Second {
					t.Fatalf("deadline=%v want=%v", remaining, tc.want)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
