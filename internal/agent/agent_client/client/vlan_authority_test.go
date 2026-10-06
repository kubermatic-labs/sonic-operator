// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type authorityResponseClient struct {
	pb.SwitchAgentServiceClient
	response       *pb.VLANAuthorityResponse
	release        *pb.ReleaseVLANAuthorityResponse
	err            error
	request        *pb.VLANAuthorityRequest
	getRequest     *pb.GetVLANAuthorityRequest
	releaseRequest *pb.ReleaseVLANAuthorityRequest
}

func (c *authorityResponseClient) GetVLANAuthority(_ context.Context, r *pb.GetVLANAuthorityRequest, _ ...grpc.CallOption) (*pb.VLANAuthorityResponse, error) {
	c.getRequest = r
	return c.response, c.err
}

func (c *authorityResponseClient) ReconcileVLANAuthority(_ context.Context, r *pb.VLANAuthorityRequest, _ ...grpc.CallOption) (*pb.VLANAuthorityResponse, error) {
	c.request = r
	return c.response, c.err
}

func (c *authorityResponseClient) ReleaseVLANAuthority(_ context.Context, r *pb.ReleaseVLANAuthorityRequest, _ ...grpc.CallOption) (*pb.ReleaseVLANAuthorityResponse, error) {
	c.releaseRequest = r
	return c.release, c.err
}

func TestVLANAuthorityClientResponses(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name      string
		response  *pb.VLANAuthorityResponse
		err       error
		wantError string
	}{
		{name: "absent VLAN unknown ownership", response: &pb.VLANAuthorityResponse{Status: &pb.Status{}, Result: &pb.VLANAuthorityResult{Digest: "absent-digest", OwnershipKnown: false}}},
		{name: "absent VLAN known unowned", response: &pb.VLANAuthorityResponse{Status: &pb.Status{}, Result: &pb.VLANAuthorityResult{Digest: "absent-digest", OwnershipKnown: true}}},
		{name: "owned VLAN", response: &pb.VLANAuthorityResponse{Status: &pb.Status{}, Result: &pb.VLANAuthorityResult{Digest: "digest", OwnerId: "uid", Vlan: &pb.VLAN{Id: 100, Members: []*pb.VLANMember{{InterfaceName: "Ethernet0", TaggingMode: "tagged"}}}, RuntimeVerified: true, PersistenceVerified: true}}},
		{name: "pending persistence", response: &pb.VLANAuthorityResponse{Status: &pb.Status{}, Result: &pb.VLANAuthorityResult{Digest: "digest", OwnerId: "uid", RuntimeVerified: true}}},
		{name: "nil response", wantError: "missing status"},
		{name: "nil status", response: &pb.VLANAuthorityResponse{}, wantError: "missing status"},
		{name: "nil result", response: &pb.VLANAuthorityResponse{Status: &pb.Status{}}, wantError: "missing result"},
		{name: "empty digest", response: &pb.VLANAuthorityResponse{Status: &pb.Status{}, Result: &pb.VLANAuthorityResult{}}, wantError: "missing digest"},
		{name: "nil member", response: &pb.VLANAuthorityResponse{Status: &pb.Status{}, Result: &pb.VLANAuthorityResult{Digest: "digest", Vlan: &pb.VLAN{Members: []*pb.VLANMember{nil}}}}, wantError: "nil member"},
		{name: "backend error", response: &pb.VLANAuthorityResponse{Status: &pb.Status{Code: 409, Message: "owner conflict"}}, wantError: "owner conflict"},
		{name: "transport error", err: status.Error(codes.Unavailable, "connection lost"), wantError: "connection lost"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			wire := &authorityResponseClient{response: tt.response, err: tt.err}
			var c VLANAuthorityClient = &defaultSwitchAgentClient{client: wire}
			for _, method := range []struct {
				name string
				call func() (*agent.VLANAuthorityResult, error)
			}{
				{"get", func() (*agent.VLANAuthorityResult, error) { return c.GetVLANAuthority(t.Context(), 100) }},
				{"reconcile", func() (*agent.VLANAuthorityResult, error) {
					return c.ReconcileVLANAuthority(t.Context(), &agent.VLANAuthorityRequest{OwnerID: "uid", VLAN: &agent.VLAN{ID: 100}})
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
					if err != nil || got == nil {
						t.Fatalf("result=%+v, err=%v", got, err)
					}
					r := tt.response.Result
					want := &agent.VLANAuthorityResult{Digest: r.Digest, OwnerID: r.OwnerId, RuntimeVerified: r.RuntimeVerified, PersistenceVerified: r.PersistenceVerified, OwnershipKnown: r.OwnershipKnown}
					if r.Vlan != nil {
						want.VLAN = &agent.VLAN{ID: 100, Members: []agent.VLANMember{{InterfaceName: "Ethernet0", TaggingMode: "tagged"}}}
					}
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("result=%+v, want %+v", got, want)
					}
				})
			}
		})
	}
}

func TestVLANAuthorityClientRequests(t *testing.T) {
	t.Parallel()
	wire := &authorityResponseClient{response: &pb.VLANAuthorityResponse{Status: &pb.Status{}, Result: &pb.VLANAuthorityResult{Digest: "digest"}}, release: &pb.ReleaseVLANAuthorityResponse{Status: &pb.Status{}}}
	c := &defaultSwitchAgentClient{client: wire}
	request := &agent.VLANAuthorityRequest{OwnerID: "uid", VLAN: &agent.VLAN{ID: 100, Members: []agent.VLANMember{{InterfaceName: "Ethernet0", TaggingMode: "untagged"}}}, AdoptionDigest: "adopt", Delete: true}
	if _, err := c.ReconcileVLANAuthority(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(wire.request, &pb.VLANAuthorityRequest{OwnerId: "uid", AdoptionDigest: "adopt", Delete: true, Vlan: &pb.VLAN{Id: 100, Members: []*pb.VLANMember{{InterfaceName: "Ethernet0", TaggingMode: "untagged"}}}}) {
		t.Fatalf("lost request: %v", wire.request)
	}
	if _, err := c.GetVLANAuthority(t.Context(), 100); err != nil || wire.getRequest.GetVlanId() != 100 {
		t.Fatalf("get request: %v, %v", wire.getRequest, err)
	}
	if err := c.ReleaseVLANAuthority(t.Context(), 100, "uid"); err != nil || !proto.Equal(wire.releaseRequest, &pb.ReleaseVLANAuthorityRequest{VlanId: 100, OwnerId: "uid"}) {
		t.Fatalf("release request: %v, %v", wire.releaseRequest, err)
	}
	for _, tt := range []struct {
		name    string
		request *agent.VLANAuthorityRequest
	}{
		{"nil", nil}, {"nil VLAN", &agent.VLANAuthorityRequest{OwnerID: "uid"}}, {"empty owner", &agent.VLANAuthorityRequest{VLAN: &agent.VLAN{ID: 100}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := &defaultSwitchAgentClient{}
			if r, err := c.ReconcileVLANAuthority(t.Context(), tt.request); err == nil || r != nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
	if err := (&defaultSwitchAgentClient{}).ReleaseVLANAuthority(t.Context(), 100, ""); err == nil {
		t.Fatal("empty owner accepted")
	}
}

func TestReleaseVLANAuthorityClientResponses(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name      string
		response  *pb.ReleaseVLANAuthorityResponse
		err       error
		wantError string
	}{
		{name: "success", response: &pb.ReleaseVLANAuthorityResponse{Status: &pb.Status{}}},
		{name: "nil response", wantError: "missing status"},
		{name: "nil status", response: &pb.ReleaseVLANAuthorityResponse{}, wantError: "missing status"},
		{name: "backend error", response: &pb.ReleaseVLANAuthorityResponse{Status: &pb.Status{Code: 409, Message: "pending persistence"}}, wantError: "pending persistence"},
		{name: "transport error", err: status.Error(codes.PermissionDenied, "read-only"), wantError: "read-only"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := &defaultSwitchAgentClient{client: &authorityResponseClient{release: tt.response, err: tt.err}}
			err := c.ReleaseVLANAuthority(t.Context(), 100, "uid")
			if tt.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("error=%v, want %q", err, tt.wantError)
			}
			if tt.err != nil && !errors.Is(err, tt.err) {
				t.Fatalf("lost transport error: %v", err)
			}
		})
	}
}
