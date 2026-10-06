// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	agenterrors "github.com/ironcore-dev/sonic-operator/internal/agent/errors"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type vlanResponseClient struct {
	pb.SwitchAgentServiceClient
	get     *pb.GetVLANResponse
	ensure  *pb.EnsureVLANResponse
	err     error
	gotID   uint32
	gotVLAN *pb.VLAN
}

func (c *vlanResponseClient) GetVLAN(_ context.Context, req *pb.GetVLANRequest, _ ...grpc.CallOption) (*pb.GetVLANResponse, error) {
	c.gotID = req.GetVlanId()
	return c.get, c.err
}

func (c *vlanResponseClient) EnsureVLAN(_ context.Context, req *pb.EnsureVLANRequest, _ ...grpc.CallOption) (*pb.EnsureVLANResponse, error) {
	c.gotVLAN = req.GetVlan()
	return c.ensure, c.err
}

func TestVLANClientResponses(t *testing.T) {
	t.Parallel()
	wire := &pb.VLAN{Id: 100, Members: []*pb.VLANMember{
		{InterfaceName: "Ethernet0", TaggingMode: "untagged"},
		{InterfaceName: "Ethernet129", TaggingMode: "tagged"},
	}}
	want := &agent.VLAN{ID: 100, Members: []agent.VLANMember{
		{InterfaceName: "Ethernet0", TaggingMode: "untagged"},
		{InterfaceName: "Ethernet129", TaggingMode: "tagged"},
	}}
	for _, tt := range []struct {
		name        string
		st          *pb.Status
		vlan        *pb.VLAN
		nilResponse bool
		err         error
		wantError   string
		notFound    bool
	}{
		{name: "success", st: &pb.Status{}, vlan: wire},
		{name: "application error", st: &pb.Status{Code: agenterrors.SERVER_ERROR, Message: "backend unavailable"}, vlan: wire, wantError: "backend unavailable"},
		{name: "not found", st: &pb.Status{Code: agenterrors.NOT_FOUND, Message: "VLAN absent"}, wantError: "VLAN absent", notFound: true},
		{name: "nil response", nilResponse: true, wantError: "missing status"},
		{name: "missing status", vlan: wire, wantError: "missing status"},
		{name: "missing VLAN", st: &pb.Status{}, wantError: "missing VLAN"},
		{name: "nil member", st: &pb.Status{}, vlan: &pb.VLAN{Id: 100, Members: []*pb.VLANMember{nil}}, wantError: "nil member"},
		{name: "transport error", err: status.Error(codes.Unavailable, "transport unavailable"), wantError: "transport unavailable"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			transport := &vlanResponseClient{err: tt.err}
			if !tt.nilResponse {
				transport.get = &pb.GetVLANResponse{Status: tt.st, Vlan: tt.vlan}
				transport.ensure = &pb.EnsureVLANResponse{Status: tt.st, Vlan: tt.vlan}
			}
			var c VLANClient = &defaultSwitchAgentClient{client: transport}
			for _, method := range []struct {
				name string
				call func() (*agent.VLAN, error)
			}{
				{"GetVLAN", func() (*agent.VLAN, error) { return c.GetVLAN(t.Context(), 100) }},
				{"EnsureVLAN", func() (*agent.VLAN, error) { return c.EnsureVLAN(t.Context(), want) }},
			} {
				t.Run(method.name, func(t *testing.T) {
					got, err := method.call()
					if tt.wantError == "" {
						if err != nil || !reflect.DeepEqual(got, want) {
							t.Fatalf("got %+v, %v; want %+v", got, err, want)
						}
					} else if err == nil || !strings.Contains(err.Error(), tt.wantError) || got != nil {
						t.Fatalf("got %+v, %v; want %q", got, err, tt.wantError)
					}
					if errors.Is(err, ErrVLANNotFound) != (tt.notFound && method.name == "GetVLAN") {
						t.Fatalf("incorrect not-found classification: %v", err)
					}
					if tt.err != nil && !errors.Is(err, tt.err) {
						t.Fatalf("lost transport error: %v", err)
					}
				})
			}
			if transport.gotID != 100 || !proto.Equal(transport.gotVLAN, wire) {
				t.Fatal("incorrect request DTO")
			}
		})
	}
}

func TestVLANClientNilInput(t *testing.T) {
	t.Parallel()
	c := &defaultSwitchAgentClient{}
	if got, err := c.EnsureVLAN(t.Context(), nil); err == nil || got != nil {
		t.Fatalf("nil VLAN accepted: %+v, %v", got, err)
	}
}
