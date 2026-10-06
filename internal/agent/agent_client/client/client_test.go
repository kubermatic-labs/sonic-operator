// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"strings"
	"testing"

	agenterrors "github.com/ironcore-dev/sonic-operator/internal/agent/errors"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
	"google.golang.org/grpc"
)

func TestNewClientRequiresTLS(t *testing.T) {
	for _, key := range []string{"SONIC_AGENT_TLS_CA_FILE", "SONIC_AGENT_TLS_CERT_FILE", "SONIC_AGENT_TLS_KEY_FILE"} {
		t.Setenv(key, "")
	}
	if _, err := NewDefaultSwitchAgentClient("localhost:50051", 0); err == nil {
		t.Fatal("client accepted missing TLS credentials")
	}
}

func TestAbsentNeighborPreservesNotFoundStatus(t *testing.T) {
	c := &defaultSwitchAgentClient{client: readResponseClient{
		status: &pb.Status{Code: agenterrors.NOT_FOUND, Message: "no LLDP neighbor"}, missingPayload: true,
	}}
	neighbor, err := c.GetInterfaceNeighbor(context.Background(), &agent.Interface{Name: "Ethernet0"})
	if err != nil || neighbor == nil || neighbor.Status.Code != agenterrors.NOT_FOUND {
		t.Fatalf("absent neighbor must be a typed observation: neighbor=%+v err=%v", neighbor, err)
	}
}

type readResponseClient struct {
	pb.SwitchAgentServiceClient
	status         *pb.Status
	nilResponse    bool
	missingPayload bool
}

func (c readResponseClient) GetInterface(context.Context, *pb.GetInterfaceRequest, ...grpc.CallOption) (*pb.GetInterfaceResponse, error) {
	if c.nilResponse {
		return nil, nil
	}
	resp := &pb.GetInterfaceResponse{Status: c.status}
	if !c.missingPayload {
		resp.Interface = &pb.Interface{Name: "eth1-0", NativeName: "Ethernet4"}
	}
	return resp, nil
}

func (c readResponseClient) GetInterfaceNeighbor(context.Context, *pb.GetInterfaceNeighborRequest, ...grpc.CallOption) (*pb.GetInterfaceNeighborResponse, error) {
	if c.nilResponse {
		return nil, nil
	}
	resp := &pb.GetInterfaceNeighborResponse{Status: c.status}
	if !c.missingPayload {
		resp.Neighbor = &pb.InterfaceNeighbor{SystemName: "peer"}
	}
	return resp, nil
}

func TestInterfaceReadResponses(t *testing.T) {
	for _, tt := range []struct {
		name     string
		response readResponseClient
		want     string
	}{
		{name: "success", response: readResponseClient{status: &pb.Status{}}},
		{name: "backend failure", response: readResponseClient{status: &pb.Status{Code: 9, Message: "backend unavailable"}, missingPayload: true}, want: "backend unavailable"},
		{name: "nil response", response: readResponseClient{nilResponse: true}, want: "missing status"},
		{name: "missing status", want: "missing status"},
		{name: "missing payload", response: readResponseClient{status: &pb.Status{}, missingPayload: true}, want: "missing"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := &defaultSwitchAgentClient{client: tt.response}
			for _, method := range []struct {
				name string
				call func() error
			}{
				{"GetInterfaceByAbstractName", func() error {
					iface, err := c.GetInterfaceByAbstractName(context.Background(), &agent.Interface{Name: "eth1-0"})
					if tt.want == "" && err == nil && (iface == nil || iface.NativeName != "Ethernet4") {
						t.Errorf("incorrect interface: %+v", iface)
					}
					return err
				}},
				{"GetInterfaceNeighbor", func() error {
					neighbor, err := c.GetInterfaceNeighbor(context.Background(), &agent.Interface{Name: "Ethernet4"})
					if tt.want == "" && err == nil && (neighbor == nil || neighbor.SystemName != "peer") {
						t.Errorf("incorrect neighbor: %+v", neighbor)
					}
					return err
				}},
			} {
				t.Run(method.name, func(t *testing.T) {
					defer func() {
						if r := recover(); r != nil {
							t.Errorf("response panicked: %v", r)
						}
					}()
					err := method.call()
					if tt.want == "" {
						if err != nil {
							t.Fatal(err)
						}
					} else if err == nil || !strings.Contains(err.Error(), tt.want) {
						t.Fatalf("error = %v, want %q", err, tt.want)
					}
				})
			}
		})
	}
}

func (c readResponseClient) GetDeviceInfo(context.Context, *pb.GetDeviceInfoRequest, ...grpc.CallOption) (*pb.GetDeviceInfoResponse, error) {
	if c.nilResponse {
		return nil, nil
	}
	return &pb.GetDeviceInfoResponse{Status: c.status}, nil
}

func (c readResponseClient) ListInterfaces(context.Context, *pb.ListInterfacesRequest, ...grpc.CallOption) (*pb.ListInterfacesResponse, error) {
	if c.nilResponse {
		return nil, nil
	}
	return &pb.ListInterfacesResponse{Status: c.status}, nil
}

func (c readResponseClient) ListPorts(context.Context, *pb.ListPortsRequest, ...grpc.CallOption) (*pb.ListPortsResponse, error) {
	if c.nilResponse {
		return nil, nil
	}
	return &pb.ListPortsResponse{Status: c.status}, nil
}

func TestReadFailuresAreErrors(t *testing.T) {
	for _, tt := range []struct {
		name        string
		status      *pb.Status
		nilResponse bool
		want        string
	}{
		{name: "success", status: &pb.Status{}},
		{name: "backend failure", status: &pb.Status{Code: 9, Message: "backend unavailable"}, want: "backend unavailable"},
		{name: "missing status", want: "missing status"},
		{name: "nil response", nilResponse: true, want: "missing status"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := &defaultSwitchAgentClient{client: readResponseClient{status: tt.status, nilResponse: tt.nilResponse}}
			for _, method := range []struct {
				name string
				call func() error
			}{
				{"GetDeviceInfo", func() error { _, err := c.GetDeviceInfo(context.Background()); return err }},
				{"ListInterfaces", func() error { _, err := c.ListInterfaces(context.Background()); return err }},
				{"ListPorts", func() error { _, err := c.ListPorts(context.Background()); return err }},
			} {
				t.Run(method.name, func(t *testing.T) {
					err := method.call()
					if tt.want == "" {
						if err != nil {
							t.Fatalf("successful response: %v", err)
						}
						return
					}
					if err == nil || !strings.Contains(err.Error(), tt.want) {
						t.Fatalf("error = %v, want %q", err, tt.want)
					}
				})
			}
		})
	}
}
