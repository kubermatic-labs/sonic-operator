// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package agent_server

import (
	"context"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// VLANAgent is optional so backends without VLAN support can still serve other RPCs.
type VLANAgent interface {
	GetVLAN(context.Context, uint32) (*agent.VLAN, *agent.Status)
	EnsureVLAN(context.Context, *agent.VLAN) (*agent.VLAN, *agent.Status)
}

func (s *proxyServer) GetVLAN(ctx context.Context, request *pb.GetVLANRequest) (*pb.GetVLANResponse, error) {
	backend, ok := s.SwitchAgent.(VLANAgent)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "backend does not support VLANs")
	}
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "missing GetVLAN request")
	}
	vlan, st := backend.GetVLAN(ctx, request.GetVlanId())
	if st != nil && st.Code != 0 {
		return &pb.GetVLANResponse{Status: &pb.Status{Code: st.Code, Message: st.Message}}, nil
	}
	if vlan == nil {
		return nil, status.Error(codes.Internal, "backend returned no VLAN")
	}
	return &pb.GetVLANResponse{Status: &pb.Status{Message: "Success"}, Vlan: vlanToProto(vlan)}, nil
}

func (s *proxyServer) EnsureVLAN(ctx context.Context, request *pb.EnsureVLANRequest) (*pb.EnsureVLANResponse, error) {
	backend, ok := s.SwitchAgent.(VLANAgent)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "backend does not support VLANs")
	}
	if request.GetVlan() == nil {
		return nil, status.Error(codes.InvalidArgument, "missing VLAN in EnsureVLAN request")
	}
	vlan := &agent.VLAN{ID: request.Vlan.GetId(), Members: make([]agent.VLANMember, len(request.Vlan.GetMembers()))}
	for i, member := range request.Vlan.GetMembers() {
		if member == nil {
			return nil, status.Error(codes.InvalidArgument, "nil member in EnsureVLAN request")
		}
		vlan.Members[i] = agent.VLANMember{InterfaceName: member.GetInterfaceName(), TaggingMode: member.GetTaggingMode()}
	}
	vlan, st := backend.EnsureVLAN(ctx, vlan)
	if st != nil && st.Code != 0 {
		return &pb.EnsureVLANResponse{Status: &pb.Status{Code: st.Code, Message: st.Message}}, nil
	}
	if vlan == nil {
		return nil, status.Error(codes.Internal, "backend returned no VLAN")
	}
	return &pb.EnsureVLANResponse{Status: &pb.Status{Message: "Success"}, Vlan: vlanToProto(vlan)}, nil
}

func vlanToProto(vlan *agent.VLAN) *pb.VLAN {
	result := &pb.VLAN{Id: vlan.ID, Members: make([]*pb.VLANMember, len(vlan.Members))}
	for i, member := range vlan.Members {
		result.Members[i] = &pb.VLANMember{InterfaceName: member.InterfaceName, TaggingMode: member.TaggingMode}
	}
	return result
}
