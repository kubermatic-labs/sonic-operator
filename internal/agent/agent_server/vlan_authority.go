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

// VLANAuthorityAgent is optional; other backends need not support ownership.
type VLANAuthorityAgent interface {
	GetVLANAuthority(context.Context, uint32) (*agent.VLANAuthorityResult, *agent.Status)
	ReconcileVLANAuthority(context.Context, *agent.VLANAuthorityRequest) (*agent.VLANAuthorityResult, *agent.Status)
	ReleaseVLANAuthority(context.Context, uint32, string) *agent.Status
}

func (s *proxyServer) GetVLANAuthority(ctx context.Context, request *pb.GetVLANAuthorityRequest) (*pb.VLANAuthorityResponse, error) {
	backend, ok := s.SwitchAgent.(VLANAuthorityAgent)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "backend does not support VLAN authority")
	}
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "missing GetVLANAuthority request")
	}
	result, st := backend.GetVLANAuthority(ctx, request.GetVlanId())
	return vlanAuthorityResponse(result, st)
}

func (s *proxyServer) ReconcileVLANAuthority(ctx context.Context, request *pb.VLANAuthorityRequest) (*pb.VLANAuthorityResponse, error) {
	backend, ok := s.SwitchAgent.(VLANAuthorityAgent)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "backend does not support VLAN authority")
	}
	if request.GetVlan() == nil || request.GetOwnerId() == "" {
		return nil, status.Error(codes.InvalidArgument, "ReconcileVLANAuthority requires VLAN and owner ID")
	}
	vlan := &agent.VLAN{ID: request.Vlan.GetId(), Members: make([]agent.VLANMember, len(request.Vlan.GetMembers()))}
	for i, member := range request.Vlan.GetMembers() {
		if member == nil {
			return nil, status.Error(codes.InvalidArgument, "nil member in ReconcileVLANAuthority request")
		}
		vlan.Members[i] = agent.VLANMember{InterfaceName: member.GetInterfaceName(), TaggingMode: member.GetTaggingMode()}
	}
	result, st := backend.ReconcileVLANAuthority(ctx, &agent.VLANAuthorityRequest{
		OwnerID: request.GetOwnerId(), VLAN: vlan, AdoptionDigest: request.GetAdoptionDigest(), Delete: request.GetDelete(),
	})
	return vlanAuthorityResponse(result, st)
}

func (s *proxyServer) ReleaseVLANAuthority(ctx context.Context, request *pb.ReleaseVLANAuthorityRequest) (*pb.ReleaseVLANAuthorityResponse, error) {
	backend, ok := s.SwitchAgent.(VLANAuthorityAgent)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "backend does not support VLAN authority")
	}
	if request.GetOwnerId() == "" {
		return nil, status.Error(codes.InvalidArgument, "ReleaseVLANAuthority requires owner ID")
	}
	st := backend.ReleaseVLANAuthority(ctx, request.GetVlanId(), request.GetOwnerId())
	if st != nil && st.Code != 0 {
		return &pb.ReleaseVLANAuthorityResponse{Status: &pb.Status{Code: st.Code, Message: st.Message}}, nil
	}
	return &pb.ReleaseVLANAuthorityResponse{Status: &pb.Status{Message: "Success"}}, nil
}

func vlanAuthorityResponse(result *agent.VLANAuthorityResult, st *agent.Status) (*pb.VLANAuthorityResponse, error) {
	if st != nil && st.Code != 0 {
		return &pb.VLANAuthorityResponse{Status: &pb.Status{Code: st.Code, Message: st.Message}}, nil
	}
	if result == nil || result.Digest == "" {
		return nil, status.Error(codes.Internal, "backend returned no VLAN authority result or digest")
	}
	wire := &pb.VLANAuthorityResult{
		Digest: result.Digest, OwnerId: result.OwnerID,
		OwnershipKnown:  result.OwnershipKnown,
		RuntimeVerified: result.RuntimeVerified, PersistenceVerified: result.PersistenceVerified,
	}
	if result.VLAN != nil {
		wire.Vlan = vlanToProto(result.VLAN)
	}
	return &pb.VLANAuthorityResponse{Status: &pb.Status{Message: "Success"}, Result: wire}, nil
}
