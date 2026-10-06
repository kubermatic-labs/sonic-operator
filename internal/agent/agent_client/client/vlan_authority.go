// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"fmt"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
)

// VLANAuthorityClient is an optional capability separate from SwitchAgentClient.
type VLANAuthorityClient interface {
	GetVLANAuthority(context.Context, uint32) (*agent.VLANAuthorityResult, error)
	ReconcileVLANAuthority(context.Context, *agent.VLANAuthorityRequest) (*agent.VLANAuthorityResult, error)
	ReleaseVLANAuthority(context.Context, uint32, string) error
}

var _ VLANAuthorityClient = (*defaultSwitchAgentClient)(nil)

func (c *defaultSwitchAgentClient) GetVLANAuthority(ctx context.Context, id uint32) (*agent.VLANAuthorityResult, error) {
	resp, err := c.client.GetVLANAuthority(ctx, &pb.GetVLANAuthorityRequest{VlanId: id})
	if err != nil {
		return nil, err
	}
	return vlanAuthorityFromProto("GetVLANAuthority", resp)
}

func (c *defaultSwitchAgentClient) ReconcileVLANAuthority(ctx context.Context, request *agent.VLANAuthorityRequest) (*agent.VLANAuthorityResult, error) {
	if request == nil || request.VLAN == nil || request.OwnerID == "" {
		return nil, fmt.Errorf("ReconcileVLANAuthority requires VLAN and owner ID")
	}
	vlan := &pb.VLAN{Id: request.VLAN.ID, Members: make([]*pb.VLANMember, len(request.VLAN.Members))}
	for i, member := range request.VLAN.Members {
		vlan.Members[i] = &pb.VLANMember{InterfaceName: member.InterfaceName, TaggingMode: member.TaggingMode}
	}
	resp, err := c.client.ReconcileVLANAuthority(ctx, &pb.VLANAuthorityRequest{
		OwnerId: request.OwnerID, Vlan: vlan, AdoptionDigest: request.AdoptionDigest, Delete: request.Delete,
	})
	if err != nil {
		return nil, err
	}
	return vlanAuthorityFromProto("ReconcileVLANAuthority", resp)
}

func (c *defaultSwitchAgentClient) ReleaseVLANAuthority(ctx context.Context, id uint32, ownerID string) error {
	if ownerID == "" {
		return fmt.Errorf("ReleaseVLANAuthority requires owner ID")
	}
	resp, err := c.client.ReleaseVLANAuthority(ctx, &pb.ReleaseVLANAuthorityRequest{VlanId: id, OwnerId: ownerID})
	if err != nil {
		return err
	}
	return responseError("ReleaseVLANAuthority", resp.GetStatus())
}

func vlanAuthorityFromProto(method string, resp *pb.VLANAuthorityResponse) (*agent.VLANAuthorityResult, error) {
	if err := responseError(method, resp.GetStatus()); err != nil {
		return nil, err
	}
	wire := resp.GetResult()
	if wire == nil {
		return nil, fmt.Errorf("%s: missing result in agent response", method)
	}
	if wire.GetDigest() == "" {
		return nil, fmt.Errorf("%s: missing digest in agent response", method)
	}
	result := &agent.VLANAuthorityResult{
		Digest: wire.GetDigest(), OwnerID: wire.GetOwnerId(),
		OwnershipKnown:  wire.GetOwnershipKnown(),
		RuntimeVerified: wire.GetRuntimeVerified(), PersistenceVerified: wire.GetPersistenceVerified(),
	}
	if wire.GetVlan() != nil {
		var err error
		result.VLAN, err = vlanFromProto(method, wire.GetVlan())
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}
