// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"fmt"

	agenterrors "github.com/ironcore-dev/sonic-operator/internal/agent/errors"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
)

// VLANClient is an optional capability separate from SwitchAgentClient.
type VLANClient interface {
	GetVLAN(context.Context, uint32) (*agent.VLAN, error)
	EnsureVLAN(context.Context, *agent.VLAN) (*agent.VLAN, error)
}

// ErrVLANNotFound identifies an absent VLAN reported by GetVLAN's backend.
var ErrVLANNotFound = errors.New("VLAN not found")

var _ VLANClient = (*defaultSwitchAgentClient)(nil)

func (c *defaultSwitchAgentClient) GetVLAN(ctx context.Context, id uint32) (*agent.VLAN, error) {
	resp, err := c.client.GetVLAN(ctx, &pb.GetVLANRequest{VlanId: id})
	if err != nil {
		return nil, err
	}
	if err := responseError("GetVLAN", resp.GetStatus()); err != nil {
		if resp.GetStatus().GetCode() == agenterrors.NOT_FOUND {
			return nil, fmt.Errorf("%w: %w", ErrVLANNotFound, err)
		}
		return nil, err
	}
	return vlanFromProto("GetVLAN", resp.GetVlan())
}

func (c *defaultSwitchAgentClient) EnsureVLAN(ctx context.Context, vlan *agent.VLAN) (*agent.VLAN, error) {
	if vlan == nil {
		return nil, fmt.Errorf("EnsureVLAN: missing VLAN")
	}
	wire := &pb.VLAN{Id: vlan.ID, Members: make([]*pb.VLANMember, len(vlan.Members))}
	for i, member := range vlan.Members {
		wire.Members[i] = &pb.VLANMember{InterfaceName: member.InterfaceName, TaggingMode: member.TaggingMode}
	}
	resp, err := c.client.EnsureVLAN(ctx, &pb.EnsureVLANRequest{Vlan: wire})
	if err != nil {
		return nil, err
	}
	if err := responseError("EnsureVLAN", resp.GetStatus()); err != nil {
		return nil, err
	}
	return vlanFromProto("EnsureVLAN", resp.GetVlan())
}

func vlanFromProto(method string, vlan *pb.VLAN) (*agent.VLAN, error) {
	if vlan == nil {
		return nil, fmt.Errorf("%s: missing VLAN in agent response", method)
	}
	result := &agent.VLAN{ID: vlan.GetId(), Members: make([]agent.VLANMember, len(vlan.GetMembers()))}
	for i, member := range vlan.GetMembers() {
		if member == nil {
			return nil, fmt.Errorf("%s: nil member in agent response", method)
		}
		result.Members[i] = agent.VLANMember{InterfaceName: member.GetInterfaceName(), TaggingMode: member.GetTaggingMode()}
	}
	return result, nil
}
