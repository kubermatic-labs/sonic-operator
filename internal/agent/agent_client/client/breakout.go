// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"fmt"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
)

// PortBreakoutClient is an optional capability separate from SwitchAgentClient.
type PortBreakoutClient interface {
	GetPortBreakout(context.Context, string) (*agent.PortBreakout, error)
	ReconcilePortBreakout(context.Context, *agent.PortBreakoutRequest) (*agent.PortBreakout, error)
}

var _ PortBreakoutClient = (*defaultSwitchAgentClient)(nil)

func (c *defaultSwitchAgentClient) GetPortBreakout(ctx context.Context, port string) (*agent.PortBreakout, error) {
	if port == "" {
		return nil, fmt.Errorf("GetPortBreakout requires port")
	}
	resp, err := c.client.GetPortBreakout(ctx, &pb.GetPortBreakoutRequest{Port: port})
	if err != nil {
		return nil, err
	}
	return portBreakoutFromProto("GetPortBreakout", resp)
}

func (c *defaultSwitchAgentClient) ReconcilePortBreakout(ctx context.Context, request *agent.PortBreakoutRequest) (*agent.PortBreakout, error) {
	if request == nil || request.Port == "" || request.Mode == "" || (request.ChildAdminState != "up" && request.ChildAdminState != "down") {
		return nil, fmt.Errorf("ReconcilePortBreakout requires port, mode, and child_admin_state up or down")
	}
	resp, err := c.client.ReconcilePortBreakout(ctx, &pb.PortBreakoutRequest{
		Port: request.Port, Mode: request.Mode, ChildAdminState: request.ChildAdminState, AdoptOnly: request.AdoptOnly,
	})
	if err != nil {
		return nil, err
	}
	return portBreakoutFromProto("ReconcilePortBreakout", resp)
}

func portBreakoutFromProto(method string, resp *pb.PortBreakoutResponse) (*agent.PortBreakout, error) {
	if err := responseError(method, resp.GetStatus()); err != nil {
		return nil, err
	}
	wire := resp.GetResult()
	if wire == nil {
		return nil, fmt.Errorf("%s: missing result in agent response", method)
	}
	result := &agent.PortBreakout{
		Port: wire.GetPort(), Mode: wire.GetMode(), SupportedModes: wire.GetSupportedModes(),
		Children:        make([]agent.PortBreakoutChild, len(wire.GetChildren())),
		RuntimeVerified: wire.GetRuntimeVerified(), PersistenceVerified: wire.GetPersistenceVerified(),
		ConfigurationVerified: wire.GetConfigurationVerified(),
		AdoptionSupported:     wire.GetAdoptionSupported(),
		Pending:               wire.GetPending(), Message: wire.GetMessage(),
	}
	for i, child := range wire.GetChildren() {
		if child == nil {
			return nil, fmt.Errorf("%s: nil child in agent response", method)
		}
		result.Children[i] = agent.PortBreakoutChild{Name: child.GetName(), Lanes: child.GetLanes(), Speed: child.GetSpeed(), AdminState: child.GetAdminState(), MTU: child.GetMtu()}
	}
	return result, nil
}
