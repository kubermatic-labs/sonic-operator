// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/json"
	"fmt"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
)

type NetworkClient interface {
	GetNetworkResource(context.Context, *agent.NetworkRequest) (*agent.NetworkResult, error)
	EnsureNetworkResource(context.Context, *agent.NetworkRequest) (*agent.NetworkResult, error)
}

type NetworkRecoveryClient interface {
	RecoverNetworkResource(context.Context, *agent.NetworkRequest) (*agent.NetworkResult, error)
}

var _ NetworkClient = (*defaultSwitchAgentClient)(nil)
var _ NetworkRecoveryClient = (*defaultSwitchAgentClient)(nil)

func (c *defaultSwitchAgentClient) GetNetworkResource(ctx context.Context, r *agent.NetworkRequest) (*agent.NetworkResult, error) {
	return c.networkResource(ctx, r, "get")
}

func (c *defaultSwitchAgentClient) EnsureNetworkResource(ctx context.Context, r *agent.NetworkRequest) (*agent.NetworkResult, error) {
	return c.networkResource(ctx, r, "ensure")
}

func (c *defaultSwitchAgentClient) RecoverNetworkResource(ctx context.Context, r *agent.NetworkRequest) (*agent.NetworkResult, error) {
	return c.networkResource(ctx, r, "recover")
}

func (c *defaultSwitchAgentClient) networkResource(ctx context.Context, r *agent.NetworkRequest, operation string) (*agent.NetworkResult, error) {
	if err := agent.ValidateNetworkRequest(r, operation != "get"); err != nil {
		return nil, err
	}
	wire := &pb.NetworkRequest{Kind: r.Kind, OwnerId: r.OwnerID, SpecJson: r.Spec}
	var resp *pb.NetworkResponse
	var err error
	method := "GetNetworkResource"
	if operation == "recover" {
		method = "RecoverNetworkResource"
		resp, err = c.client.RecoverNetworkResource(ctx, wire)
	} else if operation == "ensure" {
		method = "EnsureNetworkResource"
		resp, err = c.client.EnsureNetworkResource(ctx, wire)
	} else {
		resp, err = c.client.GetNetworkResource(ctx, wire)
	}
	if err != nil {
		return nil, err
	}
	err = responseError(method, resp.GetStatus())
	w := resp.GetResult()
	if w == nil {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%s: missing network result", method)
	}
	if len(w.GetObservedJson()) != 0 && !json.Valid(w.GetObservedJson()) {
		return nil, fmt.Errorf("%s: invalid observed JSON", method)
	}
	return &agent.NetworkResult{Exists: w.Exists, ConfigurationVerified: w.ConfigurationVerified, RuntimeVerified: w.RuntimeVerified, PersistenceVerified: w.PersistenceVerified, Observed: w.ObservedJson, Message: w.Message}, err
}
