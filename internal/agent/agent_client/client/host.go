// SPDX-License-Identifier: Apache-2.0
package client

import (
	"context"
	"encoding/json"

	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
	hp "github.com/ironcore-dev/sonic-operator/internal/agent/hostproto"
)

type HostClient interface {
	GetHost(context.Context, host.Request) (host.Result, error)
	EnsureHost(context.Context, host.Request) (host.Result, error)
	ConfirmHost(context.Context, host.Confirmation) (host.Result, error)
}

func hostResult(r *hp.HostResult, e error) (host.Result, error) {
	if e != nil {
		return host.Result{}, host.ErrNative
	}
	if r == nil {
		return host.Result{}, host.ErrNative
	}
	return host.Result{ConfigurationVerified: r.ConfigurationVerified, RuntimeVerified: r.RuntimeVerified, PersistenceVerified: r.PersistenceVerified, GatewayVerified: r.GatewayVerified, Recovery: r.Recovery, Transaction: r.Transaction, Challenge: r.Challenge, Owner: r.Owner}, nil
}
func (c *defaultSwitchAgentClient) GetHost(ctx context.Context, q host.Request) (host.Result, error) {
	if host.ValidateRequest(q) != nil {
		return host.Result{}, host.ErrInvalid
	}
	b, _ := json.Marshal(q)
	r, e := hp.NewHostServiceClient(c.conn).Get(ctx, &hp.HostRequest{ConfigurationJson: b})
	return hostResult(r, e)
}
func (c *defaultSwitchAgentClient) EnsureHost(ctx context.Context, q host.Request) (host.Result, error) {
	if host.ValidateRequest(q) != nil {
		return host.Result{}, host.ErrInvalid
	}
	b, _ := json.Marshal(q)
	r, e := hp.NewHostServiceClient(c.conn).Ensure(ctx, &hp.HostRequest{ConfigurationJson: b})
	return hostResult(r, e)
}
func (c *defaultSwitchAgentClient) ConfirmHost(ctx context.Context, q host.Confirmation) (host.Result, error) {
	r, e := hp.NewHostServiceClient(c.conn).Confirm(ctx, &hp.HostConfirmation{Owner: q.Owner, Target: q.Target, Transaction: q.Transaction, Challenge: q.Challenge})
	return hostResult(r, e)
}
