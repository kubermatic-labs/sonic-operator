// SPDX-License-Identifier: Apache-2.0
package sonic

import (
	"context"
	"net"

	"github.com/redis/go-redis/v9"
)

// NewSonicRedisAgentContext creates a private backend whose connections cannot
// outlive a qualification request. Cancellation closes in-flight sockets as well
// as supplying Redis deadlines: a cancel-only context need not have a deadline.
// The caller closes the backend's clients after qualification completes.
func NewSonicRedisAgentContext(ctx context.Context, address string) (*SonicAgent, error) {
	m := &SonicAgent{redisAddr: address, redisContext: ctx, clientPool: make(map[string]*redis.Client)}
	if _, err := m.ConnectContext(ctx, "CONFIG_DB"); err != nil {
		return nil, err
	}
	return m, nil
}

type requestRedisConnection struct {
	net.Conn
	stop func() bool
}

func (c *requestRedisConnection) Close() error { c.stop(); return c.Conn.Close() }
func requestRedisDialer(ctx context.Context) func(context.Context, string, string) (net.Conn, error) {
	return func(_ context.Context, network, address string) (net.Conn, error) {
		conn, err := (&net.Dialer{Timeout: RedisDialTimeout}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		return &requestRedisConnection{Conn: conn, stop: stop}, nil
	}
}
