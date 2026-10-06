// SPDX-License-Identifier: Apache-2.0
package agent_server

import (
	"context"

	"google.golang.org/grpc/stats"
)

// Both transport identity and pre-decode admission own context values. Preserve
// each returned context and fan out completion events, particularly lease End.
type combinedStats struct{ handlers []stats.Handler }

func (s combinedStats) TagConn(ctx context.Context, info *stats.ConnTagInfo) context.Context {
	for _, h := range s.handlers {
		ctx = h.TagConn(ctx, info)
	}
	return ctx
}
func (s combinedStats) TagRPC(ctx context.Context, info *stats.RPCTagInfo) context.Context {
	for _, h := range s.handlers {
		ctx = h.TagRPC(ctx, info)
	}
	return ctx
}
func (s combinedStats) HandleConn(ctx context.Context, event stats.ConnStats) {
	for _, h := range s.handlers {
		h.HandleConn(ctx, event)
	}
}
func (s combinedStats) HandleRPC(ctx context.Context, event stats.RPCStats) {
	for _, h := range s.handlers {
		h.HandleRPC(ctx, event)
	}
}
