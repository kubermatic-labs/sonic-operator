// SPDX-License-Identifier: Apache-2.0
package agent_server

import (
	"context"
	"strings"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/tap"
)

// Tap admission runs before protobuf body decoding. Rejection has no queue and
// a lease is held until RPC End, not merely until client cancellation.
type artifactAdmission struct{ slots chan struct{} }
type artifactLease struct {
	once    sync.Once
	release func()
}
type artifactLeaseKey struct{}

func newArtifactAdmission() *artifactAdmission {
	return &artifactAdmission{slots: make(chan struct{}, 1)}
}
func (a *artifactAdmission) tap(ctx context.Context, info *tap.Info) (context.Context, error) {
	if !strings.HasPrefix(info.FullMethodName, "/artifact.ArtifactService/") {
		return ctx, nil
	}
	select {
	case a.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, status.Error(codes.Canceled, "artifact request canceled")
	default:
		return nil, status.Error(codes.ResourceExhausted, "artifact request admission full")
	}
	lease := &artifactLease{release: func() { <-a.slots }}
	return context.WithValue(ctx, artifactLeaseKey{}, lease), nil
}
func (a *artifactAdmission) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context {
	return ctx
}
func (a *artifactAdmission) HandleRPC(ctx context.Context, event stats.RPCStats) {
	if _, ok := event.(*stats.End); ok {
		if lease, ok := ctx.Value(artifactLeaseKey{}).(*artifactLease); ok {
			lease.once.Do(lease.release)
		}
	}
}
func (a *artifactAdmission) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	return ctx
}
func (a *artifactAdmission) HandleConn(context.Context, stats.ConnStats) {}
