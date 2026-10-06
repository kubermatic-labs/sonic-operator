// SPDX-License-Identifier: Apache-2.0
package agent_server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"time"

	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
	hp "github.com/ironcore-dev/sonic-operator/internal/agent/hostproto"
	"github.com/ironcore-dev/sonic-operator/internal/agent/sonic"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"
)

var allowHostConfig = flag.Bool("allow-host-config", false, "Allow typed host management/system configuration when read-only is disabled")
var hostJournalDir = flag.String("host-journal-dir", "", "Persistent private host recovery directory; keep configured after first use")

type hostConnectionKey struct{}
type hostConnectionStats struct{}

func (hostConnectionStats) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return context.WithValue(ctx, hostConnectionKey{}, hex.EncodeToString(b))
}
func (hostConnectionStats) HandleConn(context.Context, stats.ConnStats) {}
func (hostConnectionStats) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context {
	return ctx
}
func (hostConnectionStats) HandleRPC(context.Context, stats.RPCStats) {}
func hostConnection(ctx context.Context) string {
	s, _ := ctx.Value(hostConnectionKey{}).(string)
	return s
}

type hostServer struct {
	hp.UnimplementedHostServiceServer
	engine *host.Engine
	writes bool
}

func hostResponse(r host.Result) *hp.HostResult {
	return &hp.HostResult{ConfigurationVerified: r.ConfigurationVerified, RuntimeVerified: r.RuntimeVerified, PersistenceVerified: r.PersistenceVerified, GatewayVerified: r.GatewayVerified, Recovery: r.Recovery, Transaction: r.Transaction, Challenge: r.Challenge, Owner: r.Owner}
}
func hostError(e error) error {
	if e == nil {
		return nil
	}
	code := codes.FailedPrecondition
	if errors.Is(e, host.ErrInvalid) {
		code = codes.InvalidArgument
	}
	if errors.Is(e, host.ErrConflict) {
		code = codes.AlreadyExists
	}
	return status.Error(code, "typed host operation could not be verified")
}
func (s *hostServer) Get(ctx context.Context, q *hp.HostRequest) (*hp.HostResult, error) {
	r, e := host.DecodeRequest(q.GetConfigurationJson())
	if e != nil {
		return nil, hostError(e)
	}
	if s.engine == nil {
		return nil, status.Error(codes.Unimplemented, "host recovery storage is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, e := s.engine.Get(ctx, r, hostConnection(ctx))
	if e != nil {
		return nil, hostError(e)
	}
	return hostResponse(out), nil
}
func (s *hostServer) Ensure(ctx context.Context, q *hp.HostRequest) (*hp.HostResult, error) {
	if !s.writes {
		return nil, status.Error(codes.PermissionDenied, "host writes require explicit host capability and read-only=false")
	}
	r, e := host.DecodeRequest(q.GetConfigurationJson())
	if e != nil {
		return nil, hostError(e)
	}
	if s.engine == nil {
		return nil, status.Error(codes.FailedPrecondition, "host recovery storage is required")
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	out, e := s.engine.Ensure(ctx, r, hostConnection(ctx))
	if e != nil {
		return nil, hostError(e)
	}
	return hostResponse(out), nil
}
func (s *hostServer) Confirm(ctx context.Context, q *hp.HostConfirmation) (*hp.HostResult, error) {
	if !s.writes {
		return nil, status.Error(codes.PermissionDenied, "host writes require explicit host capability and read-only=false")
	}
	if s.engine == nil {
		return nil, status.Error(codes.FailedPrecondition, "host recovery storage is required")
	}
	if len(q.GetOwner()) > 256 || len(q.GetTarget()) > 256 || len(q.GetTransaction()) != 64 || len(q.GetChallenge()) != 64 {
		return nil, hostError(host.ErrInvalid)
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, e := s.engine.Confirm(ctx, host.Confirmation{Owner: q.GetOwner(), Target: q.GetTarget(), Transaction: q.GetTransaction(), Challenge: q.GetChallenge()}, hostConnection(ctx))
	if e != nil {
		return nil, hostError(e)
	}
	return hostResponse(out), nil
}
func registerHost(s *grpc.Server, backend *sonic.SonicAgent) error {
	server := &hostServer{writes: *allowHostConfig && !*readOnly}
	if server.writes {
		cfg, err := host.ReadRecoveryConfig()
		if err != nil || cfg != (host.RecoveryConfig{JournalDir: *hostJournalDir, RedisAddress: *redisAddr, VLANJournalDir: *vlanAuthorityJournalDir, BreakoutJournalDir: *breakoutJournalDir, NetworkJournalDir: *networkJournalDir}) {
			return host.ErrStorage
		}
	}
	if *hostJournalDir != "" {
		if err := backend.ConfigureHostJournal(*hostJournalDir); err != nil {
			return err
		}
		e, err := host.NewEngine(*hostJournalDir, backend.NewHostNative())
		if err != nil {
			return err
		}
		server.engine = e
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		if err = e.RecoverExpired(ctx); err != nil {
			return err
		}
	} else if server.writes {
		return host.ErrStorage
	}
	hp.RegisterHostServiceServer(s, server)
	return nil
}
