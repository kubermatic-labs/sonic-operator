// SPDX-License-Identifier: Apache-2.0
package agent_server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"os"
	"sync"
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
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable")
	}
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
	engine     *host.Engine
	writes     bool
	engineMu   sync.Mutex
	loadEngine func(context.Context) (*host.Engine, error)
}

func (s *hostServer) hostEngine(ctx context.Context) (*host.Engine, error) {
	for !s.engineMu.TryLock() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
	defer s.engineMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.engine == nil && s.loadEngine != nil {
		e, err := s.loadEngine(ctx)
		if err != nil {
			return nil, err
		}
		s.engine = e
	}
	if s.engine == nil {
		return nil, host.ErrStorage
	}
	return s.engine, nil
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
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	engine, err := s.hostEngine(ctx)
	if err != nil {
		return nil, status.Error(codes.Unimplemented, "host recovery storage is not configured")
	}
	out, e := engine.Get(ctx, r, hostConnection(ctx))
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
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	engine, err := s.hostEngine(ctx)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "host recovery storage is required")
	}
	out, e := engine.Ensure(ctx, r, hostConnection(ctx))
	if e != nil {
		return nil, hostError(e)
	}
	return hostResponse(out), nil
}
func (s *hostServer) Confirm(ctx context.Context, q *hp.HostConfirmation) (*hp.HostResult, error) {
	if !s.writes {
		return nil, status.Error(codes.PermissionDenied, "host writes require explicit host capability and read-only=false")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	engine, err := s.hostEngine(ctx)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "host recovery storage is required")
	}
	if len(q.GetOwner()) > 256 || len(q.GetTarget()) > 256 || len(q.GetTransaction()) != 64 || len(q.GetChallenge()) != 64 {
		return nil, hostError(host.ErrInvalid)
	}
	out, e := engine.Confirm(ctx, host.Confirmation{Owner: q.GetOwner(), Target: q.GetTarget(), Transaction: q.GetTransaction(), Challenge: q.GetChallenge()}, hostConnection(ctx))
	if e != nil {
		return nil, hostError(e)
	}
	return hostResponse(out), nil
}
func registerHost(s *grpc.Server, backend *sonic.SonicAgent) error {
	server := &hostServer{writes: *allowHostConfig && !*readOnly}
	if _, err := os.Lstat(host.RecoveryBootstrapDir); err == nil {
		if *hostJournalDir != host.FleetRecoveryConfig().JournalDir {
			return host.ErrStorage
		}
		// Retain the host publication fence even when the suite needs repair. The
		// independent Bootstrap RPC must remain reachable across process restart.
		if err := backend.ConfigureHostJournal(*hostJournalDir); err != nil {
			return err
		}
		server.loadEngine = func(ctx context.Context) (*host.Engine, error) {
			cfg, err := host.ReadRecoveryConfig()
			if err != nil || cfg != host.FleetRecoveryConfig() || cfg != (host.RecoveryConfig{JournalDir: *hostJournalDir, RedisAddress: *redisAddr, VLANJournalDir: *vlanAuthorityJournalDir, BreakoutJournalDir: *breakoutJournalDir, NetworkJournalDir: *networkJournalDir}) {
				return nil, host.ErrStorage
			}
			if _, err := (&host.Native{}).InstallationReceipt(true); err != nil {
				return nil, err
			}
			e, err := host.NewRecoveryEngine(cfg, backend)
			if err != nil {
				return nil, err
			}
			ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
			defer cancel()
			if err = e.RecoverExpired(ctx); err != nil {
				return nil, err
			}
			return e, nil
		}
		// Failed installation readiness disables Host operations, while the same
		// listener can repair its immutable suite. Lazy binding retries after repair.
		_, _ = server.hostEngine(context.Background())
		hp.RegisterHostServiceServer(s, server)
		return nil
	}
	var cfg *host.RecoveryConfig
	_, configErr := os.Lstat(host.RecoveryConfigFile)
	if configErr != nil && !errors.Is(configErr, os.ErrNotExist) {
		return host.ErrStorage
	}
	if server.writes || configErr == nil {
		installed, err := host.ReadRecoveryConfig()
		if err != nil || installed != (host.RecoveryConfig{JournalDir: *hostJournalDir, RedisAddress: *redisAddr, VLANJournalDir: *vlanAuthorityJournalDir, BreakoutJournalDir: *breakoutJournalDir, NetworkJournalDir: *networkJournalDir}) {
			return host.ErrStorage
		}
		cfg = &installed
	}
	if *hostJournalDir != "" {
		var e *host.Engine
		var err error
		if cfg != nil {
			e, err = host.NewRecoveryEngine(*cfg, backend)
		} else {
			if err := backend.ConfigureHostJournal(*hostJournalDir); err != nil {
				return err
			}
			e, err = host.NewEngine(*hostJournalDir, backend.NewHostNative())
		}
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
