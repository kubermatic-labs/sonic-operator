// SPDX-License-Identifier: Apache-2.0

package agent_server

import (
	"context"
	"fmt"
	"path/filepath"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *proxyServer) GetNetworkResource(ctx context.Context, request *pb.NetworkRequest) (*pb.NetworkResponse, error) {
	return s.networkResource(ctx, request, "get")
}

func (s *proxyServer) EnsureNetworkResource(ctx context.Context, request *pb.NetworkRequest) (*pb.NetworkResponse, error) {
	return s.networkResource(ctx, request, "ensure")
}

func (s *proxyServer) RecoverNetworkResource(ctx context.Context, request *pb.NetworkRequest) (*pb.NetworkResponse, error) {
	return s.networkResource(ctx, request, "recover")
}

func (s *proxyServer) networkResource(ctx context.Context, request *pb.NetworkRequest, operation string) (*pb.NetworkResponse, error) {
	r := &agent.NetworkRequest{Kind: request.GetKind(), OwnerID: request.GetOwnerId(), Spec: request.GetSpecJson()}
	if err := agent.ValidateNetworkRequest(r, operation != "get"); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	var result *agent.NetworkResult
	var st *agent.Status
	if operation == "recover" {
		backend, ok := s.SwitchAgent.(agent.NetworkRecoveryAgent)
		if !ok {
			return nil, status.Error(codes.Unimplemented, "backend does not support network recovery")
		}
		result, st = backend.RecoverNetworkResource(ctx, r)
	} else {
		backend, ok := s.SwitchAgent.(agent.NetworkAgent)
		if !ok {
			return nil, status.Error(codes.Unimplemented, "backend does not support network resources")
		}
		if operation == "ensure" {
			result, st = backend.EnsureNetworkResource(ctx, r)
		} else {
			result, st = backend.GetNetworkResource(ctx, r)
		}
	}
	out := &pb.NetworkResponse{Status: &pb.Status{}}
	if st != nil {
		out.Status.Code, out.Status.Message = st.Code, st.Message
	}
	if result == nil {
		if out.Status.Code == 0 {
			return nil, status.Error(codes.Internal, "backend returned no network result")
		}
		return out, nil
	}
	// Keep independent verification evidence even when persistence failed.
	out.Result = &pb.NetworkResult{Exists: result.Exists, ConfigurationVerified: result.ConfigurationVerified, RuntimeVerified: result.RuntimeVerified, PersistenceVerified: result.PersistenceVerified, ObservedJson: result.Observed, Message: result.Message}
	return out, nil
}

func configureNetworkJournal(backend any, dir string, allow, readOnly bool) error {
	if dir == "" {
		if allow && !readOnly {
			return fmt.Errorf("--network-journal-dir is required when network writes are enabled")
		}
		return nil
	}
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("--network-journal-dir must be an absolute path")
	}
	j, ok := backend.(interface{ ConfigureNetworkJournal(string) error })
	if !ok {
		return fmt.Errorf("backend does not support network journals")
	}
	return j.ConfigureNetworkJournal(dir)
}
