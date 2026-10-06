// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
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

func (s *proxyServer) GetPortBreakout(ctx context.Context, request *pb.GetPortBreakoutRequest) (*pb.PortBreakoutResponse, error) {
	backend, ok := s.SwitchAgent.(agent.PortBreakoutAgent)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "backend does not support port breakout")
	}
	if request.GetPort() == "" {
		return nil, status.Error(codes.InvalidArgument, "GetPortBreakout requires port")
	}
	result, st := backend.GetPortBreakout(ctx, request.GetPort())
	return portBreakoutResponse(result, st)
}

func (s *proxyServer) ReconcilePortBreakout(ctx context.Context, request *pb.PortBreakoutRequest) (*pb.PortBreakoutResponse, error) {
	backend, ok := s.SwitchAgent.(agent.PortBreakoutAgent)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "backend does not support port breakout")
	}
	if request.GetPort() == "" || request.GetMode() == "" || (request.GetChildAdminState() != "up" && request.GetChildAdminState() != "down") {
		return nil, status.Error(codes.InvalidArgument, "ReconcilePortBreakout requires port, mode, and child_admin_state up or down")
	}
	result, st := backend.ReconcilePortBreakout(ctx, &agent.PortBreakoutRequest{
		Port: request.GetPort(), Mode: request.GetMode(), ChildAdminState: request.GetChildAdminState(),
	})
	return portBreakoutResponse(result, st)
}

func portBreakoutResponse(result *agent.PortBreakout, st *agent.Status) (*pb.PortBreakoutResponse, error) {
	if st != nil && st.Code != 0 {
		return &pb.PortBreakoutResponse{Status: &pb.Status{Code: st.Code, Message: st.Message}}, nil
	}
	if result == nil {
		return nil, status.Error(codes.Internal, "backend returned no port breakout result")
	}
	wire := &pb.PortBreakout{
		Port: result.Port, Mode: result.Mode, SupportedModes: result.SupportedModes,
		Children:        make([]*pb.PortBreakoutChild, len(result.Children)),
		RuntimeVerified: result.RuntimeVerified, PersistenceVerified: result.PersistenceVerified,
		ConfigurationVerified: result.ConfigurationVerified,
		Pending:               result.Pending, Message: result.Message,
	}
	for i, child := range result.Children {
		wire.Children[i] = &pb.PortBreakoutChild{Name: child.Name, Lanes: child.Lanes, Speed: child.Speed, AdminState: child.AdminState, Mtu: child.MTU}
	}
	return &pb.PortBreakoutResponse{Status: &pb.Status{Message: "Success"}, Result: wire}, nil
}

func configureBreakoutJournal(backend any, dir string, allow, readOnly bool) error {
	if dir == "" {
		if allow && !readOnly {
			return fmt.Errorf("--breakout-journal-dir is required when breakout writes are enabled")
		}
		return nil
	}
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("--breakout-journal-dir must be an absolute path")
	}
	// Only the backend opens and validates the private journal. Reads must not
	// initialize it, but startup can configure it for pending-operation inspection.
	journal, ok := backend.(interface{ ConfigureBreakoutJournal(string) error })
	if !ok {
		return fmt.Errorf("backend does not support breakout journals")
	}
	if err := journal.ConfigureBreakoutJournal(dir); err != nil {
		return fmt.Errorf("configure breakout journal: %w", err)
	}
	return nil
}
