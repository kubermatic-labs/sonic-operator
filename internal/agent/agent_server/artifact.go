// SPDX-License-Identifier: Apache-2.0
package agent_server

import (
	"context"
	"flag"

	"github.com/ironcore-dev/sonic-operator/internal/agent/releaseinfo"

	"github.com/ironcore-dev/sonic-operator/internal/agent/sonic"

	"github.com/ironcore-dev/sonic-operator/internal/artifact"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var allowArtifacts = flag.Bool("allow-artifacts", false, "Allow declared site artifacts through the independently installed durable supervisor")
var artifactReservationV1 = flag.Bool("artifact-reservation-v1", false, "Require reciprocal durable artifact publication fencing (compatibility floor)")

type artifactServer struct {
	pb.UnimplementedArtifactServiceServer
	allow     bool
	execute   func(context.Context, artifact.Request) (*artifact.Result, error)
	bootstrap func(context.Context, artifact.Bundle) error
}

func (s *artifactServer) GetCapabilities(_ context.Context, r *pb.ArtifactCapabilitiesRequest) (*pb.ArtifactCapabilitiesResponse, error) {
	if r == nil || len(r.ProtoReflect().GetUnknown()) != 0 {
		return nil, status.Error(codes.InvalidArgument, "empty capability request required")
	}
	i := releaseinfo.Current()
	return &pb.ArtifactCapabilitiesResponse{SourceCommit: i.SourceCommit, Capabilities: i.Capabilities}, nil
}

func (s *artifactServer) Bootstrap(ctx context.Context, r *pb.ArtifactRequest) (*pb.ArtifactResponse, error) {
	return s.call(ctx, r, "bootstrap")
}

func (s *artifactServer) Observe(ctx context.Context, r *pb.ArtifactRequest) (*pb.ArtifactResponse, error) {
	return s.call(ctx, r, "observe")
}
func (s *artifactServer) Stage(ctx context.Context, r *pb.ArtifactRequest) (*pb.ArtifactResponse, error) {
	return s.call(ctx, r, "stage")
}
func (s *artifactServer) Confirm(ctx context.Context, r *pb.ArtifactRequest) (*pb.ArtifactResponse, error) {
	return s.call(ctx, r, "confirm")
}
func (s *artifactServer) call(ctx context.Context, r *pb.ArtifactRequest, op string) (*pb.ArtifactResponse, error) {
	if op != "observe" && !s.allow {
		return nil, status.Error(codes.PermissionDenied, "artifacts require --allow-artifacts=true and --read-only=false")
	}
	var b artifact.Bundle
	if r == nil || len(r.BundleJson) > artifact.MaxMetadataBytes || artifact.Decode(r.BundleJson, &b) != nil || artifact.MetadataOnly(b) != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid typed artifact request")
	}
	if op != "stage" {
		for _, f := range b.Files {
			if len(f.Data) > 0 {
				return nil, status.Error(codes.InvalidArgument, "content is only accepted for staging")
			}
		}
	}
	if op == "bootstrap" {
		if b.Bootstrap == nil {
			return nil, status.Error(codes.InvalidArgument, "complete immutable bootstrap content required")
		}
		bootstrap := s.bootstrap
		if bootstrap == nil {
			bootstrap = func(ctx context.Context, b artifact.Bundle) error {
				return artifact.BootstrapAgent(ctx, b, func() (artifact.WriterFence, error) { return sonic.NewFleetArtifactWriterFence() })
			}
			var err error
			b, err = artifact.HydrateContent(ctx, "/", b, op, r.ContentSession)
			if err != nil {
				return nil, status.Error(codes.FailedPrecondition, "bootstrap content unavailable: "+artifact.SafeReason(err))
			}
		}
		if err := bootstrap(ctx, b); err != nil {
			return nil, status.Error(codes.FailedPrecondition, "declared bootstrap ownership or activation failed: "+artifact.SafeReason(err))
		}
		return &pb.ArtifactResponse{ConfigurationVerified: true, RuntimeVerified: true, PersistenceVerified: true, RecoveryPhase: "BootstrapReady"}, nil
	}
	out, err := s.execute(ctx, artifact.Request{Operation: op, Bundle: b, Token: r.ConfirmationToken, ContentSession: r.ContentSession})
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "artifact supervisor rejected operation: "+artifact.SafeReason(err))
	}
	if out == nil {
		return nil, status.Error(codes.Internal, "missing artifact result")
	}
	return &pb.ArtifactResponse{ConfigurationVerified: out.Configuration, RuntimeVerified: out.Runtime, PersistenceVerified: out.Persistence, RecoveryPhase: out.Phase, ConfirmationToken: out.Token, Identity: out.Identity, Reason: out.Reason}, nil
}
