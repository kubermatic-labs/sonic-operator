// SPDX-License-Identifier: Apache-2.0
package agent_server

import (
	"context"

	"github.com/ironcore-dev/sonic-operator/internal/artifact"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *artifactServer) PrepareContent(ctx context.Context, r *pb.ArtifactPrepareRequest) (*pb.ArtifactPrepareResponse, error) {
	if !s.allow {
		return nil, status.Error(codes.PermissionDenied, "artifact writes disabled")
	}
	var b artifact.Bundle
	if r == nil || len(r.BundleJson) > artifact.MaxMetadataBytes || artifact.Decode(r.BundleJson, &b) != nil || artifact.MetadataOnly(b) != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid metadata content manifest")
	}
	blobs := make([]artifact.Blob, 0, len(r.Blobs))
	for _, blob := range r.Blobs {
		blobs = append(blobs, artifact.Blob{SHA256: blob.Sha256, Size: blob.Size})
	}
	session, offsets, err := artifact.PrepareContent(ctx, "/", b, r.Operation, blobs)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "content preparation rejected")
	}
	out := &pb.ArtifactPrepareResponse{Session: session.ID}
	for _, offset := range offsets {
		out.Offsets = append(out.Offsets, &pb.ArtifactOffset{Sha256: offset.SHA256, Offset: offset.Offset})
	}
	return out, nil
}
func (s *artifactServer) UploadContent(ctx context.Context, r *pb.ArtifactChunkRequest) (*pb.ArtifactChunkResponse, error) {
	if !s.allow {
		return nil, status.Error(codes.PermissionDenied, "artifact writes disabled")
	}
	if r == nil || len(r.Data) > artifact.ChunkBytes {
		return nil, status.Error(codes.InvalidArgument, "invalid bounded content chunk")
	}
	offset, err := artifact.UploadContent(ctx, "/", r.Session, r.Sha256, r.Offset, r.Data)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "content chunk rejected")
	}
	return &pb.ArtifactChunkResponse{Offset: offset}, nil
}
