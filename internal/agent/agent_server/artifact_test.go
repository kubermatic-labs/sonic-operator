// SPDX-License-Identifier: Apache-2.0
package agent_server

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ironcore-dev/sonic-operator/internal/artifact"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestArtifactProtocolGuards(t *testing.T) {
	calls := 0
	s := &artifactServer{execute: func(context.Context, artifact.Request) (*artifact.Result, error) {
		calls++
		return &artifact.Result{}, nil
	}}
	data := []byte(`{"ports":[]}`)
	b := artifact.Bundle{Owner: "owner", Target: "target", Generation: 1, Baseline: "base", Files: []artifact.File{{Slot: "PlatformJSON", SHA256: artifact.Digest(data), Data: data}}}
	raw, _ := json.Marshal(b)
	if _, err := s.Stage(context.Background(), &pb.ArtifactRequest{BundleJson: raw}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unguarded stage %v", err)
	}
	s.allow = true
	if _, err := s.Stage(context.Background(), &pb.ArtifactRequest{BundleJson: []byte(`{"command":"sh"}`)}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("unknown field %v", err)
	}
	b.Files[0].Slot = "../../etc/passwd"
	bad, _ := json.Marshal(b)
	if _, err := s.Stage(context.Background(), &pb.ArtifactRequest{BundleJson: bad}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("destination %v", err)
	}
	if calls != 0 {
		t.Fatal("invalid request reached supervisor")
	}
	if _, err := s.Stage(context.Background(), &pb.ArtifactRequest{BundleJson: raw}); status.Code(err) != codes.InvalidArgument {
		t.Fatal("inline payload bypassed chunk admission")
	}
	b.Files[0].Slot = "PlatformJSON"
	b.Files[0].Data = nil
	raw, _ = json.Marshal(b)
	if _, err := s.Stage(context.Background(), &pb.ArtifactRequest{BundleJson: raw}); err != nil || calls != 1 {
		t.Fatalf("valid stage %v", err)
	}
}

func TestBootstrapRPCIsIndependentAndWriteGated(t *testing.T) {
	calls := 0
	s := &artifactServer{bootstrap: func(context.Context, artifact.Bundle) error { calls++; return nil }, execute: func(context.Context, artifact.Request) (*artifact.Result, error) {
		t.Fatal("bootstrap depended on supervisor being available")
		return nil, nil
	}}
	b := artifact.Bundle{Owner: "owner", Target: "target", Generation: 1, Baseline: "base", Files: []artifact.File{{Slot: "PlatformJSON", SHA256: artifact.Digest([]byte(`{}`))}}}
	raw, _ := json.Marshal(b)
	if _, err := s.Bootstrap(context.Background(), &pb.ArtifactRequest{BundleJson: raw}); status.Code(err) != codes.PermissionDenied || calls != 0 {
		t.Fatal("ungated bootstrap")
	}
	s.allow = true
	if _, err := s.Bootstrap(context.Background(), &pb.ArtifactRequest{BundleJson: raw}); status.Code(err) != codes.InvalidArgument || calls != 0 {
		t.Fatal("incomplete bootstrap reached mutation backend")
	}
	b.Bootstrap = &artifact.Bootstrap{SupervisorSHA256: artifact.Digest([]byte("code")), PolicySHA256: artifact.Digest([]byte(`{}`)), UnitSHA256: artifact.Digest([]byte(artifact.SupervisorUnit))}
	raw, _ = json.Marshal(b)
	result, err := s.Bootstrap(context.Background(), &pb.ArtifactRequest{BundleJson: raw})
	if err != nil || calls != 1 || result.RecoveryPhase != "BootstrapReady" {
		t.Fatalf("independent bootstrap failed: %+v %v", result, err)
	}
}

func TestArtifactRejectionCarriesFilteredReason(t *testing.T) {
	b := artifact.Bundle{Owner: "owner", Target: "target", Generation: 1, Baseline: "base", Files: []artifact.File{{Slot: "PlatformJSON", SHA256: strings.Repeat("a", 64)}}}
	raw, _ := json.Marshal(b)
	for _, tc := range []struct {
		err  error
		want string
	}{
		{errors.New("external artifact supervisor rejected operation: agent binary is outside accepted release set"), "artifact supervisor rejected operation: external artifact supervisor rejected operation: agent binary is outside accepted release set"},
		{errors.New("-----BEGIN PRIVATE KEY-----"), "artifact supervisor rejected operation: unclassified"},
	} {
		s := &artifactServer{allow: true, execute: func(context.Context, artifact.Request) (*artifact.Result, error) { return nil, tc.err }}
		_, err := s.Observe(context.Background(), &pb.ArtifactRequest{BundleJson: raw})
		if status.Code(err) != codes.FailedPrecondition || status.Convert(err).Message() != tc.want {
			t.Fatalf("got %v, want %q", err, tc.want)
		}
	}
}
