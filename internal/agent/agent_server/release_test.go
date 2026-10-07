// SPDX-License-Identifier: Apache-2.0
package agent_server

import (
	"context"
	"net"
	"reflect"
	"testing"

	"github.com/ironcore-dev/sonic-operator/internal/agent/releaseinfo"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestReleaseCapabilitiesReadOnlyGRPC(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := newArtifactAdmission()
	s := grpc.NewServer(grpc.InTapHandle(a.tap), grpc.StatsHandler(a))
	pb.RegisterArtifactServiceServer(s, &artifactServer{allow: false})
	go func() { _ = s.Serve(l) }()
	defer s.Stop()
	c, err := grpc.NewClient(l.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	for range 2 {
		got, err := pb.NewArtifactServiceClient(c).GetCapabilities(context.Background(), &pb.ArtifactCapabilitiesRequest{})
		if err != nil {
			t.Fatal(err)
		}
		want := releaseinfo.Current()
		if got.SourceCommit != want.SourceCommit || !reflect.DeepEqual(got.Capabilities, want.Capabilities) {
			t.Fatal("loaded declaration mismatch")
		}
	}
}

func TestReleaseCapabilitiesRejectsPayload(t *testing.T) {
	r := &pb.ArtifactCapabilitiesRequest{}
	r.ProtoReflect().SetUnknown([]byte{0x0a, 0x01, 0x00})
	if _, err := (&artifactServer{}).GetCapabilities(context.Background(), r); err == nil {
		t.Fatal("nonempty capability request accepted")
	}
}
