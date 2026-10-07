// SPDX-License-Identifier: Apache-2.0
package agent_server

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/ironcore-dev/sonic-operator/internal/artifact"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/tap"
)

func TestArtifactAdmissionPrecedesDecodeAndSurvivesCancellationUntilEnd(t *testing.T) {
	admission := newArtifactAdmission()
	ctx, cancel := context.WithCancel(context.Background())
	first, err := admission.tap(ctx, &tap.Info{FullMethodName: "/artifact.ArtifactService/Stage"})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	for range 100 {
		if _, err := admission.tap(context.Background(), &tap.Info{FullMethodName: "/artifact.ArtifactService/Observe"}); status.Code(err) != codes.ResourceExhausted {
			t.Fatal("canceled-but-running request lost its admission lease")
		}
	}
	admission.HandleRPC(first, &stats.End{})
	second, err := admission.tap(context.Background(), &tap.Info{FullMethodName: "/artifact.ArtifactService/UploadContent"})
	if err != nil {
		t.Fatal(err)
	}
	admission.HandleRPC(second, &stats.End{})
	if _, err := admission.tap(context.Background(), &tap.Info{FullMethodName: "/other.Service/Read"}); err != nil {
		t.Fatal("unrelated small RPC blocked")
	}
}

func TestGRPCRejectsConcurrentArtifactBeforeHandlerAndReleasesCanceledRPC(t *testing.T) {
	admission := newArtifactAdmission()
	server := grpc.NewServer(grpc.MaxRecvMsgSize(4<<20), grpc.InTapHandle(admission.tap), grpc.StatsHandler(admission))
	listener := bufconn.Listen(1 << 20)
	entered := make(chan struct{}, 1)
	pb.RegisterArtifactServiceServer(server, &artifactServer{execute: func(ctx context.Context, _ artifact.Request) (*artifact.Result, error) {
		entered <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}})
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	connection, err := grpc.NewClient("passthrough:///fixture", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	client := pb.NewArtifactServiceClient(connection)
	raw, _ := json.Marshal(artifact.Bundle{Owner: "o", Target: "t", Generation: 1, Baseline: "b", Files: []artifact.File{{Slot: "PlatformJSON", SHA256: artifact.Digest([]byte(`{}`))}}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := client.Observe(ctx, &pb.ArtifactRequest{BundleJson: raw}); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first RPC did not reach slow native handler")
	}
	for range 8 {
		_, err := client.Observe(context.Background(), &pb.ArtifactRequest{BundleJson: make([]byte, 1<<20)})
		if status.Code(err) != codes.ResourceExhausted {
			t.Fatalf("concurrent decode not rejected: %v", err)
		}
	}
	cancel()
	<-done
	deadline := time.Now().Add(time.Second)
	for len(admission.slots) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(admission.slots) != 0 {
		t.Fatal("canceled RPC admission leaked")
	}
}
