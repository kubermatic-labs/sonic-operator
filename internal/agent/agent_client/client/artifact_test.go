// SPDX-License-Identifier: Apache-2.0
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"sync"
	"testing"

	"github.com/ironcore-dev/sonic-operator/internal/artifact"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type artifactWireFixture struct {
	pb.UnimplementedArtifactServiceServer
	mu             sync.Mutex
	events         []string
	data           []byte
	uploaded       []byte
	cached, badAck bool
	request        *pb.ArtifactRequest
}

func (s *artifactWireFixture) PrepareContent(_ context.Context, q *pb.ArtifactPrepareRequest) (*pb.ArtifactPrepareResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, "prepare")
	if len(q.Blobs) != 1 || q.Blobs[0].Sha256 != artifact.Digest(s.data) || q.Blobs[0].Size != uint64(len(s.data)) {
		return nil, errors.New("unexpected manifest")
	}
	offset := uint64(0)
	if s.cached {
		offset = uint64(len(s.data))
	}
	return &pb.ArtifactPrepareResponse{Session: "session", Offsets: []*pb.ArtifactOffset{{Sha256: artifact.Digest(s.data), Offset: offset}}}, nil
}
func (s *artifactWireFixture) UploadContent(_ context.Context, q *pb.ArtifactChunkRequest) (*pb.ArtifactChunkResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if q.Session != "session" || q.Sha256 != artifact.Digest(s.data) || q.Offset != uint64(len(s.uploaded)) || len(q.Data) > artifact.ChunkBytes {
		return nil, errors.New("unexpected chunk")
	}
	s.uploaded = append(s.uploaded, q.Data...)
	s.events = append(s.events, "chunk")
	offset := uint64(len(s.uploaded))
	if s.badAck {
		offset++
	}
	return &pb.ArtifactChunkResponse{Offset: offset}, nil
}
func (s *artifactWireFixture) dispatch(op string, q *pb.ArtifactRequest) (*pb.ArtifactResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, op)
	s.request = q
	return &pb.ArtifactResponse{ConfigurationVerified: true}, nil
}
func (s *artifactWireFixture) Bootstrap(_ context.Context, q *pb.ArtifactRequest) (*pb.ArtifactResponse, error) {
	return s.dispatch("bootstrap", q)
}
func (s *artifactWireFixture) Stage(_ context.Context, q *pb.ArtifactRequest) (*pb.ArtifactResponse, error) {
	return s.dispatch("stage", q)
}
func (s *artifactWireFixture) Confirm(_ context.Context, q *pb.ArtifactRequest) (*pb.ArtifactResponse, error) {
	return s.dispatch("confirm", q)
}
func (s *artifactWireFixture) Observe(_ context.Context, q *pb.ArtifactRequest) (*pb.ArtifactResponse, error) {
	return s.dispatch("observe", q)
}

func TestArtifactDispatchFreshnessAndCompatibility(t *testing.T) {
	for _, op := range []string{"bootstrap", "stage", "confirm", "observe"} {
		for _, mode := range []string{"fresh", "stale", "cached-stale", "direct", "bad-ack", "cancel"} {
			t.Run(op+"/"+mode, func(t *testing.T) {
				t.Parallel()
				data := bytes.Repeat([]byte("payload"), artifact.ChunkBytes/7+3)
				s := &artifactWireFixture{data: data, cached: mode == "cached-stale", badAck: mode == "bad-ack"}
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				server := grpc.NewServer()
				pb.RegisterArtifactServiceServer(server, s)
				t.Cleanup(server.Stop)
				go func() { _ = server.Serve(listener) }()
				conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = conn.Close() })
				c := &defaultSwitchAgentClient{conn: conn}
				b := artifact.Bundle{Owner: "owner", Target: "target", Generation: 1, Baseline: "base", Files: []artifact.File{{Slot: "PlatformJSON", Data: data, SHA256: artifact.Digest(data)}}}
				if op == "bootstrap" {
					b.Bootstrap = &artifact.Bootstrap{Supervisor: data, Policy: data, SupervisorSHA256: artifact.Digest(data), PolicySHA256: artifact.Digest(data), UnitSHA256: artifact.Digest([]byte(artifact.SupervisorUnit))}
				}
				before, _ := json.Marshal(b)
				stale := errors.New("stale inputs")
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				check := func(ctx context.Context) error {
					if _, ok := ctx.Deadline(); !ok {
						return errors.New("missing overall deadline")
					}
					s.mu.Lock()
					defer s.mu.Unlock()
					s.events = append(s.events, "fresh")
					if (op == "bootstrap" || op == "stage") && !s.cached && !bytes.Equal(s.data, s.uploaded) {
						return errors.New("freshness ran before final chunk")
					}
					if mode == "stale" || mode == "cached-stale" {
						return stale
					}
					if mode == "cancel" {
						cancel()
						return ctx.Err()
					}
					return nil
				}
				q := artifact.Request{Operation: op, Bundle: b, Token: "token"}
				if mode == "direct" {
					_, err = c.Artifact(ctx, q)
				} else {
					fresh, ok := any(c).(interface {
						ArtifactFresh(context.Context, artifact.Request, func(context.Context) error) (*artifact.Result, error)
					})
					if !ok {
						t.Fatal("client missing dispatch freshness capability")
					}
					_, err = fresh.ArtifactFresh(ctx, q, check)
				}
				after, _ := json.Marshal(b)
				if !bytes.Equal(before, after) {
					t.Fatal("caller bundle changed")
				}
				s.mu.Lock()
				defer s.mu.Unlock()
				transfer := op == "bootstrap" || op == "stage"
				blocked := op != "observe" && (mode == "stale" || mode == "cached-stale" || mode == "cancel" || (transfer && mode == "bad-ack"))
				if blocked {
					if err == nil || s.request != nil {
						t.Fatalf("stale/failed transfer dispatched: err=%v events=%v", err, s.events)
					}
					if (mode == "stale" || mode == "cached-stale") && !errors.Is(err, stale) {
						t.Fatalf("lost callback error: %v", err)
					}
					if mode == "cancel" && !errors.Is(err, context.Canceled) {
						t.Fatalf("lost callback cancellation: %v", err)
					}
					return
				}
				if err != nil || s.request == nil {
					t.Fatalf("dispatch failed: %v events=%v", err, s.events)
				}
				if op != "observe" && mode != "direct" && !reflect.DeepEqual(s.events[len(s.events)-2:], []string{"fresh", op}) {
					t.Fatalf("not immediately before dispatch: %v", s.events)
				}
				var sent artifact.Bundle
				if err := json.Unmarshal(s.request.BundleJson, &sent); err != nil {
					t.Fatal(err)
				}
				if len(sent.Files[0].Data) != 0 || (sent.Bootstrap != nil && (len(sent.Bootstrap.Supervisor) != 0 || len(sent.Bootstrap.Policy) != 0)) {
					t.Fatal("content serialized in final dispatch")
				}
				if s.request.ConfirmationToken != "token" {
					t.Fatal("token lost")
				}
			})
		}
	}
}

func TestArtifactRPCErrorKeepsFilteredReason(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{status.Error(codes.FailedPrecondition, "artifact supervisor rejected operation: running and installed agent executables differ"), "artifact confirm RPC failed: FailedPrecondition: artifact supervisor rejected operation: running and installed agent executables differ"},
		{status.Error(codes.Unavailable, "connection error: desc = \"transport: secret\""), "artifact confirm RPC failed: Unavailable: unclassified"},
		{context.DeadlineExceeded, "artifact confirm RPC failed: deadline exceeded"},
		{errors.New("plain failure"), "artifact confirm RPC failed: plain failure"},
	} {
		if got := artifactRPCError("confirm", tc.err).Error(); got != tc.want {
			t.Errorf("got %q, want %q", got, tc.want)
		}
	}
}
