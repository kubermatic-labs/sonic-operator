// SPDX-License-Identifier: Apache-2.0
package client

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"

	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"

	"github.com/ironcore-dev/sonic-operator/internal/agent/releaseinfo"
	"github.com/ironcore-dev/sonic-operator/internal/artifact"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestReleaseHealthRequiresImmutableHashEntry(t *testing.T) {
	hash := artifact.Digest([]byte("candidate"))
	i := releaseinfo.Current()
	i.SourceCommit = strings.Repeat("a", 40)
	raw, _ := json.Marshal(artifact.Policy{AgentBuilds: map[string]artifact.ReleaseBuild{hash: i}})
	b := artifact.Bundle{Files: []artifact.File{{Slot: "AgentBinary", SHA256: hash}}, Bootstrap: &artifact.Bootstrap{Policy: raw, PolicySHA256: artifact.Digest(raw)}}
	policy, candidate, err := agentReleasePolicy(b)
	if err != nil || candidate != hash || !releaseinfo.Equal(policy.AgentBuilds[candidate], i) {
		t.Fatal(candidate, err)
	}
	b.Files[0].SHA256 = artifact.Digest([]byte("wrong"))
	if _, _, err := agentReleasePolicy(b); err == nil {
		t.Fatal("self-reported unlisted code accepted")
	}
	b.Files[0].SHA256 = hash
	b.Bootstrap.PolicySHA256 = hash
	if _, _, err := agentReleasePolicy(b); err == nil {
		t.Fatal("wrong immutable policy accepted")
	}
}

type releaseReplyServer struct {
	pb.UnimplementedArtifactServiceServer
	info releaseinfo.Info
}

func (s *releaseReplyServer) GetCapabilities(context.Context, *pb.ArtifactCapabilitiesRequest) (*pb.ArtifactCapabilitiesResponse, error) {
	return &pb.ArtifactCapabilitiesResponse{SourceCommit: s.info.SourceCommit, Capabilities: s.info.Capabilities}, nil
}

func TestReleaseCapabilitiesClientGRPCBounds(t *testing.T) {
	for _, kind := range []string{"valid", "unknown", "missing", "oversize", "source"} {
		t.Run(kind, func(t *testing.T) {
			i := releaseinfo.Current()
			i.SourceCommit = strings.Repeat("a", 40)
			switch kind {
			case "unknown":
				i.Capabilities[0] = "unknown-v1"
			case "missing":
				i.Capabilities = i.Capabilities[1:]
			case "oversize":
				i.Capabilities = []string{strings.Repeat("x", artifact.MaxMetadataBytes+1)}
			case "source":
				i.SourceCommit = "unknown"
			}
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			s := grpc.NewServer()
			pb.RegisterArtifactServiceServer(s, &releaseReplyServer{info: i})
			go s.Serve(l)
			defer s.Stop()
			conn, err := grpc.NewClient(l.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			c := &defaultSwitchAgentClient{conn: conn}
			got, err := c.ArtifactCapabilities(t.Context())
			if kind == "valid" {
				if err != nil || !releaseinfo.Equal(got, i) {
					t.Fatal("valid loaded declaration rejected", err)
				}
			} else if err == nil {
				t.Fatal("invalid capability response accepted")
			}
		})
	}
}
