// SPDX-License-Identifier: Apache-2.0
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ironcore-dev/sonic-operator/internal/agent/releaseinfo"
	"github.com/ironcore-dev/sonic-operator/internal/artifact"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type ArtifactClient interface {
	Artifact(context.Context, artifact.Request) (*artifact.Result, error)
}

type ArtifactCapabilityClient interface {
	ArtifactCapabilities(context.Context) (releaseinfo.Info, error)
}

func (c *defaultSwitchAgentClient) ArtifactCapabilities(ctx context.Context) (releaseinfo.Info, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	r, err := pb.NewArtifactServiceClient(c.conn).GetCapabilities(ctx, &pb.ArtifactCapabilitiesRequest{}, grpc.MaxCallRecvMsgSize(artifact.MaxMetadataBytes))
	if err != nil {
		return releaseinfo.Info{}, fmt.Errorf("agent capability response unavailable")
	}
	i := releaseinfo.Info{SourceCommit: r.SourceCommit, Capabilities: r.Capabilities}
	if err := releaseinfo.Validate(i); err != nil {
		return releaseinfo.Info{}, err
	}
	return i, nil
}

// FreshArtifactClient checks controller-local inputs after content transfer and
// immediately before a mutating RPC. The callback is never sent to the agent.
// Observe does not invoke it; nil preserves the ordinary Artifact contract.
type FreshArtifactClient interface {
	ArtifactFresh(context.Context, artifact.Request, func(context.Context) error) (*artifact.Result, error)
}

func (c *defaultSwitchAgentClient) Artifact(ctx context.Context, r artifact.Request) (*artifact.Result, error) {
	return c.ArtifactFresh(ctx, r, nil)
}

//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func (c *defaultSwitchAgentClient) ArtifactFresh(ctx context.Context, r artifact.Request, fresh func(context.Context) error) (*artifact.Result, error) {
	var expectedRelease releaseinfo.Info
	var acceptedPolicy artifact.Policy
	var checkRelease bool
	if r.Operation == "observe" || r.Operation == "confirm" {
		var hash string
		var err error
		acceptedPolicy, hash, err = agentReleasePolicy(r.Bundle)
		if err != nil {
			return nil, err
		}
		checkRelease = hash != ""
		expectedRelease = acceptedPolicy.AgentBuilds[hash]
	}
	expected, hasCert, err := expectedArtifactChain(r.Bundle)
	if err != nil {
		return nil, err
	}
	if r.Operation != "observe" && r.Operation != "stage" && r.Operation != "confirm" && r.Operation != "bootstrap" {
		return nil, fmt.Errorf("unsupported artifact operation")
	}
	if err := r.Bundle.Validate(r.Operation == "stage"); err != nil {
		return nil, err
	}
	content := map[string][]byte{}
	if r.Operation == "stage" {
		for _, f := range r.Bundle.Files {
			content[f.SHA256] = f.Data
		}
	}
	if r.Operation == "bootstrap" && r.Bundle.Bootstrap != nil {
		content = r.Bundle.BootstrapContent()
	}
	r.Bundle = r.Bundle.WithoutContent()
	raw, err := json.Marshal(r.Bundle)
	if err != nil {
		return nil, fmt.Errorf("invalid artifact bundle")
	}
	request := &pb.ArtifactRequest{BundleJson: raw, ConfirmationToken: r.Token}
	client := pb.NewArtifactServiceClient(c.conn)
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if r.Operation == "stage" || r.Operation == "bootstrap" {
		manifest := &pb.ArtifactPrepareRequest{BundleJson: raw, Operation: r.Operation}
		for hash, data := range content {
			manifest.Blobs = append(manifest.Blobs, &pb.ArtifactBlob{Sha256: hash, Size: uint64(len(data))})
		}
		prepared, err := client.PrepareContent(ctx, manifest)
		if err != nil {
			return nil, fmt.Errorf("artifact content preparation failed")
		}
		request.ContentSession = prepared.Session
		for _, progress := range prepared.Offsets {
			data, ok := content[progress.Sha256]
			if !ok || progress.Offset > uint64(len(data)) {
				return nil, fmt.Errorf("invalid content acknowledgement")
			}
			for offset := progress.Offset; offset < uint64(len(data)); {
				end := offset + artifact.ChunkBytes
				if end > uint64(len(data)) {
					end = uint64(len(data))
				}
				reply, err := client.UploadContent(ctx, &pb.ArtifactChunkRequest{Session: prepared.Session, Sha256: progress.Sha256, Offset: offset, Data: data[offset:end]})
				if err != nil || reply.Offset != end {
					return nil, fmt.Errorf("artifact chunk transfer failed")
				}
				offset = end
			}
		}
	}
	var out *pb.ArtifactResponse
	candidateRelease := true
	if checkRelease {
		loaded, err := c.ArtifactCapabilities(ctx)
		candidateRelease = releaseinfo.Equal(loaded, expectedRelease)
		accepted := false
		for _, build := range acceptedPolicy.AgentBuilds {
			accepted = accepted || releaseinfo.Equal(loaded, build)
		}
		// Observe must reach the supervisor while an accepted old release is
		// running, both before Stage and after rollback. This only qualifies the
		// capability response: the engine still verifies candidate/fallback byte
		// hashes. Old release support cannot certify the desired runtime/Confirm.
		if err != nil || !accepted || (r.Operation == "confirm" && !candidateRelease) {
			return nil, fmt.Errorf("loaded agent differs from accepted release")
		}
	}
	var tlsPeer peer.Peer
	opts := []grpc.CallOption{grpc.Peer(&tlsPeer)}
	if r.Operation != "observe" && fresh != nil {
		if err := fresh(ctx); err != nil {
			return nil, err
		}
	}
	switch r.Operation {
	case "bootstrap":
		out, err = client.Bootstrap(ctx, request, opts...)
	case "observe":
		out, err = client.Observe(ctx, request, opts...)
	case "stage":
		out, err = client.Stage(ctx, request, opts...)
	case "confirm":
		out, err = client.Confirm(ctx, request, opts...)
	}
	if err != nil {
		return nil, artifactRPCError(r.Operation, err)
	}
	if out == nil {
		return nil, fmt.Errorf("missing artifact response")
	}
	out.RuntimeVerified = out.RuntimeVerified && candidateRelease
	if hasCert && (r.Operation == "observe" || r.Operation == "confirm") {
		out.RuntimeVerified = out.RuntimeVerified && artifactPeerMatches(tlsPeer, expected)
	}
	return &artifact.Result{Configuration: out.ConfigurationVerified, Runtime: out.RuntimeVerified, Persistence: out.PersistenceVerified, Phase: out.RecoveryPhase, Token: out.ConfirmationToken, Identity: out.Identity, Reason: out.Reason}, nil
}

func agentReleasePolicy(b artifact.Bundle) (artifact.Policy, string, error) {
	hash := ""
	for _, f := range b.Files {
		if f.Slot == "AgentBinary" {
			hash = f.SHA256
		}
	}
	if hash == "" {
		return artifact.Policy{}, "", nil
	}
	var p artifact.Policy
	if b.Bootstrap == nil || artifact.Digest(b.Bootstrap.Policy) != b.Bootstrap.PolicySHA256 || artifact.Decode(b.Bootstrap.Policy, &p) != nil || artifact.ValidateAgentRelease(p, hash) != nil {
		return artifact.Policy{}, "", fmt.Errorf("immutable accepted agent policy required for health")
	}
	return p, hash, nil
}

// artifactRPCError keeps the gRPC code and the agent's filtered reason, so a
// rejected operation can be diagnosed from the controller.
func artifactRPCError(operation string, err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return fmt.Errorf("artifact %s RPC failed: %s", operation, artifact.SafeReason(err))
	}
	return fmt.Errorf("artifact %s RPC failed: %s: %s", operation, st.Code(), artifact.SafeText(st.Message()))
}
