//go:build integration

// SPDX-License-Identifier: Apache-2.0
package agent_server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	agentclient "github.com/ironcore-dev/sonic-operator/internal/agent/agent_client/client"
	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
	hp "github.com/ironcore-dev/sonic-operator/internal/agent/hostproto"
	"github.com/ironcore-dev/sonic-operator/internal/agent/transport"
	"github.com/ironcore-dev/sonic-operator/internal/artifact"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

type transportHostBackend struct{ state host.Management }

func (b *transportHostBackend) Exclusive(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

func TestCombinedArtifactFreshTransportUsesLoadedCertificate(t *testing.T) {
	serverCA, clientCA := issueCertificate(t, nil, 0), issueCertificate(t, nil, 0)
	a, b := issueCertificate(t, &serverCA, x509.ExtKeyUsageServerAuth), issueCertificate(t, &serverCA, x509.ExtKeyUsageServerAuth)
	client := issueCertificate(t, &clientCA, x509.ExtKeyUsageClientAuth)
	t.Setenv("SONIC_AGENT_TLS_CA_FILE", serverCA.certFile)
	t.Setenv("SONIC_AGENT_TLS_CERT_FILE", client.certFile)
	t.Setenv("SONIC_AGENT_TLS_KEY_FILE", client.keyFile)
	t.Setenv("SONIC_AGENT_TLS_SERVER_NAME", "agent.test")
	start := func() (*grpc.Server, string, *transport.LoadedTLS) {
		s, proof, err := newGRPCServerWithTLSProof(a.certFile, a.keyFile, clientCA.certFile, false, false, false, false, false, false, false)
		if err != nil {
			t.Fatal(err)
		}
		pb.RegisterArtifactServiceServer(s, &artifactServer{allow: true, execute: func(ctx context.Context, _ artifact.Request) (*artifact.Result, error) {
			if hostConnection(ctx) == "" {
				t.Error("missing combined transport identity")
			}
			return &artifact.Result{Runtime: true, Configuration: true, Persistence: true}, nil
		}})
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Stop(); lis.Close() })
		go s.Serve(lis)
		return s, lis.Addr().String(), proof
	}
	s, address, proof := start()
	aPEM, _ := os.ReadFile(a.certFile)
	if proof.Certificate != transport.TLSDigest(aPEM) {
		t.Fatal("TLS receipt does not describe loaded A")
	}
	cert, _ := os.ReadFile(b.certFile)
	key, _ := os.ReadFile(b.keyFile)
	if err := os.WriteFile(a.certFile, cert, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.keyFile, key, 0600); err != nil {
		t.Fatal(err)
	}
	bundle := artifact.Bundle{Owner: "owner", Target: "switch", Baseline: "test", Generation: 1, Files: []artifact.File{{Slot: "AgentCertificate", SHA256: artifact.Digest(cert), Data: cert}}}
	check := func(address string, want bool) {
		c, err := agentclient.NewDefaultSwitchAgentClient(address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.(interface{ Close() error }).Close()
		for _, op := range []string{"observe", "confirm"} {
			out, err := c.(agentclient.ArtifactClient).Artifact(t.Context(), artifact.Request{Operation: op, Bundle: bundle})
			if err != nil || out.Runtime != want {
				t.Fatalf("fresh %s: runtime=%+v want=%v err=%v", op, out, want, err)
			}
		}
	}
	check(address, false) // New TLS transport still receives loaded A, not disk B.
	s.Stop()
	_, address, proof = start()
	if proof.Certificate != transport.TLSDigest(cert) {
		t.Fatal("reload receipt did not change to B")
	}
	check(address, true)
}
func (b *transportHostBackend) ExclusiveRecovery(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}
func (*transportHostBackend) CheckPublication(context.Context) error    { return nil }
func (*transportHostBackend) RecoverDependencies(context.Context) error { return nil }
func (b *transportHostBackend) Observe(_ context.Context, q host.Request) (host.Result, error) {
	match := reflect.DeepEqual(b.state, *q.Management)
	return host.Result{ConfigurationVerified: match, RuntimeVerified: match, PersistenceVerified: match, GatewayVerified: match}, nil
}
func (b *transportHostBackend) VerifySaved(_ context.Context, q host.Request) error {
	if q.Management == nil || !reflect.DeepEqual(b.state, *q.Management) {
		return host.ErrNative
	}
	return nil
}
func (b *transportHostBackend) Snapshot(context.Context) (host.Snapshot, error) {
	return host.Snapshot{Management: b.state, ActiveMAC: b.state.MAC}, nil
}
func (*transportHostBackend) Validate(context.Context, host.Request) error { return nil }
func (*transportHostBackend) WatchdogReady(context.Context) error          { return nil }
func (b *transportHostBackend) ApplyManagement(_ context.Context, _ host.Snapshot, m host.Management) error {
	b.state = m
	return nil
}
func (b *transportHostBackend) RestoreManagement(_ context.Context, s host.RecoveryScope) error {
	b.state = s.Before.Management
	return nil
}
func (*transportHostBackend) ApplySystem(context.Context, host.Request) error { return nil }

type blockedArtifactUpload struct {
	pb.UnimplementedArtifactServiceServer
	entered chan string
	release chan struct{}
}

func (s *blockedArtifactUpload) UploadContent(ctx context.Context, _ *pb.ArtifactChunkRequest) (*pb.ArtifactChunkResponse, error) {
	s.entered <- hostConnection(ctx)
	<-s.release
	return nil, status.Error(codes.Canceled, "test upload complete")
}

func TestCombinedHostArtifactRealTransport(t *testing.T) {
	serverCA, clientCA := issueCertificate(t, nil, 0), issueCertificate(t, nil, 0)
	serverCert := issueCertificate(t, &serverCA, x509.ExtKeyUsageServerAuth)
	clientCert := issueCertificate(t, &clientCA, x509.ExtKeyUsageClientAuth)
	s, err := newGRPCServer(serverCert.certFile, serverCert.keyFile, clientCA.certFile, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	m := host.Management{Interface: "eth0", MAC: "02:00:00:00:00:11", Addresses: []host.Address{{Prefix: "10.0.0.11/24", Gateway: "10.0.0.1"}}}
	e, err := host.NewEngine(dir, &transportHostBackend{state: m})
	if err != nil {
		t.Fatal(err)
	}
	hp.RegisterHostServiceServer(s, &hostServer{engine: e, writes: true})
	upload := &blockedArtifactUpload{entered: make(chan string, 2), release: make(chan struct{})}
	pb.RegisterArtifactServiceServer(s, upload)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	go s.Serve(lis)
	pair, err := tls.LoadX509KeyPair(clientCert.certFile, clientCert.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(serverCA.cert)
	dial := func() *grpc.ClientConn {
		c, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: pool, Certificates: []tls.Certificate{pair}, ServerName: "agent.test", MinVersion: tls.VersionTLS12})))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	a, b := dial(), dial()
	first, fresh := hp.NewHostServiceClient(a), hp.NewHostServiceClient(b)
	m.Addresses = []host.Address{{Prefix: "10.0.0.99/24", Gateway: "10.0.0.1"}}
	q := host.Request{Kind: "Management", Owner: "owner", Target: "switch", Revision: "1", Management: &m, RollbackSeconds: 60}
	raw, _ := json.Marshal(q)
	request := &hp.HostRequest{ConfigurationJson: raw}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	pending, err := first.Ensure(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	same, err := first.Get(ctx, request)
	if err != nil || same.Challenge != "" {
		t.Fatalf("same transport challenge: %v %v", same, err)
	}
	challenge, err := fresh.Get(ctx, request)
	if err != nil || challenge.Challenge == "" {
		t.Fatalf("fresh transport proof lost by stats: %v %v", challenge, err)
	}
	confirm := &hp.HostConfirmation{Owner: q.Owner, Target: q.Target, Transaction: pending.Transaction, Challenge: challenge.Challenge}
	if _, err := first.Confirm(ctx, confirm); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("challenge accepted on old transport: %v", err)
	}
	newProof, err := fresh.Get(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Confirm(ctx, confirm); status.Code(err) != codes.FailedPrecondition {
		t.Fatal("stale challenge accepted", err)
	}
	confirm.Challenge = newProof.Challenge
	if _, err := fresh.Confirm(ctx, confirm); err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Confirm(ctx, confirm); status.Code(err) != codes.FailedPrecondition {
		t.Fatal("one-use challenge replay", err)
	}

	uCtx, uCancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		_, err := pb.NewArtifactServiceClient(a).UploadContent(uCtx, &pb.ArtifactChunkRequest{})
		done <- err
	}()
	select {
	case id := <-upload.entered:
		if id == "" {
			t.Fatal("artifact RPC lost host transport context")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	uCancel()
	<-done
	for range 8 {
		if _, err := pb.NewArtifactServiceClient(b).UploadContent(ctx, &pb.ArtifactChunkRequest{}); status.Code(err) != codes.ResourceExhausted {
			t.Fatalf("canceled running upload released lease: %v", err)
		}
	}
	if _, err := first.Get(ctx, request); err != nil {
		t.Fatal("host read starved by artifact upload", err)
	}
	close(upload.release)
	// Decode failures must also release the lease. Poll until the first End.
	for {
		_, err := pb.NewArtifactServiceClient(b).Observe(ctx, &pb.ArtifactRequest{BundleJson: make([]byte, 5<<20)})
		if status.Code(err) == codes.ResourceExhausted && ctx.Err() == nil {
			// Both admission and the receive ceiling use ResourceExhausted. A small
			// subsequent request distinguishes a released decode failure.
			_, err = pb.NewArtifactServiceClient(b).Observe(ctx, &pb.ArtifactRequest{})
			if status.Code(err) == codes.Unimplemented {
				break
			}
		}
		if ctx.Err() != nil {
			t.Fatal("decode failure leaked artifact lease")
		}
		time.Sleep(time.Millisecond)
	}
}
