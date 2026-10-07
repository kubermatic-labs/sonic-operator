// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	agentclient "github.com/ironcore-dev/sonic-operator/internal/agent/agent_client/client"
	"github.com/ironcore-dev/sonic-operator/internal/agent/artifactstate"
	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
	"github.com/ironcore-dev/sonic-operator/internal/agent/releaseinfo"
	"github.com/ironcore-dev/sonic-operator/internal/artifact"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// The transport is real mTLS and staging/confirmation/rollback use the real
// protected artifact store and host bootstrap installer/read-only verification.
// Native execution/service probes are injected: fixture ELF bytes are never run.
type releaseLifecycleWire struct {
	pb.UnimplementedArtifactServiceServer
	mu                                     sync.Mutex
	engine                                 *artifact.Engine
	policy                                 artifact.Policy
	root                                   string
	loaded                                 releaseinfo.Info
	runningHash                            string
	content                                map[string][]byte
	stages, acceptedStages, confirms       int
	observations                           []string
	confirmPeer                            string
	hostFence                              *lifecycleHostFence
	hostActivations, reservationBootstraps int
}

func (s *releaseLifecycleWire) GetCapabilities(context.Context, *pb.ArtifactCapabilitiesRequest) (*pb.ArtifactCapabilitiesResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return &pb.ArtifactCapabilitiesResponse{SourceCommit: s.loaded.SourceCommit, Capabilities: append([]string(nil), s.loaded.Capabilities...)}, nil
}
func (s *releaseLifecycleWire) PrepareContent(_ context.Context, q *pb.ArtifactPrepareRequest) (*pb.ArtifactPrepareResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.content = map[string][]byte{}
	out := &pb.ArtifactPrepareResponse{Session: "release-fixture"}
	for _, b := range q.Blobs {
		out.Offsets = append(out.Offsets, &pb.ArtifactOffset{Sha256: b.Sha256})
	}
	return out, nil
}
func (s *releaseLifecycleWire) UploadContent(_ context.Context, q *pb.ArtifactChunkRequest) (*pb.ArtifactChunkResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if q.Offset != uint64(len(s.content[q.Sha256])) || len(q.Data) > artifact.ChunkBytes {
		return nil, fmt.Errorf("invalid fixture chunk")
	}
	s.content[q.Sha256] = append(s.content[q.Sha256], q.Data...)
	return &pb.ArtifactChunkResponse{Offset: uint64(len(s.content[q.Sha256]))}, nil
}
func (s *releaseLifecycleWire) Bootstrap(ctx context.Context, q *pb.ArtifactRequest) (*pb.ArtifactResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b artifact.Bundle
	if artifact.Decode(q.BundleJson, &b) != nil || b.Bootstrap == nil || b.Bootstrap.HostRecovery == nil {
		return nil, fmt.Errorf("host bootstrap required")
	}
	h := b.Bootstrap.HostRecovery
	h.Binary = s.content[h.BinarySHA256]
	h.Profile = s.content[h.ProfileSHA256]
	reservation, err := artifactstate.Read(filepath.Join(s.root, artifactstate.DefaultDir))
	if err != nil {
		return nil, err
	}
	if reservation != nil && reservation.Phase == "Active" {
		s.reservationBootstraps++
	}
	err = artifact.EnsureHostBootstrap(ctx, s.root, b, s.hostFence, func(context.Context) error { s.hostActivations++; return nil })
	if err != nil {
		return nil, err
	}
	return &pb.ArtifactResponse{ConfigurationVerified: true, RuntimeVerified: true, PersistenceVerified: true}, nil
}
func releaseWireResult(r *artifact.Result, err error) (*pb.ArtifactResponse, error) {
	if err != nil {
		return nil, err
	}
	return &pb.ArtifactResponse{ConfigurationVerified: r.Configuration, RuntimeVerified: r.Runtime, PersistenceVerified: r.Persistence, RecoveryPhase: r.Phase, ConfirmationToken: r.Token, Identity: r.Identity, Reason: r.Reason}, nil
}
func (s *releaseLifecycleWire) Observe(ctx context.Context, q *pb.ArtifactRequest) (*pb.ArtifactResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b artifact.Bundle
	if artifact.Decode(q.BundleJson, &b) != nil {
		return nil, fmt.Errorf("invalid fixture metadata")
	}
	p, _ := peer.FromContext(ctx)
	s.observations = append(s.observations, p.Addr.String())
	return releaseWireResult(s.engine.Observe(b))
}
func (s *releaseLifecycleWire) Stage(ctx context.Context, q *pb.ArtifactRequest) (*pb.ArtifactResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stages++
	var b artifact.Bundle
	if artifact.Decode(q.BundleJson, &b) != nil {
		return nil, fmt.Errorf("invalid fixture metadata")
	}
	for i := range b.Files {
		b.Files[i].Data = s.content[b.Files[i].SHA256]
	}
	r, err := s.engine.EnsureContext(ctx, b, time.Now())
	if err == nil {
		s.acceptedStages++
	}
	return releaseWireResult(r, err)
}
func (s *releaseLifecycleWire) Confirm(ctx context.Context, q *pb.ArtifactRequest) (*pb.ArtifactResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.confirms++
	var b artifact.Bundle
	if artifact.Decode(q.BundleJson, &b) != nil {
		return nil, fmt.Errorf("invalid fixture metadata")
	}
	p, _ := peer.FromContext(ctx)
	s.confirmPeer = p.Addr.String()
	return releaseWireResult(s.engine.ConfirmContext(ctx, b, q.ConfirmationToken, time.Now()))
}
func (s *releaseLifecycleWire) tick(t *testing.T, when time.Time) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.engine.Tick(when); err != nil {
		t.Fatal(err)
	}
}
func (s *releaseLifecycleWire) setInfo(info releaseinfo.Info) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loaded = info
}

func releaseFixtureELF(label string) []byte {
	b := make([]byte, 120)
	copy(b, []byte{'\x7f', 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(b[16:], 2)
	binary.LittleEndian.PutUint16(b[18:], 62)
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint64(b[32:], 64)
	binary.LittleEndian.PutUint16(b[52:], 64)
	binary.LittleEndian.PutUint16(b[54:], 56)
	binary.LittleEndian.PutUint16(b[56:], 1)
	binary.LittleEndian.PutUint32(b[64:], 1)
	return append(b, []byte(label)...)
}

func releaseControllerFixture(t *testing.T, initial string) (*ArtifactReconciler, client.Client, *api.SwitchArtifact, *releaseLifecycleWire, artifact.Bundle, releaseinfo.Info, releaseinfo.Info, func() agentclient.ArtifactClient) {
	t.Helper()
	kube, obj, _, _, _ := artifactFreshnessFixture(t)
	tlsConfig := hostFreshnessTLS(t)
	a, b := releaseFixtureELF("accepted-A"), releaseFixtureELF("candidate-B")
	infoA, infoB := releaseinfo.Current(), releaseinfo.Current()
	infoA.SourceCommit = strings.Repeat("a", 40)
	infoB.SourceCommit = strings.Repeat("b", 40)
	policy := artifact.Policy{Baseline: "base", AgentBuilds: map[string]artifact.ReleaseBuild{artifact.Digest(a): infoA, artifact.Digest(b): infoB}}
	if initial == "unlisted-candidate" {
		delete(policy.AgentBuilds, artifact.Digest(b))
	}
	if initial == "unlisted-fallback" {
		delete(policy.AgentBuilds, artifact.Digest(a))
	}
	rawPolicy, _ := json.Marshal(policy)
	obj.Spec.Files = nil
	obj.Generation = 2
	obj.Spec.Activation = "AgentRestart"
	obj.Spec.Agent = &api.ArtifactAgentOptions{BindAddress: "0.0.0.0", Port: 50051, Artifacts: true, HostGuard: true, HostConfig: true}
	yes := true
	refs := map[string]api.ArtifactContentRef{}
	payloads := map[string][]byte{"AgentBinary": b, "supervisor": a, "policy": rawPolicy}
	profile, err := os.ReadFile("../../config/agent/profiles/202411.1216684-48c2d4c3e.json")
	if err != nil {
		t.Fatal(err)
	}
	payloads["host-binary"] = releaseFixtureELF("independent-watchdog")
	payloads["host-profile"] = profile
	for slot, env := range map[string]string{"AgentCertificate": "SONIC_AGENT_TLS_CERT_FILE", "AgentKey": "SONIC_AGENT_TLS_KEY_FILE", "AgentCA": "SONIC_AGENT_TLS_CA_FILE"} {
		raw, err := os.ReadFile(os.Getenv(env))
		if err != nil {
			t.Fatal(err)
		}
		payloads[slot] = raw
	}
	for name, data := range payloads {
		meta := metav1.ObjectMeta{Name: "release-" + strings.ToLower(name), Namespace: obj.Namespace, UID: types.UID("fixture-release-" + name)}
		ref := api.ArtifactContentRef{Kind: "ConfigMap", Name: meta.Name, UID: string(meta.UID), Key: "content"}
		var source client.Object = &corev1.ConfigMap{ObjectMeta: meta, Immutable: &yes, BinaryData: map[string][]byte{"content": data}}
		if artifact.SecretSlot(name) {
			ref.Kind = "Secret"
			source = &corev1.Secret{ObjectMeta: meta, Immutable: &yes, Data: map[string][]byte{"content": data}}
		}
		if err := kube.Create(t.Context(), source); err != nil {
			t.Fatal(err)
		}
		refs[name] = ref
	}
	for _, slot := range []string{"AgentBinary", "AgentCertificate", "AgentKey", "AgentCA"} {
		obj.Spec.Files = append(obj.Spec.Files, api.ArtifactFile{Slot: slot, SHA256: artifact.Digest(payloads[slot]), Chunks: []api.ArtifactContentRef{refs[slot]}})
	}
	obj.Spec.Bootstrap = &api.ArtifactBootstrapSpec{SupervisorSHA256: artifact.Digest(a), SupervisorChunks: []api.ArtifactContentRef{refs["supervisor"]}, PolicySHA256: artifact.Digest(rawPolicy), PolicyRef: refs["policy"], UnitSHA256: artifact.Digest([]byte(artifact.SupervisorUnit))}
	cfg, _ := host.EncodeRecoveryConfig(host.FleetRecoveryConfig())
	obj.Spec.Bootstrap.HostRecovery = &api.ArtifactHostRecoverySpec{BinarySHA256: artifact.Digest(payloads["host-binary"]), BinaryChunks: []api.ArtifactContentRef{refs["host-binary"]}, ProfileSHA256: artifact.Digest(profile), ProfileRef: refs["host-profile"], ServiceSHA256: artifact.Digest(host.RecoveryServiceUnit()), TimerSHA256: artifact.Digest(host.RecoveryTimerUnit()), ConfigSHA256: artifact.Digest(cfg), JournalLayout: "FleetHostV1"}
	if err := kube.Update(t.Context(), obj); err != nil {
		t.Fatal(err)
	}
	bundle, err := resolveArtifactSources(t.Context(), kube, obj, obj.Status.Target)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	write := func(path string, data []byte, mode os.FileMode) {
		t.Helper()
		p := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, mode); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range bundle.Files {
		path, mode, _ := artifact.Destination(f.Slot)
		data := f.Data
		if f.Slot == "AgentBinary" {
			data = a
		}
		write(path, data, mode)
	}
	unit, _ := artifact.AgentUnit(*bundle.Agent)
	write("etc/systemd/system/sonic-operator-agent.service", unit, 0644)
	wire := &releaseLifecycleWire{policy: policy, root: root, loaded: infoA, runningHash: artifact.Digest(a), hostFence: &lifecycleHostFence{}}
	if err := artifact.EnsureHostBootstrap(t.Context(), root, bundle, wire.hostFence, func(context.Context) error { wire.hostActivations++; return nil }); err != nil {
		t.Fatal(err)
	}
	health := func() error {
		data, err := os.ReadFile(filepath.Join(root, "usr/local/sbin/sonic-operator-agent"))
		if err != nil || artifact.Digest(data) != wire.runningHash {
			return fmt.Errorf("fixture loaded executable mismatch")
		}
		return artifact.ValidateAgentRelease(policy, wire.runningHash)
	}
	activate := func() error {
		data, err := os.ReadFile(filepath.Join(root, "usr/local/sbin/sonic-operator-agent"))
		if err != nil {
			return err
		}
		wire.runningHash = artifact.Digest(data)
		wire.loaded = policy.AgentBuilds[wire.runningHash]
		return nil
	}
	wire.engine, err = artifact.Open(root, artifactstate.DefaultDir, policy, health, activate)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { wire.engine.Close() })
	if initial == "confirmed-old" {
		old := bundle
		old.Generation = 1
		old.Files = append([]artifact.File(nil), bundle.Files...)
		old.Files[0] = artifact.File{Slot: "AgentBinary", Data: a, SHA256: artifact.Digest(a)}
		r, err := wire.engine.Ensure(old, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		wire.tick(t, time.Now())
		if _, err := wire.engine.Confirm(old, r.Token, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if initial == "unknown-capability" {
		wire.loaded.Capabilities = append(wire.loaded.Capabilities, "unknown-v1")
	}
	if initial == "unlisted-source" {
		wire.loaded.SourceCommit = strings.Repeat("c", 40)
	}
	if initial == "unlisted-binary" {
		unknown := releaseFixtureELF("unlisted-but-reports-source-A")
		write("usr/local/sbin/sonic-operator-agent", unknown, 0755)
		wire.runningHash = artifact.Digest(unknown)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	pb.RegisterArtifactServiceServer(server, wire)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	factory := func() agentclient.ArtifactClient {
		t.Helper()
		c, err := agentclient.NewDefaultSwitchAgentClient(listener.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.(io.Closer).Close() })
		return c.(agentclient.ArtifactClient)
	}
	reconciler := &ArtifactReconciler{Client: kube, APIReader: kube, AllowArtifacts: true, NewClient: func(context.Context, client.Reader, *api.Switch) (artifactRPC, io.Closer, error) {
		c := factory()
		return c, c.(io.Closer), nil
	}}
	return reconciler, kube, obj, wire, bundle, infoA, infoB, factory
}

func TestArtifactReleaseUpgradeAndRollbackThroughRealClient(t *testing.T) {
	for _, initial := range []string{"unowned", "confirmed-old"} {
		for _, outcome := range []string{"confirm", "rollback"} {
			t.Run(initial+"/"+outcome, func(t *testing.T) {
				r, kube, obj, s, bundle, infoA, infoB, newClient := releaseControllerFixture(t, initial)
				unchangedHost := captureReleaseHostSuite(t, s.root)
				hostMutations := s.hostFence.mutations
				reconcile := func() error {
					_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)})
					return err
				}
				if err := reconcile(); err != nil {
					t.Fatalf("accepted A prevented staging B: %v", err)
				}
				if s.acceptedStages != 1 || s.confirms != 0 {
					t.Fatal("candidate was not staged exactly once")
				}
				staged, err := newClient().Artifact(t.Context(), artifact.Request{Operation: "observe", Bundle: bundle})
				if err != nil || staged.Phase != "Staged" || staged.Runtime {
					t.Fatalf("A must permit staged observation without candidate runtime: %+v %v", staged, err)
				}
				if err := reconcile(); err != nil || s.acceptedStages != 1 {
					t.Fatal("staged candidate could not be observed", err)
				}
				s.tick(t, time.Now())
				reservation, err := artifactstate.Read(filepath.Join(s.root, artifactstate.DefaultDir))
				if err != nil || reservation == nil || reservation.Phase != "Active" {
					t.Fatalf("combined active reservation missing: %+v %v", reservation, err)
				}
				// Real Bootstrap takes its confirmed read-only path despite the
				// Active reservation. A's declaration still cannot confirm B.
				s.setInfo(infoA)
				if err := reconcile(); err == nil || s.confirms != 0 || s.reservationBootstraps == 0 {
					t.Fatal("active-reservation host verification or candidate gate failed", err)
				}
				s.setInfo(infoB)
				if outcome == "confirm" {
					// Even positive file/runtime readback may not certify B when the capability
					// response still identifies accepted A. Confirm must retain exact B proof.
					s.setInfo(infoA)
					observed, err := newClient().Artifact(t.Context(), artifact.Request{Operation: "observe", Bundle: bundle})
					if err != nil || observed.Phase != "AwaitingConfirmation" || observed.Runtime {
						t.Fatalf("fallback reported candidate runtime: %+v %v", observed, err)
					}
					freshCalls := 0
					_, err = newClient().(agentclient.FreshArtifactClient).ArtifactFresh(t.Context(), artifact.Request{Operation: "confirm", Bundle: bundle, Token: observed.Token}, func(context.Context) error { freshCalls++; return nil })
					if err == nil || freshCalls != 0 || s.confirms != 0 {
						t.Fatal("fallback capability passed Confirm/freshness boundary")
					}
					s.setInfo(infoB)
					before := len(s.observations)
					if err := reconcile(); err != nil {
						t.Fatal("B failed fresh confirmation", err)
					}
					if s.confirms != 1 || len(s.observations) != before+2 || s.observations[before] == s.observations[before+1] || s.confirmPeer != s.observations[before+1] {
						t.Fatal("confirmation did not use fresh candidate transport")
					}
					current := &api.SwitchArtifact{}
					if err := kube.Get(t.Context(), client.ObjectKeyFromObject(obj), current); err != nil {
						t.Fatal(err)
					}
					if current.Status.RecoveryPhase != "Confirmed" || !current.Status.RuntimeVerified || !current.Status.PersistenceVerified {
						t.Fatal("candidate not confirmed")
					}
				} else {
					s.tick(t, time.Now().Add(6*time.Minute))
					expected, err := s.engine.Observe(bundle)
					if err != nil {
						t.Fatal(err)
					}
					observed, err := newClient().Artifact(t.Context(), artifact.Request{Operation: "observe", Bundle: bundle})
					if err != nil || observed.Phase != "RolledBack" || observed.Runtime || observed.Token != expected.Token || observed.Identity != expected.Identity || observed.Reason != expected.Reason {
						t.Fatalf("accepted A hid rollback state: %+v %v", observed, err)
					}
					_ = reconcile() // Existing engine deliberately rejects restaging a rolled-back generation.
					current := &api.SwitchArtifact{}
					if err := kube.Get(t.Context(), client.ObjectKeyFromObject(obj), current); err != nil {
						t.Fatal(err)
					}
					if current.Status.RecoveryPhase != "RolledBack" || current.Status.RuntimeVerified || s.confirms != 0 || s.acceptedStages != 1 {
						t.Fatal("controller lost rollback observation or confirmed fallback")
					}
				}
				unchangedHost()
				if s.hostActivations != 1 || s.hostFence.mutations != hostMutations {
					t.Fatal("healthy Bootstrap entered host mutation/activation")
				}
			})
		}
	}
}

func captureReleaseHostSuite(t *testing.T, root string) func() {
	t.Helper()
	before := map[string][]byte{}
	identities := map[string]os.FileInfo{}
	for _, p := range []string{host.RecoveryBinaryFile, host.RecoveryConfigFile, host.RecoveryProfileFile, host.RecoveryServiceFile, host.RecoveryTimerFile, host.RecoveryReceiptFile} {
		var err error
		before[p], err = os.ReadFile(filepath.Join(root, p))
		if err != nil {
			t.Fatal("real host bootstrap suite required", err)
		}
		identities[p], err = os.Stat(filepath.Join(root, p))
		if err != nil {
			t.Fatal(err)
		}
	}
	return func() {
		t.Helper()
		for p, raw := range before {
			got, err := os.ReadFile(filepath.Join(root, p))
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(filepath.Join(root, p))
			if err != nil || !bytes.Equal(raw, got) || !os.SameFile(identities[p], info) {
				t.Fatal("healthy host bootstrap rewrote suite", p, err)
			}
		}
	}
}

func TestArtifactReleaseRejectsUnknownRunningOrUnacceptedBuild(t *testing.T) {
	for _, initial := range []string{"unknown-capability", "unlisted-source", "unlisted-binary", "unlisted-candidate", "unlisted-fallback"} {
		t.Run(initial, func(t *testing.T) {
			r, _, obj, s, bundle, _, _, _ := releaseControllerFixture(t, initial)
			_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)})
			if err == nil || s.acceptedStages != 0 || s.confirms != 0 {
				t.Fatal("unaccepted code obtained mutation authority", err)
			}
			current, err := s.engine.Observe(bundle)
			if err != nil || current.Phase != "Unowned" {
				t.Fatal("rejected admission published journal", err)
			}
		})
	}
}
