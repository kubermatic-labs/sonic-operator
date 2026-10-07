// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	agentclient "github.com/ironcore-dev/sonic-operator/internal/agent/agent_client/client"
	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
	"github.com/ironcore-dev/sonic-operator/internal/agent/releaseinfo"
	"github.com/ironcore-dev/sonic-operator/internal/artifact"
	pb "github.com/ironcore-dev/sonic-operator/pkg/agent/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func hostArtifactFreshFixture(t *testing.T, environment ...bool) (client.Client, *api.SwitchArtifact, *api.Switch, *api.SwitchManagement, map[string]*corev1.ConfigMap) {
	t.Helper()
	kube, obj, sw, _, _ := artifactFreshnessFixture(t)
	dir := os.Getenv("SONIC_TEST_MAC_FIXTURE_DIR")
	if dir == "" {
		t.Skip("set SONIC_TEST_MAC_FIXTURE_DIR to the captured MAC helper scripts")
	}
	helper, err := os.ReadFile(filepath.Join(dir, "set-management-mac.sh"))
	if err != nil {
		t.Fatal("captured helper fixture unavailable", err)
	}
	profile, err := os.ReadFile("../../config/agent/profiles/202411.1216684-48c2d4c3e.json")
	if err != nil {
		t.Fatal(err)
	}
	var p host.NativeProfile
	if json.Unmarshal(profile, &p) != nil {
		t.Fatal("profile fixture")
	}
	p.LegacyMACHooks = []host.LegacyMACHook{{Kind: "management-mac-shell", BaseMAC: "00:00:5e:00:53:01", MAC: "02:00:5e:00:53:01", Addresses: []host.Address{{Prefix: "10.0.0.22/24", Gateway: "10.0.0.1"}}, HookSHA256: artifact.Digest(host.ImportedMACUnit("management-mac-shell")), HelperSHA256: host.ImportedHelperSHA256("management-mac-shell")}}
	p.ConsumerSHA256["imported-shell"] = artifact.Digest([]byte("qualified-shell"))
	withEnvironment := len(environment) > 0 && environment[0]
	if withEnvironment {
		p.ImportedMACEnvironment = host.ImportedMACEnvironmentNone
	}
	profile, _ = json.Marshal(p)
	data := map[string][]byte{"binary": bytes.Repeat([]byte("host-binary"), artifact.ChunkBytes/5), "profile": profile, "helper": helper, "hook": []byte("[Service]\nExecStartPost=/usr/local/sbin/set-management-mac\n")}
	if withEnvironment {
		data["binary"] = append(data["binary"], []byte(releaseinfo.Marker)...)
		data["supervisor"] = []byte("supervisor-test-binary" + releaseinfo.Marker)
		i := releaseinfo.Current()
		i.SourceCommit = strings.Repeat("a", 40)
		data["policy"], _ = json.Marshal(artifact.Policy{AgentBuilds: map[string]artifact.ReleaseBuild{strings.Repeat("b", 64): i}})
	}
	sources := map[string]*corev1.ConfigMap{}
	refs := map[string]api.ArtifactContentRef{}
	yes := true
	for name, payload := range data {
		source := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "host-" + name, Namespace: obj.Namespace, UID: types.UID("fixture-" + name)}, Immutable: &yes, BinaryData: map[string][]byte{"content": payload}}
		if err := kube.Create(t.Context(), source); err != nil {
			t.Fatal(err)
		}
		if err := kube.Get(t.Context(), client.ObjectKeyFromObject(source), source); err != nil {
			t.Fatal(err)
		}
		sources[name] = source
		refs[name] = api.ArtifactContentRef{Kind: "ConfigMap", Name: source.Name, UID: string(source.UID), Key: "content"}
	}
	cfg, _ := host.EncodeRecoveryConfig(host.FleetRecoveryConfig())
	obj.Spec.Agent = &api.ArtifactAgentOptions{HostGuard: true, HostConfig: true, BindAddress: "0.0.0.0", Port: 50051}
	obj.Spec.Bootstrap.HostRecovery = &api.ArtifactHostRecoverySpec{BinarySHA256: artifact.Digest(data["binary"]), BinaryChunks: []api.ArtifactContentRef{refs["binary"]}, ProfileSHA256: artifact.Digest(profile), ProfileRef: refs["profile"], ServiceSHA256: artifact.Digest(host.RecoveryServiceUnit()), TimerSHA256: artifact.Digest(host.RecoveryTimerUnit()), ConfigSHA256: artifact.Digest(cfg), JournalLayout: "FleetHostV1", MACHooks: []api.ArtifactMACHookSpec{{Kind: "management-mac-shell", SourceHookSHA256: artifact.Digest(data["hook"]), SourceHookRef: refs["hook"], HelperSHA256: artifact.Digest(helper), HelperRef: refs["helper"]}}}
	if withEnvironment {
		obj.Spec.Bootstrap.SupervisorSHA256 = artifact.Digest(data["supervisor"])
		obj.Spec.Bootstrap.SupervisorChunks = []api.ArtifactContentRef{refs["supervisor"]}
		obj.Spec.Bootstrap.PolicySHA256 = artifact.Digest(data["policy"])
		obj.Spec.Bootstrap.PolicyRef = refs["policy"]
	}
	if err := kube.Update(t.Context(), obj); err != nil {
		t.Fatal(err)
	}
	if err := kube.Get(t.Context(), client.ObjectKeyFromObject(sw), sw); err != nil {
		t.Fatal(err)
	}
	sw.Spec.MacAddress = p.LegacyMACHooks[0].BaseMAC
	if err := kube.Update(t.Context(), sw); err != nil {
		t.Fatal(err)
	}
	m := &api.SwitchManagement{ObjectMeta: metav1.ObjectMeta{Name: "management", UID: "management-uid", Generation: 1}, Spec: api.SwitchManagementSpec{NetworkResourceSpec: api.NetworkResourceSpec{SwitchRef: api.NetworkSwitchReference{Name: sw.Name}, ManagementPolicy: api.NetworkManagementPolicyManage}, Interface: "eth0", Addresses: []api.ManagementAddress{{Prefix: "10.0.0.22/24", Gateway: "10.0.0.1"}}}}
	if err := kube.Create(t.Context(), m); err != nil {
		t.Fatal(err)
	}
	return kube, obj, sw, m, sources
}

func TestImportedSupervisorSourceReaderFloor(t *testing.T) {
	for _, tc := range []struct {
		name                                                  string
		environment, hostRecovery, newPolicy, capable, reject bool
	}{
		{"environment-old-supervisor", true, true, true, false, true},
		{"environment-capable", true, true, true, true, false},
		{"no-hook-new-policy-old-supervisor", false, true, true, false, true},
		{"no-hook-new-policy-capable", false, true, true, true, false},
		{"no-host-new-policy-old-supervisor", false, false, true, false, true},
		{"no-host-new-policy-capable", false, false, true, true, false},
		{"wholly-legacy-no-hook", false, true, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kube, obj, _, _, sources := hostArtifactFreshFixture(t, true)
			setSource := func(name string, raw []byte) {
				t.Helper()
				sources[name].BinaryData["content"] = raw
				if err := kube.Update(t.Context(), sources[name]); err != nil {
					t.Fatal(err)
				}
			}
			if !tc.environment {
				var p host.NativeProfile
				if err := json.Unmarshal(sources["profile"].BinaryData["content"], &p); err != nil {
					t.Fatal(err)
				}
				p.ImportedMACEnvironment, p.LegacyMACHooks = "", nil
				delete(p.ConsumerSHA256, "imported-shell")
				raw, _ := json.Marshal(p)
				setSource("profile", raw)
				obj.Spec.Bootstrap.HostRecovery.ProfileSHA256 = artifact.Digest(raw)
				obj.Spec.Bootstrap.HostRecovery.MACHooks = nil
			}
			if !tc.hostRecovery {
				obj.Spec.Bootstrap.HostRecovery = nil
				obj.Spec.Agent.HostConfig = false
			}
			marker := releaseinfo.LegacyMarker
			if tc.capable {
				marker = releaseinfo.Marker
			}
			setSource("supervisor", []byte("supervisor-test-binary"+marker))
			obj.Spec.Bootstrap.SupervisorSHA256 = artifact.Digest(sources["supervisor"].BinaryData["content"])
			if !tc.newPolicy {
				i := releaseinfo.Current()
				i.SourceCommit = strings.Repeat("a", 40)
				i.Capabilities = slices.DeleteFunc(slices.Clone(i.Capabilities), func(s string) bool { return s == releaseinfo.ImportedMACUnit })
				raw, _ := json.Marshal(artifact.Policy{AgentBuilds: map[string]artifact.ReleaseBuild{strings.Repeat("b", 64): i}})
				setSource("policy", raw)
				obj.Spec.Bootstrap.PolicySHA256 = artifact.Digest(raw)
				setSource("binary", []byte("watchdog-test-binary"+releaseinfo.LegacyMarker))
				obj.Spec.Bootstrap.HostRecovery.BinarySHA256 = artifact.Digest(sources["binary"].BinaryData["content"])
			}
			if err := kube.Update(t.Context(), obj); err != nil {
				t.Fatal(err)
			}
			b, err := resolveArtifactSources(t.Context(), kube, obj, "target")
			if (err != nil) != tc.reject || (tc.reject && !strings.Contains(err.Error(), "supervisor")) {
				t.Fatalf("supervisor source reader floor: %v, reject=%v", err, tc.reject)
			}
			if !tc.reject && artifact.Digest(b.Bootstrap.Supervisor) != obj.Spec.Bootstrap.SupervisorSHA256 {
				t.Fatal("resolver changed supervisor payload identity")
			}
		})
	}
}

func TestImportedEnvironmentProfileSourceBinding(t *testing.T) {
	kube, obj, sw, m, sources := hostArtifactFreshFixture(t, true)
	b, err := resolveArtifactSources(t.Context(), kube, obj, "target")
	if err != nil {
		t.Fatal(err)
	}
	p, err := host.ValidateNativeProfile(b.Bootstrap.HostRecovery.Profile)
	if err != nil || p.ImportedMACEnvironment != host.ImportedMACEnvironmentNone {
		t.Fatal("resolver lost explicit recipe", err)
	}
	if b.Bootstrap.HostRecovery.ProfileSHA256 != artifact.Digest(sources["profile"].BinaryData["content"]) {
		t.Fatal("profile hash not retained")
	}
	r := &HostReconciler{APIReader: kube}
	q, inputs, err := r.hostDesired(t.Context(), m, string(sw.UID))
	if err != nil || q.Management.MAC != "" {
		t.Fatal("source resolution changed typed MAC omission", err)
	}
	source := sources["profile"]
	if err := kube.Delete(t.Context(), source); err != nil {
		t.Fatal(err)
	}
	replacement := source.DeepCopy()
	replacement.UID = "replacement-profile"
	replacement.ResourceVersion = ""
	if err := kube.Create(t.Context(), replacement); err != nil {
		t.Fatal(err)
	}
	if err := inputs.fresh(t.Context()); err == nil {
		t.Fatal("same bytes with replacement UID remained fresh")
	}
	if _, err := resolveArtifactSources(t.Context(), kube, obj, "target"); err == nil {
		t.Fatal("replacement UID bypassed immutable source binding")
	}
}

func TestHostDesiredTracksRetainedSourceIdentities(t *testing.T) {
	for _, name := range []string{"profile", "helper", "hook"} {
		t.Run(name, func(t *testing.T) {
			kube, _, sw, m, sources := hostArtifactFreshFixture(t)
			r := &HostReconciler{APIReader: kube}
			_, inputs, err := r.hostDesired(t.Context(), m, string(sw.UID))
			if err != nil {
				t.Fatal(err)
			}
			source := sources[name]
			source.Labels = map[string]string{"changed": "true"}
			if err := kube.Update(t.Context(), source); err != nil {
				t.Fatal(err)
			}
			if err := inputs.fresh(t.Context()); err == nil {
				t.Fatal("retained host source bypassed shared UID/RV reader", name)
			}
		})
	}
}

func TestHostArtifactQualificationRejectsMismatchedInputs(t *testing.T) {
	for _, change := range []string{"backend", "consumer", "config", "profile-hash", "helper-hash", "mixed-owner", "addresses"} {
		t.Run(change, func(t *testing.T) {
			kube, obj, _, m, sources := hostArtifactFreshFixture(t)
			spec := obj.Spec.Bootstrap.HostRecovery
			switch change {
			case "backend", "consumer":
				var p host.NativeProfile
				_ = json.Unmarshal(sources["profile"].BinaryData["content"], &p)
				if change == "backend" {
					p.NTPBackend = "chrony"
					p.ChronySHA256 = p.NTPsecSHA256
					p.NTPsecSHA256 = ""
				} else {
					p.ConsumerSHA256["arbitrary-executable"] = artifact.Digest([]byte("bad"))
				}
				raw, _ := json.Marshal(p)
				sources["profile"].BinaryData["content"] = raw
				spec.ProfileSHA256 = artifact.Digest(raw)
				if err := kube.Update(t.Context(), sources["profile"]); err != nil {
					t.Fatal(err)
				}
			case "config":
				spec.ConfigSHA256 = artifact.Digest([]byte("wrong Redis/journal layout"))
			case "profile-hash":
				spec.ProfileSHA256 = artifact.Digest([]byte("different profile"))
			case "helper-hash":
				spec.MACHooks[0].HelperSHA256 = artifact.Digest([]byte("unknown helper"))
			case "mixed-owner":
				m.Spec.MAC = "02:00:5e:00:53:01"
				if err := kube.Update(t.Context(), m); err != nil {
					t.Fatal(err)
				}
			case "addresses":
				m.Spec.Addresses[0].Gateway = "10.0.0.2"
				if err := kube.Update(t.Context(), m); err != nil {
					t.Fatal(err)
				}
			}
			if err := kube.Update(t.Context(), obj); err != nil {
				t.Fatal(err)
			}
			calls := 0
			r := &ArtifactReconciler{Client: kube, APIReader: kube, AllowArtifacts: true, NewClient: func(context.Context, client.Reader, *api.Switch) (artifactRPC, io.Closer, error) {
				calls++
				return nil, nil, fmt.Errorf("unexpected client creation")
			}}
			if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}); err == nil || calls != 0 {
				t.Fatalf("invalid qualification reached agent: %v calls=%d", err, calls)
			}
		})
	}
}

type hostArtifactWire struct {
	pb.UnimplementedArtifactServiceServer
	mu      sync.Mutex
	sizes   map[string]uint64
	content map[string][]byte
	last    string
	mutate  func() error
	mutated bool
	writes  int
	chunks  int
}

func (s *hostArtifactWire) PrepareContent(_ context.Context, q *pb.ArtifactPrepareRequest) (*pb.ArtifactPrepareResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b artifact.Bundle
	if artifact.Decode(q.BundleJson, &b) != nil || artifact.MetadataOnly(b) != nil {
		return nil, fmt.Errorf("not metadata")
	}
	s.sizes = map[string]uint64{}
	s.content = map[string][]byte{}
	for _, blob := range q.Blobs {
		s.sizes[blob.Sha256] = blob.Size
	}
	if s.sizes[s.last] == 0 {
		return nil, fmt.Errorf("missing last host blob")
	}
	keys := []string{}
	for hash := range s.sizes {
		if hash != s.last {
			keys = append(keys, hash)
		}
	}
	sort.Strings(keys)
	keys = append(keys, s.last)
	out := &pb.ArtifactPrepareResponse{Session: "host-session"}
	for _, hash := range keys {
		out.Offsets = append(out.Offsets, &pb.ArtifactOffset{Sha256: hash})
	}
	return out, nil
}
func (s *hostArtifactWire) UploadContent(_ context.Context, q *pb.ArtifactChunkRequest) (*pb.ArtifactChunkResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if q.Offset != uint64(len(s.content[q.Sha256])) || len(q.Data) > artifact.ChunkBytes {
		return nil, fmt.Errorf("bad chunk")
	}
	s.content[q.Sha256] = append(s.content[q.Sha256], q.Data...)
	s.chunks++
	if q.Sha256 == s.last && uint64(len(s.content[s.last])) == s.sizes[s.last] {
		for hash, size := range s.sizes {
			if uint64(len(s.content[hash])) != size || artifact.Digest(s.content[hash]) != hash {
				return nil, fmt.Errorf("callback before complete transfer")
			}
		}
		if err := s.mutate(); err != nil {
			return nil, err
		}
		s.mutated = true
	}
	return &pb.ArtifactChunkResponse{Offset: uint64(len(s.content[q.Sha256]))}, nil
}
func (s *hostArtifactWire) Bootstrap(_ context.Context, _ *pb.ArtifactRequest) (*pb.ArtifactResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writes++
	return &pb.ArtifactResponse{ConfigurationVerified: true, RuntimeVerified: true, PersistenceVerified: true}, nil
}
func (s *hostArtifactWire) Observe(_ context.Context, q *pb.ArtifactRequest) (*pb.ArtifactResponse, error) {
	var b artifact.Bundle
	_ = json.Unmarshal(q.BundleJson, &b)
	return &pb.ArtifactResponse{ConfigurationVerified: true, RuntimeVerified: true, PersistenceVerified: true, RecoveryPhase: "Confirmed", Identity: b.Identity()}, nil
}

func hostFreshnessTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "host-freshness"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	rawKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rawKey})
	dir := t.TempDir()
	for name, data := range map[string][]byte{"cert": cert, "key": keyPEM, "ca": cert} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("SONIC_AGENT_TLS_CERT_FILE", filepath.Join(dir, "cert"))
	t.Setenv("SONIC_AGENT_TLS_KEY_FILE", filepath.Join(dir, "key"))
	t.Setenv("SONIC_AGENT_TLS_CA_FILE", filepath.Join(dir, "ca"))
	t.Setenv("SONIC_AGENT_TLS_SERVER_NAME", "127.0.0.1")
	pair, err := tls.X509KeyPair(cert, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(cert)
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert}
}

func TestArtifactHostSourcesFreshAfterActualFinalBlob(t *testing.T) {
	for _, name := range []string{"profile", "helper", "hook"} {
		for _, change := range []string{"delete", "recreate", "metadata", "management", "valid"} {
			t.Run(name+"/"+change, func(t *testing.T) {
				kube, obj, _, m, sources := hostArtifactFreshFixture(t)
				wire := &hostArtifactWire{last: artifact.Digest(sources[name].BinaryData["content"])}
				wire.mutate = func() error {
					source := sources[name]
					switch change {
					case "delete":
						return kube.Delete(t.Context(), source)
					case "recreate":
						if err := kube.Delete(t.Context(), source); err != nil {
							return err
						}
						source.UID = "replacement"
						source.ResourceVersion = ""
						return kube.Create(t.Context(), source)
					case "metadata":
						source.Labels = map[string]string{"changed": "true"}
						return kube.Update(t.Context(), source)
					case "management":
						m.Spec.MAC = "02:00:5e:00:53:01"
						return kube.Update(t.Context(), m)
					}
					return nil
				}
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				server := grpc.NewServer(grpc.Creds(credentials.NewTLS(hostFreshnessTLS(t))))
				pb.RegisterArtifactServiceServer(server, wire)
				t.Cleanup(server.Stop)
				go func() { _ = server.Serve(listener) }()
				r := &ArtifactReconciler{Client: kube, APIReader: kube, AllowArtifacts: true, NewClient: func(context.Context, client.Reader, *api.Switch) (artifactRPC, io.Closer, error) {
					c, err := agentclient.NewDefaultSwitchAgentClient(listener.Addr().String(), time.Second)
					if err != nil {
						return nil, nil, err
					}
					return c.(artifactRPC), c.(io.Closer), nil
				}}
				_, err = r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)})
				wire.mu.Lock()
				defer wire.mu.Unlock()
				if !wire.mutated || wire.chunks < 5 {
					t.Fatalf("host transfer boundary not reached: %v chunks=%d", err, wire.chunks)
				}
				if change == "valid" {
					if err != nil || wire.writes != 1 {
						t.Fatalf("valid host transfer failed: %v writes=%d", err, wire.writes)
					}
				} else if err == nil || wire.writes != 0 {
					t.Fatalf("stale host input dispatched: %v writes=%d", err, wire.writes)
				}
			})
		}
	}
}
