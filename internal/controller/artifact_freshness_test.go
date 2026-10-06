// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	"github.com/ironcore-dev/sonic-operator/internal/artifact"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type artifactBoundaryFake struct {
	artifactFake
	before func(string)
}

func (f *artifactBoundaryFake) Artifact(ctx context.Context, q artifact.Request) (*artifact.Result, error) {
	if f.before != nil {
		f.before(q.Operation)
	}
	return f.artifactFake.Artifact(ctx, q)
}
func (f *artifactBoundaryFake) ArtifactFresh(ctx context.Context, q artifact.Request, fresh func(context.Context) error) (*artifact.Result, error) {
	if f.before != nil {
		f.before(q.Operation)
	}
	if fresh == nil {
		panic("Manage omitted freshness callback")
	}
	if err := fresh(ctx); err != nil {
		return nil, err
	}
	return f.artifactFake.Artifact(ctx, q)
}

func artifactFreshnessFixture(t *testing.T) (client.Client, *api.SwitchArtifact, *api.Switch, *corev1.ConfigMap, *corev1.Secret) {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = api.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	yes := true
	data := []byte(`{"ports":[]}`)
	source := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "source", Namespace: "fleet", UID: "source-uid"}, Immutable: &yes, BinaryData: map[string][]byte{"file": data}}
	credentials := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "credentials", Namespace: "fleet", UID: "credentials-uid"}, Data: map[string][]byte{"password": []byte("private-credential-fixture")}}
	keySource := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "key-source", Namespace: "fleet", UID: "key-uid"}, Immutable: &yes, Data: map[string][]byte{"key": []byte("private-artifact-key-fixture")}}
	sw := &api.Switch{ObjectMeta: metav1.ObjectMeta{Name: "switch", UID: "switch-uid"}, Spec: api.SwitchSpec{MacAddress: "00:11:22:33:44:55", Management: api.Management{Host: "10.0.0.11", Port: "50051", Credentials: corev1.ObjectReference{Namespace: "fleet", Name: "credentials"}}}}
	ref := api.ArtifactContentRef{Kind: "ConfigMap", Name: source.Name, UID: string(source.UID), Key: "file"}
	obj := &api.SwitchArtifact{ObjectMeta: metav1.ObjectMeta{Name: "site", Namespace: "fleet", UID: "owner", Generation: 1}, Spec: api.SwitchArtifactSpec{SwitchName: sw.Name, ManagementPolicy: "Manage", Baseline: "base", Files: []api.ArtifactFile{{Slot: "PlatformJSON", SHA256: artifact.Digest(data), Chunks: []api.ArtifactContentRef{ref}}}, Bootstrap: &api.ArtifactBootstrapSpec{SupervisorSHA256: artifact.Digest(data), SupervisorChunks: []api.ArtifactContentRef{ref}, PolicySHA256: artifact.Digest(data), PolicyRef: ref, UnitSHA256: artifact.Digest([]byte(artifact.SupervisorUnit))}}}
	obj.Spec.Files = append(obj.Spec.Files, api.ArtifactFile{Slot: "AgentKey", SHA256: artifact.Digest(keySource.Data["key"]), Chunks: []api.ArtifactContentRef{{Kind: "Secret", Name: keySource.Name, UID: string(keySource.UID), Key: "key"}}})
	kube := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(obj).WithObjects(obj, sw, source, credentials, keySource).Build()
	// The first reconciliation persists the existing target identity before I/O.
	r := &ArtifactReconciler{Client: kube, APIReader: kube, AllowArtifacts: true}
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}); err != nil {
		t.Fatal(err)
	}
	if err := kube.Get(t.Context(), client.ObjectKeyFromObject(obj), obj); err != nil {
		t.Fatal(err)
	}
	return kube, obj, sw, source, credentials
}

func TestArtifactControllerRejectsStaleDispatch(t *testing.T) {
	changes := []string{"object-delete", "object-recreate", "generation", "spec-without-generation", "source-ref", "source-delete", "source-recreate", "source-mutable", "source-hash", "source-key", "switch-delete", "switch-recreate", "endpoint", "port", "base-mac", "credential-ref", "switch-spec", "secret-rotate", "secret-delete", "secret-recreate", "artifact-secret-rotate", "artifact-secret-delete", "artifact-secret-recreate", "competing-owner"}
	for _, boundary := range []string{"bootstrap", "stage", "confirm", "stage-after-observe", "confirm-after-observe", "confirm-after-fresh-observe"} {
		for _, change := range changes {
			t.Run(boundary+"/"+change, func(t *testing.T) {
				kube, obj, sw, source, secret := artifactFreshnessFixture(t)
				calls := []string{}
				changed, writesAtChange := false, 0
				writes := func() int {
					n := 0
					for _, op := range calls {
						if op != "observe" {
							n++
						}
					}
					return n
				}
				update := func(o client.Object) {
					t.Helper()
					if err := kube.Update(t.Context(), o); err != nil {
						t.Fatal(err)
					}
				}
				remove := func(o client.Object) {
					t.Helper()
					if err := kube.Delete(t.Context(), o); err != nil {
						t.Fatal(err)
					}
				}
				create := func(o client.Object) {
					t.Helper()
					o.SetResourceVersion("")
					if err := kube.Create(t.Context(), o); err != nil {
						t.Fatal(err)
					}
				}
				observations := 0
				mutate := func(op string) {
					if op == "observe" {
						observations++
					}
					trigger := strings.Split(boundary, "-")[0]
					if strings.Contains(boundary, "after-") {
						trigger = "observe"
					}
					if boundary == "confirm-after-fresh-observe" && observations < 2 {
						return
					}
					if changed || op != trigger {
						return
					}
					changed, writesAtChange = true, writes()
					switch change {
					case "object-delete":
						remove(obj)
					case "object-recreate":
						remove(obj)
						obj.UID = "new-owner"
						create(obj)
					case "generation":
						obj.Generation++
						update(obj)
					case "spec-without-generation":
						obj.Spec.ManagementPolicy = "Observe"
						update(obj)
					case "source-ref":
						remove(source)
						source.UID = "replacement"
						create(source)
						obj.Spec.Files[0].Chunks[0].UID = "replacement"
						obj.Spec.Bootstrap.SupervisorChunks[0].UID = "replacement"
						obj.Spec.Bootstrap.PolicyRef.UID = "replacement"
						update(obj)
					case "source-delete":
						remove(source)
					case "source-recreate":
						remove(source)
						source.UID = "replacement"
						create(source)
					case "source-mutable":
						source.Immutable = nil
						update(source)
					case "source-hash":
						source.BinaryData["file"] = []byte("private-config-fixture")
						update(source)
					case "source-key":
						delete(source.BinaryData, "file")
						update(source)
					case "switch-delete":
						remove(sw)
					case "switch-recreate":
						remove(sw)
						sw.UID = "replacement"
						create(sw)
					case "endpoint":
						sw.Spec.Management.Host = "10.0.0.99"
						update(sw)
					case "port":
						sw.Spec.Management.Port = "50052"
						update(sw)
					case "base-mac":
						sw.Spec.MacAddress = "00:11:22:33:44:66"
						update(sw)
					case "credential-ref":
						sw.Spec.Management.Credentials.Name = "new-credentials"
						update(sw)
					case "switch-spec":
						sw.Spec.Ports = []api.PortSpec{{Name: "Ethernet8"}}
						update(sw)
					case "secret-rotate":
						if err := kube.Get(t.Context(), client.ObjectKeyFromObject(secret), secret); err != nil {
							t.Fatal(err)
						}
						secret.Data["password"] = []byte("private-rotated-fixture")
						update(secret)
					case "secret-delete":
						remove(secret)
					case "secret-recreate":
						remove(secret)
						secret.UID = "replacement"
						create(secret)
					case "artifact-secret-rotate", "artifact-secret-delete", "artifact-secret-recreate":
						keySource := &corev1.Secret{}
						if err := kube.Get(t.Context(), client.ObjectKey{Namespace: "fleet", Name: "key-source"}, keySource); err != nil {
							t.Fatal(err)
						}
						if change == "artifact-secret-rotate" {
							keySource.Data["key"] = []byte("private-rotated-artifact-key-fixture")
							update(keySource)
						} else {
							remove(keySource)
							if change == "artifact-secret-recreate" {
								keySource.UID = "replacement"
								create(keySource)
							}
						}
					case "competing-owner":
						other := obj.DeepCopy()
						other.Name = "competitor"
						other.Namespace = "other"
						other.UID = "competitor"
						create(other)
					}
				}
				bundle, err := resolveArtifactSources(t.Context(), kube, obj, obj.Status.Target)
				if err != nil {
					t.Fatal(err)
				}
				observed := artifact.Result{Phase: "Unowned"}
				if strings.HasPrefix(boundary, "confirm") {
					observed = artifact.Result{Phase: "AwaitingConfirmation", Identity: bundle.Identity(), Token: "token", Configuration: true, Runtime: true}
				}
				r := &ArtifactReconciler{Client: kube, APIReader: kube, AllowArtifacts: true, NewClient: func(ctx context.Context, reader client.Reader, _ *api.Switch) (artifactRPC, io.Closer, error) {
					credentials := &corev1.Secret{}
					// Exercise the same reader handed to production connection construction.
					if err := reader.Get(ctx, client.ObjectKeyFromObject(secret), credentials); err != nil {
						return nil, nil, err
					}
					f := &artifactBoundaryFake{artifactFake: artifactFake{calls: &calls, observe: observed}, before: mutate}
					return f, f, nil
				}}
				_, err = r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)})
				if !changed || err == nil || writes() != writesAtChange {
					t.Fatalf("stale input dispatched: changed=%v err=%v calls=%v priorWrites=%d", changed, err, calls, writesAtChange)
				}
				current := &api.SwitchArtifact{}
				_ = kube.Get(t.Context(), client.ObjectKeyFromObject(obj), current)
				public, _ := json.Marshal(current.Status)
				if strings.Contains(string(public)+err.Error(), "private-") {
					t.Fatal("private input leaked")
				}
			})
		}
	}
}

func TestArtifactControllerRequiresFreshCapabilityOnlyForManage(t *testing.T) {
	for _, policy := range []string{"Manage", "Observe"} {
		t.Run(policy, func(t *testing.T) {
			kube, obj, _, _, _ := artifactFreshnessFixture(t)
			obj.Spec.ManagementPolicy = policy
			if err := kube.Update(t.Context(), obj); err != nil {
				t.Fatal(err)
			}
			calls := []string{}
			r := &ArtifactReconciler{Client: kube, APIReader: kube, AllowArtifacts: true, NewClient: func(context.Context, client.Reader, *api.Switch) (artifactRPC, io.Closer, error) {
				f := &artifactFake{calls: &calls}
				return f, f, nil
			}}
			_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)})
			if policy == "Manage" {
				if err == nil || len(calls) != 0 {
					t.Fatalf("unsupported Manage dispatched: %v %v", err, calls)
				}
			} else if err != nil || len(calls) != 1 || calls[0] != "observe" {
				t.Fatalf("Observe incompatible: %v %v", err, calls)
			}
		})
	}
}

func TestArtifactControllerRequiresFreshCapabilityOnReconnect(t *testing.T) {
	kube, obj, _, _, _ := artifactFreshnessFixture(t)
	bundle, err := resolveArtifactSources(t.Context(), kube, obj, obj.Status.Target)
	if err != nil {
		t.Fatal(err)
	}
	calls := []string{}
	connections := 0
	r := &ArtifactReconciler{Client: kube, APIReader: kube, AllowArtifacts: true, NewClient: func(context.Context, client.Reader, *api.Switch) (artifactRPC, io.Closer, error) {
		connections++
		f := artifactFake{calls: &calls, observe: artifact.Result{Phase: "AwaitingConfirmation", Identity: bundle.Identity(), Token: "token", Configuration: true, Runtime: true}}
		if connections == 1 {
			fresh := &artifactBoundaryFake{artifactFake: f}
			return fresh, fresh, nil
		}
		return &f, &f, nil
	}}
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}); err == nil {
		t.Fatal("fresh transport accepted old interface")
	}
	for _, op := range calls {
		if op == "confirm" {
			t.Fatal("unsupported confirmation dispatched")
		}
	}
}
