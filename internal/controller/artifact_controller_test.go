// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"context"
	"io"
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

type artifactFake struct {
	calls   *[]string
	observe artifact.Result
}

func (f *artifactFake) Artifact(_ context.Context, r artifact.Request) (*artifact.Result, error) {
	*f.calls = append(*f.calls, r.Operation)
	if r.Operation == "observe" {
		return &f.observe, nil
	}
	return &artifact.Result{Phase: "Confirmed", Configuration: true, Runtime: true, Persistence: true}, nil
}
func (f *artifactFake) Close() error { return nil }
func TestArtifactReconcilerEnforcesAndFreshlyConfirms(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = api.AddToScheme(scheme)
	yes := true
	data := []byte(`{"ports":[]}`)
	obj := &api.SwitchArtifact{ObjectMeta: metav1.ObjectMeta{Name: "site", Namespace: "fleet", UID: "owner", Generation: 1}, Spec: api.SwitchArtifactSpec{SwitchName: "switch", ManagementPolicy: "Manage", Baseline: "base", Files: []api.ArtifactFile{{Slot: "PlatformJSON", SHA256: artifact.Digest(data), Chunks: []api.ArtifactContentRef{{Kind: "ConfigMap", Name: "source", UID: "source-uid", Key: "file"}}}}}}
	ref := obj.Spec.Files[0].Chunks[0]
	obj.Spec.Bootstrap = &api.ArtifactBootstrapSpec{SupervisorSHA256: artifact.Digest(data), SupervisorChunks: []api.ArtifactContentRef{ref}, PolicySHA256: artifact.Digest(data), PolicyRef: ref, UnitSHA256: artifact.Digest([]byte(artifact.SupervisorUnit))}
	sw := &api.Switch{ObjectMeta: metav1.ObjectMeta{Name: "switch", UID: "switch-uid"}}
	sw.Spec.Management.Host = "10.1.2.3"
	sw.Spec.Management.Port = "50051"
	source := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "source", Namespace: "fleet", UID: "source-uid"}, Immutable: &yes, BinaryData: map[string][]byte{"file": data, "policy": []byte("{}")}}
	obj.Spec.Bootstrap.PolicyRef.Key = "policy"
	obj.Spec.Bootstrap.PolicySHA256 = artifact.Digest(source.BinaryData["policy"])
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(obj).WithObjects(obj, sw, source).Build()
	calls := []string{}
	connections := 0
	r := &ArtifactReconciler{Client: c, APIReader: c, AllowArtifacts: true, NewClient: func(context.Context, client.Reader, *api.Switch) (artifactRPC, io.Closer, error) {
		connections++
		f := &artifactBoundaryFake{artifactFake: artifactFake{calls: &calls, observe: artifact.Result{Phase: "Unowned"}}}
		return f, f, nil
	}}
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}
	for range 2 {
		if _, err := r.Reconcile(context.Background(), req); err != nil {
			t.Fatal(err)
		}
	}
	if len(calls) < 2 || calls[len(calls)-1] != "stage" {
		t.Fatalf("did not enforce: %v", calls)
	}
	current := &api.SwitchArtifact{}
	_ = c.Get(context.Background(), req.NamespacedName, current)
	b, err := resolveArtifactSources(context.Background(), c, current, current.Status.Target)
	if err != nil {
		t.Fatal(err)
	}
	connections = 0
	calls = nil
	r.NewClient = func(context.Context, client.Reader, *api.Switch) (artifactRPC, io.Closer, error) {
		connections++
		f := &artifactBoundaryFake{artifactFake: artifactFake{calls: &calls, observe: artifact.Result{Phase: "AwaitingConfirmation", Token: "token", Identity: b.Identity(), Configuration: true, Runtime: true}}}
		return f, f, nil
	}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if connections != 2 || len(calls) != 4 || calls[0] != "bootstrap" || calls[1] != "observe" || calls[2] != "observe" || calls[3] != "confirm" {
		t.Fatalf("no independent reconnect: %d %v", connections, calls)
	}
	// A desired update during observation must not stage the old generation.
	calls = nil
	r.NewClient = func(context.Context, client.Reader, *api.Switch) (artifactRPC, io.Closer, error) {
		latest := &api.SwitchArtifact{}
		if err := c.Get(context.Background(), req.NamespacedName, latest); err != nil {
			t.Fatal(err)
		}
		latest.Generation++
		if err := c.Update(context.Background(), latest); err != nil {
			t.Fatal(err)
		}
		f := &artifactBoundaryFake{artifactFake: artifactFake{calls: &calls, observe: artifact.Result{Phase: "Unowned"}}}
		return f, f, nil
	}
	if _, err := r.Reconcile(context.Background(), req); err == nil || len(calls) != 0 {
		t.Fatalf("stale generation staged: %v %v", calls, err)
	}
	// An endpoint change may never move the recorded lifecycle to another target.
	_ = c.Get(context.Background(), client.ObjectKeyFromObject(sw), sw)
	sw.Spec.Management.Host = "10.1.2.4"
	_ = c.Update(context.Background(), sw)
	calls = nil
	if _, err := r.Reconcile(context.Background(), req); err == nil || len(calls) > 0 {
		t.Fatalf("target change not blocked: %v %v", calls, err)
	}
}

func TestArtifactReconcilerConvergesPolicyOnlyGenerationWithoutStaging(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = api.AddToScheme(scheme)
	yes := true
	data := []byte(`{"ports":[]}`)
	obj := &api.SwitchArtifact{ObjectMeta: metav1.ObjectMeta{Name: "site", Namespace: "fleet", UID: "owner", Generation: 1}, Spec: api.SwitchArtifactSpec{SwitchName: "switch", ManagementPolicy: "Manage", Baseline: "base", Files: []api.ArtifactFile{{Slot: "PlatformJSON", SHA256: artifact.Digest(data), Chunks: []api.ArtifactContentRef{{Kind: "ConfigMap", Name: "source", UID: "source-uid", Key: "file"}}}}}}
	ref := obj.Spec.Files[0].Chunks[0]
	obj.Spec.Bootstrap = &api.ArtifactBootstrapSpec{SupervisorSHA256: artifact.Digest(data), SupervisorChunks: []api.ArtifactContentRef{ref}, PolicySHA256: artifact.Digest(data), PolicyRef: ref, UnitSHA256: artifact.Digest([]byte(artifact.SupervisorUnit))}
	sw := &api.Switch{ObjectMeta: metav1.ObjectMeta{Name: "switch", UID: "switch-uid"}}
	sw.Spec.Management.Host = "10.1.2.3"
	sw.Spec.Management.Port = "50051"
	source := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "source", Namespace: "fleet", UID: "source-uid"}, Immutable: &yes, BinaryData: map[string][]byte{"file": data, "policy": []byte("{}")}}
	obj.Spec.Bootstrap.PolicyRef.Key = "policy"
	obj.Spec.Bootstrap.PolicySHA256 = artifact.Digest(source.BinaryData["policy"])
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(obj).WithObjects(obj, sw, source).Build()
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}
	ctx := context.Background()
	calls := []string{}
	observed := artifact.Result{Phase: "Unowned"}
	r := &ArtifactReconciler{Client: c, APIReader: c, AllowArtifacts: true, NewClient: func(context.Context, client.Reader, *api.Switch) (artifactRPC, io.Closer, error) {
		f := &artifactBoundaryFake{artifactFake: artifactFake{calls: &calls, observe: observed}}
		return f, f, nil
	}}
	if _, err := r.Reconcile(ctx, req); err != nil { // binds the target
		t.Fatal(err)
	}
	current := &api.SwitchArtifact{}
	_ = c.Get(ctx, req.NamespacedName, current)
	confirmed, err := resolveArtifactSources(ctx, c, current, current.Status.Target)
	if err != nil {
		t.Fatal(err)
	}
	observed = artifact.Result{Phase: "Confirmed", Identity: confirmed.Identity(), Configuration: true, Runtime: true, Persistence: true}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	_ = c.Get(ctx, req.NamespacedName, current)
	if current.Status.ConfirmedGeneration != 1 {
		t.Fatalf("confirmed generation not recorded: %d", current.Status.ConfirmedGeneration)
	}

	// Observe -> Manage round trip: only the generation changes.
	current.Generation = 3
	if err := c.Update(ctx, current); err != nil {
		t.Fatal(err)
	}
	calls = nil
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	for _, call := range calls {
		if call == "stage" {
			t.Fatalf("policy-only generation staged again: %v", calls)
		}
	}
	_ = c.Get(ctx, req.NamespacedName, current)
	ready := false
	for _, cond := range current.Status.Conditions {
		if cond.Type == "Ready" && cond.Status == metav1.ConditionTrue {
			ready = true
		}
	}
	if !ready || current.Status.ConfirmedGeneration != 1 || current.Status.Identity != confirmed.Identity() {
		t.Fatalf("policy-only generation not converged: %+v", current.Status)
	}

	// A content change still stages.
	current.Spec.Baseline = "other"
	current.Generation = 4
	if err := c.Update(ctx, current); err != nil {
		t.Fatal(err)
	}
	calls = nil
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if len(calls) == 0 || calls[len(calls)-1] != "stage" {
		t.Fatalf("content change did not stage: %v", calls)
	}
}
