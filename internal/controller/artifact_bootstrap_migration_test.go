// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"context"
	"fmt"
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

// predecessorSwitch records the bootstrap requests and reports the owner
// conflict until it receives the approved predecessor.
type predecessorSwitch struct{ migrations *[]string }

func (f *predecessorSwitch) Artifact(_ context.Context, r artifact.Request) (*artifact.Result, error) {
	if r.Operation == "observe" {
		return &artifact.Result{Phase: "Unowned"}, nil
	}
	return &artifact.Result{Phase: "Staged"}, nil
}
func (f *predecessorSwitch) ArtifactFresh(ctx context.Context, r artifact.Request, fresh func(context.Context) error) (*artifact.Result, error) {
	if err := fresh(ctx); err != nil {
		return nil, err
	}
	if r.Operation != "bootstrap" {
		return f.Artifact(ctx, r)
	}
	*f.migrations = append(*f.migrations, r.Bundle.Bootstrap.MigrationFrom)
	if r.Bundle.Bootstrap.MigrationFrom == "" {
		return nil, fmt.Errorf("artifact bootstrap RPC failed: FailedPrecondition: declared bootstrap ownership or activation failed: immutable bootstrap owner or identity conflict")
	}
	return &artifact.Result{Configuration: true, Runtime: true, Persistence: true}, nil
}
func (f *predecessorSwitch) Close() error { return nil }

func TestArtifactBootstrapRetriesWithApprovedPredecessorOnlyOnConflict(t *testing.T) {
	for _, tc := range []struct {
		name, from string
		want       []string
	}{
		{"approved predecessor", artifact.Digest([]byte("old policy")), []string{"", artifact.Digest([]byte("old policy"))}},
		{"no approval", "", []string{""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)
			_ = api.AddToScheme(scheme)
			yes := true
			data := []byte(`{"ports":[]}`)
			obj := &api.SwitchArtifact{ObjectMeta: metav1.ObjectMeta{Name: "site", Namespace: "fleet", UID: "owner", Generation: 1}, Spec: api.SwitchArtifactSpec{SwitchName: "switch", ManagementPolicy: "Manage", Baseline: "base", BootstrapMigrationFrom: tc.from, Files: []api.ArtifactFile{{Slot: "PlatformJSON", SHA256: artifact.Digest(data), Chunks: []api.ArtifactContentRef{{Kind: "ConfigMap", Name: "source", UID: "source-uid", Key: "file"}}}}}}
			ref := obj.Spec.Files[0].Chunks[0]
			obj.Spec.Bootstrap = &api.ArtifactBootstrapSpec{SupervisorSHA256: artifact.Digest(data), SupervisorChunks: []api.ArtifactContentRef{ref}, PolicyRef: ref, UnitSHA256: artifact.Digest([]byte(artifact.SupervisorUnit))}
			obj.Spec.Bootstrap.PolicyRef.Key = "policy"
			sw := &api.Switch{ObjectMeta: metav1.ObjectMeta{Name: "switch", UID: "switch-uid"}}
			sw.Spec.Management.Host = "10.1.2.3"
			sw.Spec.Management.Port = "50051"
			source := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "source", Namespace: "fleet", UID: "source-uid"}, Immutable: &yes, BinaryData: map[string][]byte{"file": data, "policy": []byte("{}")}}
			obj.Spec.Bootstrap.PolicySHA256 = artifact.Digest(source.BinaryData["policy"])
			c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(obj).WithObjects(obj, sw, source).Build()
			var migrations []string
			r := &ArtifactReconciler{Client: c, APIReader: c, AllowArtifacts: true, NewClient: func(context.Context, client.Reader, *api.Switch) (artifactRPC, io.Closer, error) {
				f := &predecessorSwitch{migrations: &migrations}
				return f, f, nil
			}}
			req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}
			for range 2 { // first reconcile binds the target
				_, _ = r.Reconcile(context.Background(), req)
			}
			if fmt.Sprint(migrations) != fmt.Sprint(tc.want) {
				t.Fatalf("bootstrap requests carried migrationFrom %q, want %q", migrations, tc.want)
			}
		})
	}
}
