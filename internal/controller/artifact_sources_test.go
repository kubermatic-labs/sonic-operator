// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"context"
	"strings"
	"testing"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	"github.com/ironcore-dev/sonic-operator/internal/artifact"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestArtifactSourcesRequireImmutableUIDAndDigest(t *testing.T) {
	yes := true
	data := []byte(`{"ports":[]}`)
	source := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "revision", Namespace: "fleet", UID: "content-uid"}, Immutable: &yes, BinaryData: map[string][]byte{"file": data}}
	scheme := runtime.NewScheme()
	corev1.AddToScheme(scheme)
	obj := &api.SwitchArtifact{ObjectMeta: metav1.ObjectMeta{Name: "site", Namespace: "fleet", UID: "owner", Generation: 1}, Spec: api.SwitchArtifactSpec{Baseline: "baseline", Files: []api.ArtifactFile{{Slot: "PlatformJSON", SHA256: artifact.Digest(data), Chunks: []api.ArtifactContentRef{{Kind: "ConfigMap", Name: "revision", UID: "content-uid", Key: "file"}}}}}}
	tests := []struct {
		name      string
		change    func(*corev1.ConfigMap, *api.SwitchArtifact)
		wantError bool
	}{
		{"valid", func(*corev1.ConfigMap, *api.SwitchArtifact) {}, false},
		{"mutable", func(c *corev1.ConfigMap, _ *api.SwitchArtifact) { c.Immutable = nil }, true},
		{"recreated", func(c *corev1.ConfigMap, _ *api.SwitchArtifact) { c.UID = types.UID("replacement") }, true},
		{"digest", func(c *corev1.ConfigMap, _ *api.SwitchArtifact) { c.BinaryData["file"] = []byte("replacement") }, true},
		{"missing-key", func(c *corev1.ConfigMap, _ *api.SwitchArtifact) { delete(c.BinaryData, "file") }, true},
		{"ambiguous-key", func(c *corev1.ConfigMap, _ *api.SwitchArtifact) { c.Data = map[string]string{"file": "replacement"} }, true},
		{"ordered-chunks", func(c *corev1.ConfigMap, o *api.SwitchArtifact) {
			c.BinaryData = map[string][]byte{"first": data[:5], "last": data[5:]}
			first := o.Spec.Files[0].Chunks[0]
			first.Key = "first"
			last := first
			last.Key = "last"
			o.Spec.Files[0].Chunks = []api.ArtifactContentRef{first, last}
		}, false},
		{"reordered-chunks", func(c *corev1.ConfigMap, o *api.SwitchArtifact) {
			c.BinaryData = map[string][]byte{"first": data[:5], "last": data[5:]}
			first := o.Spec.Files[0].Chunks[0]
			first.Key = "first"
			last := first
			last.Key = "last"
			o.Spec.Files[0].Chunks = []api.ArtifactContentRef{last, first}
		}, true},
		{"secret-public", func(_ *corev1.ConfigMap, o *api.SwitchArtifact) { o.Spec.Files[0].Slot = "AgentKey" }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := source.DeepCopy()
			o := obj.DeepCopy()
			tt.change(c, o)
			reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(c).Build()
			_, err := resolveArtifactSources(context.Background(), reader, o, "target")
			if (err != nil) != tt.wantError {
				t.Fatalf("error %v", err)
			}
			if err != nil && strings.Contains(err.Error(), "replacement") {
				t.Fatal("content leaked")
			}
		})
	}
}

func TestBootstrapSourcesShareAggregateBudget(t *testing.T) {
	yes := true
	data := []byte(strings.Repeat("x", 1<<20))
	source := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "chunk", Namespace: "fleet", UID: "published-uid"}, Immutable: &yes, BinaryData: map[string][]byte{"data": data, "policy": []byte("{}")}}
	ref := api.ArtifactContentRef{Kind: "ConfigMap", Name: source.Name, UID: string(source.UID), Key: "data"}
	refs := make([]api.ArtifactContentRef, 70)
	for i := range refs {
		refs[i] = ref
	}
	policy := ref
	policy.Key = "policy"
	hash := artifact.Digest([]byte(strings.Repeat(string(data), 70)))
	obj := &api.SwitchArtifact{ObjectMeta: metav1.ObjectMeta{Namespace: "fleet", UID: "owner", Generation: 1}, Spec: api.SwitchArtifactSpec{Baseline: "base", Files: []api.ArtifactFile{{Slot: "AgentBinary", SHA256: hash, Chunks: refs}}, Bootstrap: &api.ArtifactBootstrapSpec{SupervisorSHA256: hash, SupervisorChunks: refs, PolicyRef: policy, PolicySHA256: artifact.Digest([]byte("{}")), UnitSHA256: artifact.Digest([]byte(artifact.SupervisorUnit))}}}
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(source).Build()
	if _, err := resolveArtifactSources(t.Context(), reader, obj, "target"); err == nil {
		t.Fatal("ordinary and bootstrap inputs exceeded aggregate budget")
	}
}
