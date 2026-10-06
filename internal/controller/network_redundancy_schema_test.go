//go:build integration

// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"
)

func TestRedundancySchema(t *testing.T) {
	crdDir := t.TempDir()
	gen := exec.Command(filepath.Join("..", "..", "bin", "controller-gen"), "crd", "paths=../../api/v1alpha1", "output:crd:artifacts:config="+crdDir)
	if output, err := gen.CombinedOutput(); err != nil {
		t.Fatalf("test-local schema generation: %v\n%s", err, output)
	}
	env := &envtest.Environment{BinaryAssetsDirectory: getFirstFoundEnvTestBinaryDir(), ErrorIfCRDPathMissing: true}
	for _, tc := range redundancyTestSpecs {
		env.CRDDirectoryPaths = append(env.CRDDirectoryPaths, filepath.Join(crdDir, "sonic.networking.metal.ironcore.dev_switch"+strings.ToLower(tc.kind)+"s.yaml"))
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Error(err)
		}
	})
	scheme := runtime.NewScheme()
	if err := api.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range redundancyTestSpecs {
		t.Run(tc.kind, func(t *testing.T) {
			obj := &unstructured.Unstructured{}
			raw := fmt.Sprintf(`{"apiVersion":%q,"kind":%q,"metadata":{"name":"defaults"},"spec":%s}`, api.GroupVersion.String(), "Switch"+tc.kind, tc.spec)
			if err := obj.UnmarshalJSON([]byte(raw)); err != nil {
				t.Fatal(err)
			}
			_ = unstructured.SetNestedField(obj.Object, "leaf", "spec", "switchRef", "name")
			if err := c.Create(t.Context(), obj); err != nil {
				t.Fatal(err)
			}
			spec, _, _ := unstructured.NestedMap(obj.Object, "spec")
			if spec["managementPolicy"] != "Observe" {
				t.Fatal("unsafe management default")
			}
			if tc.kind == "MLAG" && (spec["keepaliveInterval"] != int64(1) || spec["sessionTimeout"] != int64(30)) {
				t.Fatal("wrong MLAG defaults")
			}
			if tc.kind == "EVPNPeer" && (spec["vrf"] != "default" || spec["adminState"] != "Down") {
				t.Fatal("unsafe EVPN defaults")
			}
			for i, bad := range redundancyInvalidFields[tc.kind] {
				candidate := obj.DeepCopy()
				candidate.SetName(fmt.Sprintf("bad-%d", i))
				candidate.SetUID("")
				candidate.SetResourceVersion("")
				var fields map[string]any
				if err := json.Unmarshal([]byte(bad), &fields); err != nil {
					t.Fatal(err)
				}
				for k, v := range fields {
					_ = unstructured.SetNestedField(candidate.Object, v, "spec", k)
				}
				if err := c.Create(t.Context(), candidate); !apierrors.IsInvalid(err) {
					t.Fatalf("invalid %s accepted: %v", bad, err)
				}
			}
			selectors := map[string]map[string]any{
				"EVPN":        {"tunnel": "other"},
				"MLAG":        {"domainID": int64(2), "peerSwitchRef": map[string]any{"name": "other"}},
				"VXLANTunnel": {"name": "other"}, "VLANVNI": {"tunnel": "other", "vlanID": int64(11)},
				"EVPNPeer": {"address": "2001:db8::3", "vrf": "VrfOther"},
			}
			selectors[tc.kind]["switchRef"] = map[string]any{"name": "other"}
			for k, v := range selectors[tc.kind] {
				candidate := obj.DeepCopy()
				_ = unstructured.SetNestedField(candidate.Object, v, "spec", k)
				if err := c.Update(t.Context(), candidate); !apierrors.IsInvalid(err) {
					t.Fatalf("mutable target %s: %v", k, err)
				}
			}
			obj.Object["status"] = map[string]any{"observed": map[string]any{"preflightEligible": true, "nested": map[string]any{"proof": "retained"}}}
			if err := c.Status().Update(t.Context(), obj); err != nil {
				t.Fatal(err)
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(obj), obj); err != nil {
				t.Fatal(err)
			}
			if _, ok, _ := unstructured.NestedFieldNoCopy(obj.Object, "status", "observed", "nested"); !ok {
				t.Fatal("observation pruned")
			}
		})
	}
	t.Run("samples", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join("..", "..", "config", "samples", "redundancy.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		for _, sample := range strings.Split(string(data), "\n---\n") {
			raw, err := yaml.YAMLToJSON([]byte(sample))
			if err != nil {
				t.Fatal(err)
			}
			obj := &unstructured.Unstructured{}
			if err := obj.UnmarshalJSON(raw); err != nil {
				t.Fatal(err)
			}
			if err := c.Create(t.Context(), obj); err != nil {
				t.Fatal(err)
			}
			policy, _, _ := unstructured.NestedString(obj.Object, "spec", "managementPolicy")
			if policy != "Observe" {
				t.Fatal("sample permits writes")
			}
		}
	})
}
