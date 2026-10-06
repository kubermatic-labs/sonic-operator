//go:build integration

// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"
)

func TestNetworkBufferSchema(t *testing.T) {
	env := &envtest.Environment{ErrorIfCRDPathMissing: true}
	for _, kind := range []string{"bufferpool", "bufferprofile", "bufferpg", "bufferqueue", "qosmap", "qosbinding"} {
		env.CRDDirectoryPaths = append(env.CRDDirectoryPaths, filepath.Join("..", "..", "config", "crd", "bases", "sonic.networking.metal.ironcore.dev_switch"+kind+"s.yaml"))
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
	c, err := client.New(cfg, client.Options{})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "config", "samples", "buffers.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	samples := 0
	for _, doc := range strings.Split(string(data), "\n---\n") {
		obj := &unstructured.Unstructured{}
		if err := yaml.Unmarshal([]byte(doc), &obj.Object); err != nil {
			t.Fatal(err)
		}
		if err := c.Create(t.Context(), obj, client.DryRunAll); err != nil {
			t.Fatalf("sample %s: %v", obj.GetName(), err)
		}
		samples++
	}
	if samples != 4 {
		t.Fatalf("expected 4 buffer samples, got %d", samples)
	}
	for _, tc := range []struct {
		kind, spec, immutable string
		invalid               map[string]any
	}{
		{"BufferPool", `{"name":"pool","type":"ingress","mode":"dynamic","size":100000}`, "name", map[string]any{"size": 0, "type": "both", "mode": "unknown", "name": "bad|name", "xoff": 100001}},
		{"BufferProfile", `{"name":"profile","pool":"pool","size":0,"dynamicThreshold":3}`, "name", map[string]any{"dynamicThreshold": 8, "staticThreshold": 100, "pool": "[BUFFER_POOL|pool]", "name": "bad|name"}},
		{"BufferPG", `{"interfaceName":"Ethernet11","range":"7","profile":"PORT3_INGRESS_PROFILE"}`, "range", map[string]any{"range": "7-7", "interfaceName": "Ethernet01", "profile": "bad|name"}},
		{"BufferQueue", `{"interfaceName":"Ethernet11","range":"0-7","profile":"out"}`, "range", map[string]any{"range": "0-256", "interfaceName": "eth0", "profile": "bad|name"}},
		{"QoSMap", `{"name":"AZURE","type":"TCToPriorityGroup","entries":[{"from":7,"to":7}]}`, "name", map[string]any{"entries": []any{map[string]any{"from": 7, "to": 8}}}},
		{"QoSBinding", `{"interfaceName":"Ethernet11","tcToPriorityGroup":"AZURE"}`, "interfaceName", map[string]any{"tcToPriorityGroup": "bad|name"}},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			var spec map[string]any
			if err := json.Unmarshal([]byte(tc.spec), &spec); err != nil {
				t.Fatal(err)
			}
			spec["switchRef"] = map[string]any{"name": "switch-1"}
			obj := &unstructured.Unstructured{Object: map[string]any{"apiVersion": api.GroupVersion.String(), "kind": "Switch" + tc.kind, "metadata": map[string]any{"name": "valid"}, "spec": spec}}
			if err := c.Create(t.Context(), obj); err != nil {
				t.Fatal(err)
			}
			policy, _, _ := unstructured.NestedString(obj.Object, "spec", "managementPolicy")
			if policy != "Observe" {
				t.Fatal("unsafe default", policy)
			}
			for field, value := range tc.invalid {
				candidate := obj.DeepCopy()
				candidate.SetName("invalid-" + strings.ToLower(field))
				candidate.SetResourceVersion("")
				candidate.SetUID("")
				raw, _ := json.Marshal(value)
				var normalized any
				_ = json.Unmarshal(raw, &normalized)
				if err := unstructured.SetNestedField(candidate.Object, normalized, "spec", field); err != nil {
					t.Fatal(err)
				}
				if err := c.Create(t.Context(), candidate); !apierrors.IsInvalid(err) {
					t.Fatalf("invalid %s=%v accepted: %v", field, value, err)
				}
			}
			change := "other"
			if tc.immutable == "range" {
				change = "6"
			}
			if tc.immutable == "interfaceName" {
				change = "Ethernet12"
			}
			if err := unstructured.SetNestedField(obj.Object, change, "spec", tc.immutable); err != nil {
				t.Fatal(err)
			}
			if err := c.Update(t.Context(), obj); !apierrors.IsInvalid(err) {
				t.Fatalf("mutable %s: %v", tc.immutable, err)
			}
			if tc.kind == "BufferPG" || tc.kind == "BufferQueue" {
				for i, value := range []string{"7-0", "00", "0-0", "256"} {
					bad := obj.DeepCopy()
					bad.SetName(fmt.Sprintf("range-%d", i))
					bad.SetResourceVersion("")
					bad.SetUID("")
					_ = unstructured.SetNestedField(bad.Object, value, "spec", "range")
					if err := c.Create(t.Context(), bad); !apierrors.IsInvalid(err) {
						t.Fatalf("range %s accepted: %v", value, err)
					}
				}
			}
		})
	}
}
