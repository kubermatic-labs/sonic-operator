//go:build integration

// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"path/filepath"
	"testing"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestNetworkPortLoopbackSchema(t *testing.T) {
	root := filepath.Join("..", "..", "config", "crd", "bases")
	env := &envtest.Environment{BinaryAssetsDirectory: getFirstFoundEnvTestBinaryDir(), CRDDirectoryPaths: []string{
		filepath.Join(root, "sonic.networking.metal.ironcore.dev_switchinterfaces.yaml"),
		filepath.Join(root, "sonic.networking.metal.ironcore.dev_switchl3interfaces.yaml"),
		filepath.Join(root, "sonic.networking.metal.ironcore.dev_switchbgps.yaml"),
	}, ErrorIfCRDPathMissing: true}
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
	for _, tc := range []struct {
		name, kind string
		spec       map[string]any
		valid      bool
	}{
		{"port-omitted", "SwitchInterface", map[string]any{"nativeName": "Ethernet0", "handle": "port-0"}, true},
		{"port-adoption", "SwitchInterface", map[string]any{"nativeName": "Ethernet0", "handle": "port-0", "speed": int64(1000), "mtu": int64(9100)}, true},
		{"port-fec", "SwitchInterface", map[string]any{"nativeName": "Ethernet0", "handle": "port-0", "fec": "rs"}, true},
		{"port-speed-invalid", "SwitchInterface", map[string]any{"nativeName": "Ethernet0", "handle": "port-0", "speed": int64(1001)}, false},
		{"port-fec-invalid", "SwitchInterface", map[string]any{"nativeName": "Ethernet0", "handle": "port-0", "fec": "auto"}, false},
		{"port-mtu-invalid", "SwitchInterface", map[string]any{"nativeName": "Ethernet0", "handle": "port-0", "mtu": int64(9217)}, false},
		{"loopback-zero", "SwitchL3Interface", map[string]any{"name": "Loopback0", "addresses": []any{"10.1.0.1/32"}}, true},
		{"loopback-last", "SwitchL3Interface", map[string]any{"name": "Loopback4095", "addresses": []any{"10.1.0.1/32"}}, true},
		{"loopback-invalid", "SwitchL3Interface", map[string]any{"name": "Loopback4096", "addresses": []any{"10.1.0.1/32"}}, false},
		{"loopback-noncanonical", "SwitchL3Interface", map[string]any{"name": "Loopback00", "addresses": []any{"10.1.0.1/32"}}, false},
		{"bgp-traditional", "SwitchBGP", map[string]any{"mode": "Traditional", "localASN": int64(65100), "routerID": "10.1.0.1", "prefixes": []any{"10.1.0.1/32"}}, true},
		{"bgp-traditional-empty", "SwitchBGP", map[string]any{"mode": "Traditional", "localASN": int64(65100), "routerID": "10.1.0.1"}, false},
		{"bgp-traditional-wrong-network", "SwitchBGP", map[string]any{"mode": "Traditional", "localASN": int64(65100), "routerID": "10.1.0.1", "prefixes": []any{"10.1.0.0/24"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.spec["switchRef"] = map[string]any{"name": "leaf"}
			obj := &unstructured.Unstructured{Object: map[string]any{"apiVersion": api.GroupVersion.String(), "kind": tc.kind, "metadata": map[string]any{"name": tc.name}, "spec": tc.spec}}
			err := c.Create(t.Context(), obj)
			if tc.valid && err != nil || !tc.valid && !apierrors.IsInvalid(err) {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
			if tc.valid {
				if tc.name == "bgp-traditional" {
					changed := obj.DeepCopy()
					_ = unstructured.SetNestedField(changed.Object, "Unified", "spec", "mode")
					if err := c.Update(t.Context(), changed); !apierrors.IsInvalid(err) {
						t.Fatalf("backend mutation accepted: %v", err)
					}
				}
				policy, _, _ := unstructured.NestedString(obj.Object, "spec", "managementPolicy")
				if policy != "Observe" {
					t.Fatalf("unsafe default: %s", policy)
				}
				if tc.name == "port-omitted" {
					for _, field := range []string{"speed", "mtu", "fec"} {
						if _, ok, _ := unstructured.NestedFieldNoCopy(obj.Object, "spec", field); ok {
							t.Fatalf("invented %s", field)
						}
					}
				}
			}
		})
	}
}
