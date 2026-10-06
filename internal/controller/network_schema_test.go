//go:build integration

// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

func TestNetworkSchema(t *testing.T) {
	env := &envtest.Environment{BinaryAssetsDirectory: getFirstFoundEnvTestBinaryDir(), ErrorIfCRDPathMissing: true}
	// Generate into test-local storage: concurrent workers own the shared outputs.
	crdDir := t.TempDir()
	gen := exec.Command(filepath.Join("..", "..", "bin", "controller-gen"), "crd", "paths=../../api/v1alpha1", "output:crd:artifacts:config="+crdDir)
	if output, err := gen.CombinedOutput(); err != nil {
		t.Fatalf("generate test-local schemas: %v\n%s", err, output)
	}
	for _, resource := range networkTestSpecs {
		plural := strings.ToLower(resource.kind) + "s"
		if resource.kind == "ACLPolicy" {
			plural = "aclpolicies"
		}
		env.CRDDirectoryPaths = append(env.CRDDirectoryPaths, filepath.Join(crdDir, "sonic.networking.metal.ironcore.dev_switch"+plural+".yaml"))
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
	for _, resource := range networkTestSpecs {
		t.Run(resource.kind, func(t *testing.T) {
			var spec map[string]any
			if err := json.Unmarshal([]byte(resource.spec), &spec); err != nil {
				t.Fatal(err)
			}
			spec["switchRef"] = map[string]any{"name": "leaf"}
			if resource.kind == "FRRMigration" {
				delete(spec, "approvedDigest")
			}
			obj := &unstructured.Unstructured{Object: map[string]any{"apiVersion": api.GroupVersion.String(), "kind": "Switch" + resource.kind, "metadata": map[string]any{"name": "defaults"}, "spec": spec}}
			if err := c.Create(t.Context(), obj); err != nil {
				t.Fatal(err)
			}
			got, _, _ := unstructured.NestedMap(obj.Object, "spec")
			if got["managementPolicy"] != "Observe" {
				t.Fatalf("unsafe policy: %+v", got)
			}
			if resource.kind == "BGPPeer" && (got["adminState"] != "Down" || got["maxPrefixes"] != int64(1000)) {
				t.Fatalf("unsafe peer defaults: %+v", got)
			}
			if resource.kind == "BGP" {
				prefixes, ok := got["prefixes"].([]any)
				if !ok || len(prefixes) != 0 {
					t.Fatalf("missing empty-prefix default: %+v", got)
				}
			}
			if resource.kind == "PortChannel" && (got["minLinks"] != int64(1) || got["mtu"] != int64(9100) || got["lacpMode"] != "active" || got["adminState"] != "Up" || got["fastRate"] != false) {
				t.Fatalf("incorrect LAG defaults: %+v", got)
			}
			if !isTrafficKind(resource.kind) && resource.kind != "VRF" && resource.kind != "PortChannel" && resource.kind != "FRRMigration" && got["vrf"] != "default" {
				t.Fatalf("missing default VRF: %+v", got)
			}
			if resource.kind == "StaticRoute" {
				hops, ok := got["nextHops"].([]any)
				if !ok || len(hops) != 1 || hops[0].(map[string]any)["distance"] != int64(1) {
					t.Fatalf("missing distance default: %+v", got)
				}
			}
			fields := []string{}
			if resource.kind == "BGP" {
				fields = []string{"localASN"}
			}
			if resource.kind == "BGPPeer" {
				fields = []string{"remoteASN", "maxPrefixes"}
			}
			for _, field := range fields {
				for _, value := range []int64{0, 2147483648, 4294967295, 4294967296} {
					candidate := obj.DeepCopy()
					if err := unstructured.SetNestedField(candidate.Object, value, "spec", field); err != nil {
						t.Fatal(err)
					}
					err := c.Update(t.Context(), candidate)
					if value == 0 || value == 4294967296 {
						if !apierrors.IsInvalid(err) {
							t.Fatalf("%s=%d accepted: %v", field, value, err)
						}
					} else {
						if err != nil {
							t.Fatalf("valid uint32 %s=%d rejected: %v", field, value, err)
						}
						obj = candidate
					}
				}
			}
			if resource.kind == "PortChannel" {
				bad := obj.DeepCopy()
				_ = unstructured.SetNestedField(bad.Object, "passive", "spec", "lacpMode")
				if err := c.Update(t.Context(), bad); !apierrors.IsInvalid(err) {
					t.Fatalf("unsupported passive LACP accepted: %v", err)
				}
			}
			if resource.kind == "DHCPRelay" {
				for _, policy := range []string{"Observe", "Manage"} {
					bad := obj.DeepCopy()
					unstructured.RemoveNestedField(bad.Object, "spec", "ipv4Servers")
					unstructured.RemoveNestedField(bad.Object, "spec", "ipv6Servers")
					_ = unstructured.SetNestedField(bad.Object, policy, "spec", "managementPolicy")
					if err := c.Update(t.Context(), bad); !apierrors.IsInvalid(err) {
						t.Fatalf("empty DHCP %s accepted: %v", policy, err)
					}
				}
			}
			if resource.kind == "FRRMigration" {
				if _, exists := got["approvedDigest"]; exists {
					t.Fatalf("Observe default invents approval: %+v", got)
				}
				for _, digest := range []string{"", "abc", strings.Repeat("A", 64), strings.Repeat("g", 64), strings.Repeat("a", 65), strings.Repeat("b", 64)} {
					candidate := obj.DeepCopy()
					_ = unstructured.SetNestedField(candidate.Object, digest, "spec", "approvedDigest")
					err := c.Update(t.Context(), candidate)
					if digest == strings.Repeat("b", 64) {
						if err != nil {
							t.Fatalf("valid approval rejected: %v", err)
						}
						obj = candidate
					} else if !apierrors.IsInvalid(err) {
						t.Fatalf("malformed approval accepted: %v", err)
					}
				}
				candidate := obj.DeepCopy()
				unstructured.RemoveNestedField(candidate.Object, "spec", "approvedDigest")
				if err := c.Update(t.Context(), candidate); err != nil {
					t.Fatalf("approval removal rejected: %v", err)
				}
				obj = candidate
				for _, mode := range []string{"Traditional", "Unified"} {
					candidate := obj.DeepCopy()
					_ = unstructured.SetNestedField(candidate.Object, mode, "spec", "mode")
					if err := c.Update(t.Context(), candidate); err != nil {
						t.Fatalf("mode update to %s rejected: %v", mode, err)
					}
					obj = candidate
					changedSwitch := obj.DeepCopy()
					_ = unstructured.SetNestedField(changedSwitch.Object, "other", "spec", "switchRef", "name")
					if err := c.Update(t.Context(), changedSwitch); !apierrors.IsInvalid(err) {
						t.Fatalf("switchRef update in %s mode accepted: %v", mode, err)
					}
				}
				traditional := obj.DeepCopy()
				traditional.SetName("traditional")
				traditional.SetUID("")
				traditional.SetResourceVersion("")
				_ = unstructured.SetNestedField(traditional.Object, "Traditional", "spec", "mode")
				if err := c.Create(t.Context(), traditional); err != nil {
					t.Fatalf("Traditional creation rejected: %v", err)
				}
			}
			for _, field := range []string{"switchRef", "target"} {
				if resource.kind == "FRRMigration" && field == "target" {
					continue // mode is mutable; the device-wide target is unchanged.
				}
				changed := obj.DeepCopy()
				if field == "switchRef" {
					_ = unstructured.SetNestedField(changed.Object, "other", "spec", "switchRef", "name")
				} else {
					key, value := "name", any("VrfOther")
					switch resource.kind {
					case "PortChannel":
						value = "PortChannel11"
					case "L3Interface":
						value = "Vlan11"
					case "StaticRoute":
						key, value = "prefix", "198.51.100.0/24"
					case "BGP":
						key, value = "vrf", "VrfOther"
					case "BGPPeer":
						key, value = "address", "192.0.2.3"
					case "DHCPRelay":
						key, value = "vlanID", int64(11)
					case "ACLBinding":
						key, value = "policy", "other"
					case "QoSBinding":
						key, value = "interfaceName", "Ethernet4"
					}
					_ = unstructured.SetNestedField(changed.Object, value, "spec", key)
				}
				if err := c.Update(t.Context(), changed); !apierrors.IsInvalid(err) {
					t.Fatalf("%s update accepted: %v", field, err)
				}
			}
			for _, invalid := range []string{"policy", "huge", "value", "duplicate"} {
				bad := obj.DeepCopy()
				bad.SetName(invalid)
				bad.SetResourceVersion("")
				bad.SetUID("")
				key, value := "managementPolicy", any("manage")
				switch invalid {
				case "huge":
					key, value = "switchRef", map[string]any{"name": strings.Repeat("a", 254)}
				case "value":
					switch resource.kind {
					case "PortChannel":
						key, value = "name", "PortChannel00"
					case "VRF":
						key, value = "name", "mgmt"
					case "L3Interface":
						key, value = "addresses", []any{"2001:db8::gg/64"}
					case "StaticRoute":
						key, value = "prefix", "192.0.2.1/24"
					case "BGP":
						key, value = "routerID", "2001:db8::1"
					case "BGPPeer":
						key, value = "address", "300.1.1.1"
					case "DHCPRelay":
						key, value = "ipv6Servers", []any{"192.0.2.1"}
					case "FRRMigration":
						key, value = "mode", "split-unified"
					}
				case "duplicate":
					switch resource.kind {
					case "PortChannel":
						key, value = "members", []any{"Ethernet0", "Ethernet0"}
					case "VRF":
						key, value = "name", "default"
					case "L3Interface":
						key, value = "addresses", []any{"192.0.2.1/24", "192.0.2.1/24"}
					case "StaticRoute":
						key, value = "nextHops", []any{map[string]any{"address": "192.0.2.2"}, map[string]any{"address": "192.0.2.2"}}
					case "BGP":
						key, value = "prefixes", []any{"192.0.2.0/24", "192.0.2.0/24"}
					case "BGPPeer":
						key, value = "addressFamilies", []any{"ipv4Unicast", "ipv4Unicast"}
					case "DHCPRelay":
						key, value = "ipv4Servers", []any{"192.0.2.1", "192.0.2.1"}
					case "FRRMigration":
						key, value = "approvedDigest", strings.Repeat("A", 64)
					}
				}
				_ = unstructured.SetNestedField(bad.Object, value, "spec", key)
				if isTrafficKind(resource.kind) && (invalid == "value" || invalid == "duplicate") {
					// Normalize numbers and slices into unstructured-compatible values.
					raw, _ := json.Marshal(trafficInvalidFields(resource.kind, invalid == "duplicate"))
					var fields map[string]any
					_ = json.Unmarshal(raw, &fields)
					for key, value := range fields {
						_ = unstructured.SetNestedField(bad.Object, value, "spec", key)
					}
				}
				if err := c.Create(t.Context(), bad); !apierrors.IsInvalid(err) {
					t.Fatalf("%s accepted: %v", invalid, err)
				}
			}
			obj.Object["status"] = map[string]any{"observed": map[string]any{"nested": map[string]any{"foo": []any{"bar"}}}}
			if err := c.Status().Update(t.Context(), obj); err != nil {
				t.Fatal(err)
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(obj), obj); err != nil {
				t.Fatal(err)
			}
			if _, ok, _ := unstructured.NestedFieldNoCopy(obj.Object, "status", "observed", "nested", "foo"); !ok {
				t.Fatal("raw observation pruned")
			}
		})
	}
	for i, tc := range trafficValidationCases {
		t.Run("traffic/"+tc.name, func(t *testing.T) {
			// Use the Kubernetes JSON decoder to retain exact int64 values.
			obj := &unstructured.Unstructured{}
			raw := fmt.Sprintf(`{"apiVersion":%q,"kind":%q,"metadata":{"name":"contract-%d"},"spec":%s}`, api.GroupVersion.String(), "Switch"+tc.kind, i, tc.spec)
			if err := obj.UnmarshalJSON([]byte(raw)); err != nil {
				t.Fatal(err)
			}
			_ = unstructured.SetNestedField(obj.Object, "leaf", "spec", "switchRef", "name")
			err := c.Create(t.Context(), obj)
			if tc.valid {
				if err != nil {
					t.Fatalf("valid contract rejected: %v", err)
				}
				if tc.kind == "Scheduler" {
					meter, _, _ := unstructured.NestedString(obj.Object, "spec", "meterType")
					if meter == "" {
						t.Fatal("missing Bytes default")
					}
				}
			} else if !apierrors.IsInvalid(err) {
				t.Fatalf("invalid contract accepted: %v", err)
			}
		})
	}
	t.Run("QoS map type immutable", func(t *testing.T) {
		obj := &api.SwitchQoSMap{}
		if err := c.Get(t.Context(), client.ObjectKey{Name: "defaults"}, obj); err != nil {
			t.Fatal(err)
		}
		obj.Spec.Type = "TCToQueue"
		if err := c.Update(t.Context(), obj); !apierrors.IsInvalid(err) {
			t.Fatalf("type update accepted: %v", err)
		}
	})
	t.Run("traffic documentation samples", func(t *testing.T) {
		doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "usage", "traffic-policy.md"))
		if err != nil {
			t.Fatal(err)
		}
		blocks := regexp.MustCompile("(?s)```yaml\\n(.*?)```").FindAllSubmatch(doc, -1)
		count := 0
		for _, block := range blocks {
			for _, sample := range strings.Split(string(block[1]), "\n---\n") {
				data, err := yaml.YAMLToJSON([]byte(sample))
				if err != nil {
					t.Fatal(err)
				}
				obj := &unstructured.Unstructured{}
				if err := obj.UnmarshalJSON(data); err != nil {
					t.Fatal(err)
				}
				if err := c.Create(t.Context(), obj); err != nil {
					t.Fatal(err)
				}
				policy, _, _ := unstructured.NestedString(obj.Object, "spec", "managementPolicy")
				if policy != "Observe" {
					t.Fatal("sample permits writes")
				}
				count++
			}
		}
		if count != 6 {
			t.Fatalf("validated %d samples, want 6", count)
		}
	})
}
