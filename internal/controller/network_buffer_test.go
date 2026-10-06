// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"encoding/json"
	"testing"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestNetworkBufferResources(t *testing.T) {
	for _, tc := range []struct{ kind, spec, target string }{
		{"BufferPool", `{"name":"PORT3_INGRESS_POOL","type":"ingress","mode":"dynamic","size":100000}`, "PORT3_INGRESS_POOL"},
		{"BufferProfile", `{"name":"PORT3_INGRESS_PROFILE","pool":"PORT3_INGRESS_POOL","size":0,"dynamicThreshold":3}`, "PORT3_INGRESS_PROFILE"},
		{"BufferPG", `{"interfaceName":"Ethernet11","range":"7","profile":"PORT3_INGRESS_PROFILE"}`, "Ethernet11/7"},
		{"BufferQueue", `{"interfaceName":"Ethernet11","range":"0-7","profile":"out"}`, "Ethernet11/0-7"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			obj, list, err := networkObjects(tc.kind)
			if err != nil {
				t.Fatal(err)
			}
			scheme := runtime.NewScheme()
			if err := api.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			if _, _, err := scheme.ObjectKinds(obj); err != nil {
				t.Fatal(err)
			}
			if _, _, err := scheme.ObjectKinds(list); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(`{"metadata":{"name":"test","uid":"uid"},"spec":`+tc.spec+`}`), obj); err != nil {
				t.Fatal(err)
			}
			_, _, common := networkFields(obj)
			common.SwitchRef.Name = "switch-1"
			req, target, err := networkDesired(tc.kind, obj)
			if err != nil {
				t.Fatal(err)
			}
			if req.Kind != tc.kind || target != tc.target || !isTrafficKind(tc.kind) {
				t.Fatalf("request=%v target=%s", req, target)
			}
			if err := json.Unmarshal([]byte(`{"spec":{"name":"invalid|name","interfaceName":"eth0"}}`), obj); err != nil {
				t.Fatal(err)
			}
			if _, _, err := networkDesired(tc.kind, obj); err == nil {
				t.Fatal("invalid bypass object accepted")
			}
		})
	}
}

func TestNetworkBufferRecoveryRangeImmutable(t *testing.T) {
	obj, _, a, c, r := networkFixture(t, "BufferPG", `{"interfaceName":"Ethernet11","range":"7","profile":"PORT3_INGRESS_PROFILE"}`)
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}
	if _, err := r.Reconcile(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(t.Context(), req.NamespacedName, obj); err != nil {
		t.Fatal(err)
	}
	obj.(*api.SwitchBufferPG).Spec.Range = "6"
	if err := c.Update(t.Context(), obj); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(t.Context(), obj); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(t.Context(), req); err == nil {
		t.Fatal("mutated buffer selector recovered")
	}
	if len(a.recoveries) != 0 {
		t.Fatal("changed buffer range contacted recovery RPC")
	}
}
