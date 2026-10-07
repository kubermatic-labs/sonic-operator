// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestNetworkBufferRepairEligibilityIsScoped(t *testing.T) {
	for _, tc := range networkTestSpecs {
		if tc.kind != "VRF" && tc.kind != "QoSMap" && tc.kind != "QoSBinding" {
			continue
		}
		obj, _, a, _, r := networkFixture(t, tc.kind, tc.spec)
		a.current = &agent.NetworkResult{Exists: true, ConfigurationVerified: true, PersistenceVerified: true, BufferRepairEligible: true}
		_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)})
		if err == nil || len(a.requests) != 0 {
			t.Fatalf("buffer eligibility enabled %s writes: %v", tc.kind, err)
		}
	}
}

func TestNetworkBufferRepairStillRequiresManagerGates(t *testing.T) {
	obj, _, a, _, r := networkFixture(t, "BufferPool", `{"name":"pool","type":"ingress","mode":"dynamic","size":1000}`)
	a.current = &agent.NetworkResult{Exists: true, ConfigurationVerified: true, PersistenceVerified: true, BufferRepairEligible: true}
	r.AllowTrafficPolicy = false
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}); err != nil {
		t.Fatal(err)
	}
	if len(a.requests) != 0 {
		t.Fatal("disabled traffic gate allowed repair")
	}
}
