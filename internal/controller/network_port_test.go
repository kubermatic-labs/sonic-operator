// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"encoding/json"
	"testing"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNetworkPortDesired(t *testing.T) {
	obj, _, _, _, _ := networkFixture(t, "Port", `{"nativeName":"Ethernet0","handle":"port-0","adminState":"Down","speed":1000,"mtu":9100}`)
	r, target, err := networkDesired("Port", obj)
	if err != nil || target != "Ethernet0" {
		t.Fatalf("target=%s err=%v", target, err)
	}
	var spec map[string]any
	if err := json.Unmarshal(r.Spec, &spec); err != nil {
		t.Fatal(err)
	}
	if spec["speed"] != float64(1000) || spec["mtu"] != float64(9100) || spec["managementPolicy"] != "Manage" {
		t.Fatalf("wrong projection: %s", r.Spec)
	}
	if _, ok := spec["fec"]; ok {
		t.Fatal("invented omitted FEC")
	}
}

func TestNetworkPortInventoryIsNotAClaim(t *testing.T) {
	obj, sw, _, c, r := networkFixture(t, "Port", `{"nativeName":"Ethernet0","handle":"port-0","speed":1000}`)
	other := &api.SwitchInterface{ObjectMeta: metav1.ObjectMeta{Name: "inventory", UID: "inventory-uid"}, Spec: api.SwitchInterfaceSpec{NativeName: "Ethernet4", Handle: "port-4", SwitchRef: &corev1.LocalObjectReference{Name: "leaf"}}}
	if err := c.Create(t.Context(), other); err != nil {
		t.Fatal(err)
	}
	if err := r.checkNetworkClaims(t.Context(), obj, sw, "Ethernet0"); err != nil {
		t.Fatalf("inventory blocked ownership: %v", err)
	}
	other.Spec.NativeName = "Ethernet0"
	speed := uint32(1000)
	other.Spec.Speed = &speed
	if err := c.Update(t.Context(), other); err != nil {
		t.Fatal(err)
	}
	if err := r.checkNetworkClaims(t.Context(), obj, sw, "Ethernet0"); err == nil {
		t.Fatal("duplicate port owner accepted")
	}
}
