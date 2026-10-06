// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestSwitchPortBreakoutPopulatedAdoption(t *testing.T) {
	t.Parallel()
	b, s, a, c, r := breakoutFixture(t)
	current := *a.response
	current.PersistenceVerified = false
	a.current = &current
	i := breakoutInventory(s, "Ethernet0", api.AdminStateUp)
	i.Annotations = map[string]string{breakoutManageAdminAnnotation: "true"}
	if err := c.Create(t.Context(), i); err != nil {
		t.Fatal(err)
	}
	before := i.DeepCopy()
	v := &api.SwitchVLAN{ObjectMeta: metav1.ObjectMeta{Name: "vlan100"}, Spec: api.SwitchVLANSpec{SwitchRef: api.SwitchVLANReference{Name: s.Name}, VLANID: 100, Members: []api.SwitchVLANMember{{InterfaceName: "Ethernet0", TaggingMode: "untagged"}}}}
	if err := c.Create(t.Context(), v); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := reconcileBreakout(t, r, b); err != nil {
			t.Fatal(err)
		}
	}
	got := getBreakout(t, c, b)
	if !meta.IsStatusConditionTrue(got.Status.Conditions, "Ready") || len(a.requests) != 1 {
		t.Fatalf("adoption failed: %+v", got.Status)
	}
	if !a.requests[0].AdoptOnly {
		t.Fatal("populated adoption is not fenced against transitions")
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(i), i); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, i) {
		t.Fatal("adoption changed managed interface declaration")
	}
}

func TestSwitchPortBreakoutAdoptionAfterPreparedAttributeChange(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"admin", "MTU"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b, s, a, c, r := breakoutFixture(t)
			current := *a.response
			current.Children = append([]agent.PortBreakoutChild(nil), current.Children...)
			current.PersistenceVerified = false
			a.current = &current
			i := breakoutInventory(s, "Ethernet0", api.AdminStateUp)
			i.Annotations = map[string]string{breakoutManageAdminAnnotation: "true"}
			if err := c.Create(t.Context(), i); err != nil {
				t.Fatal(err)
			}
			v := &api.SwitchVLAN{ObjectMeta: metav1.ObjectMeta{Name: "vlan100"}, Spec: api.SwitchVLANSpec{SwitchRef: api.SwitchVLANReference{Name: s.Name}, VLANID: 100, Members: []api.SwitchVLANMember{{InterfaceName: "Ethernet0", TaggingMode: "untagged"}}}}
			if err := c.Create(t.Context(), v); err != nil {
				t.Fatal(err)
			}
			if err := reconcileBreakout(t, r, b); err != nil {
				t.Fatal(err)
			}
			prepared := getBreakout(t, c, b)
			condition := meta.FindStatusCondition(prepared.Status.Conditions, "Ready")
			if condition == nil || condition.Reason != "BreakoutPrepared" || len(prepared.Status.PreviousChildren) != 4 || len(a.requests) != 0 {
				t.Fatalf("adoption not prepared before attribute update: %+v", prepared.Status)
			}
			if name == "admin" {
				current.Children[0].AdminState = "down"
				i.Spec.AdminState = api.AdminStateDown
				if err := c.Update(t.Context(), i); err != nil {
					t.Fatal(err)
				}
			} else {
				current.Children[0].MTU = "1500"
			}
			before := i.DeepCopy()
			response := current
			response.Children = append([]agent.PortBreakoutChild(nil), current.Children...)
			response.PersistenceVerified = true
			a.response = &response
			// Resume from durable preparation, then cover another periodic adoption.
			restarted := *r
			for attempt := range 3 {
				if err := reconcileBreakout(t, &restarted, b); err != nil {
					t.Errorf("reconcile %d after attribute update: %v", attempt+1, err)
				}
			}
			got := getBreakout(t, c, b)
			if !meta.IsStatusConditionTrue(got.Status.Conditions, "Ready") || len(got.Status.PreviousChildren) != 0 || len(a.requests) != 2 {
				t.Fatalf("adoption did not complete on retries: ready=%t previousChildren=%d requests=%+v", meta.IsStatusConditionTrue(got.Status.Conditions, "Ready"), len(got.Status.PreviousChildren), a.requests)
			}
			for _, request := range a.requests {
				if !request.AdoptOnly {
					t.Fatal("attribute update allowed a transition-capable request")
				}
			}
			if got.Status.Children[0].AdminState != i.Spec.AdminState || got.Status.Children[0].MTU != current.Children[0].MTU {
				t.Fatalf("adoption did not preserve fresh attributes: %+v", got.Status.Children[0])
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(i), i); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, i) {
				t.Fatal("adoption changed managed interface declaration")
			}
			gotVLAN := &api.SwitchVLAN{}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(v), gotVLAN); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(v, gotVLAN) {
				t.Fatal("adoption changed VLAN declaration")
			}
		})
	}
}

func TestSwitchPortBreakoutPendingTransitionKeepsPreflight(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"VLAN", "admin managed", "no dependencies"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b, s, a, c, r := breakoutFixture(t)
			if err := reconcileBreakout(t, r, b); err != nil {
				t.Fatal(err)
			}
			a.writeErr = errors.New("save failed after native transition")
			a.onWrite = func() { a.current = a.response }
			if err := reconcileBreakout(t, r, b); err == nil {
				t.Fatal("pending transition failure hidden")
			}
			a.writeErr, a.onWrite = nil, nil
			a.current.Pending = true
			response := *a.response
			response.Pending = false
			a.response = &response
			switch name {
			case "VLAN":
				v := &api.SwitchVLAN{ObjectMeta: metav1.ObjectMeta{Name: "vlan100"}, Spec: api.SwitchVLANSpec{SwitchRef: api.SwitchVLANReference{Name: s.Name}, VLANID: 100, Members: []api.SwitchVLANMember{{InterfaceName: "Ethernet0", TaggingMode: "untagged"}}}}
				if err := c.Create(t.Context(), v); err != nil {
					t.Fatal(err)
				}
			case "admin managed":
				i := breakoutInventory(s, "Ethernet0", api.AdminStateUp)
				i.Annotations = map[string]string{breakoutManageAdminAnnotation: "true"}
				if err := c.Create(t.Context(), i); err != nil {
					t.Fatal(err)
				}
			}
			restarted := *r
			for range 3 {
				err := reconcileBreakout(t, &restarted, b)
				if name == "no dependencies" {
					if err != nil {
						t.Fatal(err)
					}
				} else if err == nil || !(strings.Contains(err.Error(), "SwitchVLAN") || strings.Contains(err.Error(), "admin-management annotation")) {
					t.Fatalf("pending transition bypassed dependency preflight: %v", err)
				}
			}
			if name == "no dependencies" {
				if len(a.requests) != 2 || a.requests[0] != a.requests[1] || a.requests[1].AdoptOnly {
					t.Fatalf("recovery changed the recorded transition request: %+v", a.requests)
				}
			} else if len(a.requests) != 1 || !getBreakout(t, c, b).Status.Pending {
				t.Fatal("dependency conflict dispatched recovery or cleared pending")
			}
		})
	}
}

func TestSwitchPortBreakoutPreparedLayoutChangeKeepsPreflight(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"name", "lanes", "speed", "mode"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b, s, a, c, r := breakoutFixture(t)
			current := *a.response
			current.Children = append([]agent.PortBreakoutChild(nil), current.Children...)
			a.current = &current
			switch name {
			case "name":
				current.Children[1].Name = "Ethernet4"
			case "lanes":
				current.Children[0].Lanes, current.Children[1].Lanes = current.Children[1].Lanes, current.Children[0].Lanes
			case "speed":
				current.Children[0].Speed = "10000"
			}
			if err := reconcileBreakout(t, r, b); err != nil {
				t.Fatal(err)
			}
			a.current = a.response
			if name == "mode" {
				a.current.Mode = "1x100G"
			}
			v := &api.SwitchVLAN{ObjectMeta: metav1.ObjectMeta{Name: "vlan100"}, Spec: api.SwitchVLANSpec{SwitchRef: api.SwitchVLANReference{Name: s.Name}, VLANID: 100, Members: []api.SwitchVLANMember{{InterfaceName: "Ethernet0", TaggingMode: "untagged"}}}}
			if err := c.Create(t.Context(), v); err != nil {
				t.Fatal(err)
			}
			for range 3 {
				if err := reconcileBreakout(t, r, b); err == nil || !strings.Contains(err.Error(), "SwitchVLAN") {
					t.Fatalf("layout change bypassed transition preflight: %v", err)
				}
			}
			if len(a.requests) != 0 {
				t.Fatal("layout change dispatched a request despite dependencies")
			}
		})
	}
}

func TestSwitchPortBreakoutAdoptionConflicts(t *testing.T) {
	for _, name := range []string{"old agent", "duplicate claim", "foreign owner", "unverified layout", "changed admin response", "changed MTU response"} {
		t.Run(name, func(t *testing.T) {
			b, s, a, c, r := breakoutFixture(t)
			current := *a.response
			a.current = &current
			i := breakoutInventory(s, "Ethernet0", api.AdminStateUp)
			switch name {
			case "old agent":
				a.current.AdoptionSupported = false
			case "duplicate claim":
				other := b.DeepCopy()
				other.Name, other.UID, other.ResourceVersion = "other", "other", ""
				if err := c.Create(t.Context(), other); err != nil {
					t.Fatal(err)
				}
			case "foreign owner":
				i.OwnerReferences[0].UID = "foreign"
			case "unverified layout":
				a.current.ConfigurationVerified = false
				i.Annotations = map[string]string{breakoutManageAdminAnnotation: "true"}
			case "changed admin response":
				a.response.Children = append([]agent.PortBreakoutChild(nil), a.response.Children...)
				a.response.Children[0].AdminState = "down"
			case "changed MTU response":
				a.response.Children = append([]agent.PortBreakoutChild(nil), a.response.Children...)
				a.response.Children[0].MTU = "1500"
			}
			if err := c.Create(t.Context(), i); err != nil {
				t.Fatal(err)
			}
			var err error
			for range 2 {
				err = reconcileBreakout(t, r, b)
			}
			if err == nil {
				t.Fatal("adoption conflict accepted")
			}
			if name != "changed admin response" && name != "changed MTU response" && len(a.requests) != 0 {
				t.Fatal("conflict allowed write")
			}
			if meta.IsStatusConditionTrue(getBreakout(t, c, b).Status.Conditions, "Ready") {
				t.Fatal("conflict Ready")
			}
		})
	}
}
