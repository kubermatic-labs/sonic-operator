// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"reflect"
	"testing"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

var breakoutTypedClaims = []struct {
	name string
	set  func(*api.SwitchInterface)
}{
	{"speed", func(i *api.SwitchInterface) { value := uint32(25000); i.Spec.Speed = &value }},
	{"MTU", func(i *api.SwitchInterface) { value := uint32(9100); i.Spec.MTU = &value }},
	{"FEC", func(i *api.SwitchInterface) { i.Spec.FEC = "rs" }},
	{"target binding", func(i *api.SwitchInterface) {
		i.Annotations = map[string]string{networkTargetAnnotation: "retained-target"}
	}},
	{"recorded request", func(i *api.SwitchInterface) {
		i.Annotations = map[string]string{networkRequestAnnotation: `{"nativeName":"Ethernet1","speed":25000}`}
	}},
	{"recovery finalizer", func(i *api.SwitchInterface) { i.Finalizers = []string{networkRecoveryFinalizer} }},
}

func TestSwitchPortBreakoutTypedClaimsPreserved(t *testing.T) {
	t.Parallel()
	for _, claim := range breakoutTypedClaims {
		for _, native := range []string{"Ethernet0", "Ethernet1"} {
			for _, policy := range []api.NetworkManagementPolicy{api.NetworkManagementPolicyManage, api.NetworkManagementPolicyObserve} {
				t.Run(claim.name+"/"+native+"/"+string(policy), func(t *testing.T) {
					t.Parallel()
					b, s, a, c, r := breakoutFixture(t)
					a.current, a.response = a.response, a.current
					a.response.RuntimeVerified, a.response.PersistenceVerified = true, true
					b.Spec.Mode = "1x100G"
					if err := c.Update(t.Context(), b); err != nil {
						t.Fatal(err)
					}
					i := breakoutInventory(s, native, api.AdminStateDown)
					i.Spec.ManagementPolicy = policy
					claim.set(i)
					if err := c.Create(t.Context(), i); err != nil {
						t.Fatal(err)
					}
					before := i.DeepCopy()
					for range 2 {
						if err := reconcileBreakout(t, r, b); err == nil {
							t.Error("destructive merge accepted typed intent without admin annotation")
						}
					}
					if len(a.requests) != 0 {
						t.Errorf("typed claim dispatched destructive breakout: %+v", a.requests)
					}
					if err := c.Get(t.Context(), client.ObjectKeyFromObject(i), i); err != nil || !reflect.DeepEqual(before, i) {
						t.Fatalf("breakout deleted or changed typed declaration/UID: %v", err)
					}
					if t.Failed() {
						return
					}
					// The same claim remains compatible with exact no-op adoption.
					b = getBreakout(t, c, b)
					b.Spec.Mode = a.current.Mode
					if err := c.Update(t.Context(), b); err != nil {
						t.Fatal(err)
					}
					response := *a.current
					response.RuntimeVerified, response.PersistenceVerified = true, true
					a.response = &response
					for range 2 {
						if err := reconcileBreakout(t, r, b); err != nil {
							t.Fatal(err)
						}
					}
					if len(a.requests) != 1 || !a.requests[0].AdoptOnly {
						t.Fatalf("matching adoption not allowed/fenced: %+v", a.requests)
					}
					if err := c.Get(t.Context(), client.ObjectKeyFromObject(i), i); err != nil || !reflect.DeepEqual(before, i) {
						t.Fatalf("no-op changed typed declaration/UID: %v", err)
					}
				})
			}
		}
	}
}

func TestSwitchPortBreakoutTypedCleanupFreshness(t *testing.T) {
	t.Parallel()
	for _, claim := range breakoutTypedClaims {
		for _, late := range []bool{false, true} {
			name := "existing/"
			if late {
				name = "final uncached read/"
			}
			t.Run(name+claim.name, func(t *testing.T) {
				t.Parallel()
				b, s, a, c, r := breakoutFixture(t)
				i := breakoutInventory(s, "Ethernet1", api.AdminStateDown)
				i.Spec.ManagementPolicy = api.NetworkManagementPolicyObserve
				if !late {
					claim.set(i)
				}
				for _, obj := range []client.Object{i, breakoutInventory(s, "Ethernet0", api.AdminStateUp)} {
					if err := c.Create(t.Context(), obj); err != nil {
						t.Fatal(err)
					}
				}
				before := i.DeepCopy()
				if err := observeBreakout(b, a.current); err != nil {
					t.Fatal(err)
				}
				inserted := false
				if late {
					r.APIReader = interceptor.NewClient(c, interceptor.Funcs{Get: func(ctx context.Context, cli client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
						if _, ok := obj.(*api.SwitchInterface); ok && key == client.ObjectKeyFromObject(i) && !inserted {
							inserted = true
							claim.set(i)
							if err := cli.Update(ctx, i); err != nil {
								return err
							}
							before = i.DeepCopy()
						}
						return cli.Get(ctx, key, obj, opts...)
					}})
				}
				previous := []api.SwitchPortBreakoutChild{{Name: "Ethernet1", Lanes: "2"}}
				err := r.reconcileBreakoutInventory(t.Context(), b, s, a, a, previous, false)
				if late && (!inserted || err == nil) {
					t.Errorf("late typed intent did not block final cleanup: inserted=%t err=%v", inserted, err)
				}
				if err := c.Get(t.Context(), client.ObjectKeyFromObject(i), i); err != nil || !reflect.DeepEqual(before, i) || !i.DeletionTimestamp.IsZero() {
					t.Fatalf("cleanup deleted or changed Observe typed declaration/UID: %v", err)
				}
				if len(a.requests) != 0 {
					t.Fatal("cleanup issued native request")
				}
			})
		}
	}
}
