//go:build integration

// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestSwitchVLANSchema(t *testing.T) {
	env := &envtest.Environment{
		BinaryAssetsDirectory: getFirstFoundEnvTestBinaryDir(),
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases", "sonic.networking.metal.ironcore.dev_switchvlans.yaml")},
		ErrorIfCRDPathMissing: true,
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
	for _, tc := range []struct {
		name   string
		change func(*api.SwitchVLAN)
		field  string
	}{
		{name: "zero", change: func(v *api.SwitchVLAN) { v.Spec.VLANID = 0 }, field: "spec.vlanID"},
		{name: "reserved", change: func(v *api.SwitchVLAN) { v.Spec.VLANID = 4095 }, field: "spec.vlanID"},
		{name: "mode", change: func(v *api.SwitchVLAN) { v.Spec.Members[0].TaggingMode = "TAGGED" }, field: "taggingMode"},
		{name: "missing-mode", change: func(v *api.SwitchVLAN) { v.Spec.Members[0].TaggingMode = "" }, field: "taggingMode"},
		{name: "alias", change: func(v *api.SwitchVLAN) { v.Spec.Members[0].InterfaceName = "eth0" }, field: "interfaceName"},
		{name: "leading-zero", change: func(v *api.SwitchVLAN) { v.Spec.Members[0].InterfaceName = "Ethernet00" }, field: "interfaceName"},
		{name: "duplicate", change: func(v *api.SwitchVLAN) { v.Spec.Members = append(v.Spec.Members, v.Spec.Members[0]) }, field: "spec.members"},
		{name: "empty-reference", change: func(v *api.SwitchVLAN) { v.Spec.SwitchRef.Name = "" }, field: "spec.switchRef.name"},
		{name: "policy", change: func(v *api.SwitchVLAN) { v.Spec.ManagementPolicy = "manage" }, field: "managementPolicy"},
		{name: "reconcile-policy", change: func(v *api.SwitchVLAN) { v.Spec.ReconcilePolicy = "authoritative" }, field: "reconcilePolicy"},
		{name: "deletion-policy", change: func(v *api.SwitchVLAN) { v.Spec.DeletionPolicy = "delete" }, field: "deletionPolicy"},
		{name: "short-digest", change: func(v *api.SwitchVLAN) { v.Spec.AdoptionDigest = "abc" }, field: "adoptionDigest"},
		{name: "uppercase-digest", change: func(v *api.SwitchVLAN) { v.Spec.AdoptionDigest = strings.Repeat("A", 64) }, field: "adoptionDigest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, _, _ := vlanFixture(t)
			v.ObjectMeta = metav1.ObjectMeta{Name: tc.name}
			tc.change(v)
			err := c.Create(t.Context(), v)
			if !apierrors.IsInvalid(err) || !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("expected admission failure for %s, got %v", tc.field, err)
			}
		})
	}
	t.Run("required-reference-name", func(t *testing.T) {
		v := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": api.GroupVersion.String(), "kind": "SwitchVLAN",
			"metadata": map[string]any{"name": "required-reference-name"},
			"spec":     map[string]any{"switchRef": map[string]any{}, "vlanID": int64(100)},
		}}
		err := c.Create(t.Context(), v)
		if !apierrors.IsInvalid(err) || !strings.Contains(err.Error(), "spec.switchRef.name") {
			t.Fatalf("expected required reference name rejection, got %v", err)
		}
	})
	t.Run("default-and-updates", func(t *testing.T) {
		v, _, _ := vlanFixture(t)
		v.ObjectMeta = metav1.ObjectMeta{Name: "valid"}
		v.Spec.ManagementPolicy = ""
		if err := c.Create(t.Context(), v); err != nil {
			t.Fatal(err)
		}
		if v.Spec.ManagementPolicy != api.VLANManagementPolicyObserve {
			t.Fatalf("policy default = %q", v.Spec.ManagementPolicy)
		}
		if v.Spec.ReconcilePolicy != api.VLANReconcilePolicyAdditive || v.Spec.DeletionPolicy != api.VLANDeletionPolicyOrphan {
			t.Fatalf("unsafe defaults: %#v", v.Spec)
		}
		for _, field := range []string{"switchRef", "vlanID"} {
			t.Run("immutable-"+field, func(t *testing.T) {
				changed := v.DeepCopy()
				if field == "switchRef" {
					changed.Spec.SwitchRef.Name = "other"
				} else {
					changed.Spec.VLANID = 200
				}
				err := c.Update(t.Context(), changed)
				if !apierrors.IsInvalid(err) || !strings.Contains(err.Error(), field+" is immutable") {
					t.Fatalf("expected immutable %s rejection, got %v", field, err)
				}
			})
		}
		v.Spec.ManagementPolicy = api.VLANManagementPolicyManage
		v.Spec.ReconcilePolicy = api.VLANReconcilePolicyAuthoritative
		v.Spec.DeletionPolicy = api.VLANDeletionPolicyDelete
		v.Spec.AdoptionDigest = strings.Repeat("a", 64)
		v.Spec.Members = append(v.Spec.Members, api.SwitchVLANMember{InterfaceName: "Ethernet129", TaggingMode: "tagged"})
		if err := c.Update(t.Context(), v); err != nil {
			t.Fatal(err)
		}
		got := &api.SwitchVLAN{}
		if err := c.Get(t.Context(), client.ObjectKeyFromObject(v), got); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got.Spec, v.Spec) || got.Generation != 2 {
			t.Fatalf("valid spec update not persisted: %#v", got)
		}
		got.Status.OwnerID = string(got.UID)
		got.Status.TargetIdentity = strings.Repeat("b", 64)
		got.Status.AdoptionDigest = strings.Repeat("c", 64)
		got.Status.RuntimeVerified, got.Status.PersistenceVerified = true, true
		if err := c.Status().Update(t.Context(), got); err != nil {
			t.Fatal(err)
		}
		confirmed := &api.SwitchVLAN{}
		if err := c.Get(t.Context(), client.ObjectKeyFromObject(got), confirmed); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(confirmed.Status, got.Status) || confirmed.Generation != 2 {
			t.Fatalf("ownership status not preserved: %#v", confirmed)
		}
		confirmed.Finalizers = []string{vlanAuthorityFinalizer}
		if err := c.Update(t.Context(), confirmed); err != nil {
			t.Fatal(err)
		}
		if err := c.Delete(t.Context(), confirmed); err != nil {
			t.Fatal(err)
		}
		if err := c.Get(t.Context(), client.ObjectKeyFromObject(got), confirmed); err != nil {
			t.Fatal(err)
		}
		if confirmed.DeletionTimestamp.IsZero() || len(confirmed.Finalizers) != 1 {
			t.Fatal("API deletion did not retain authority finalizer")
		}
	})
}
