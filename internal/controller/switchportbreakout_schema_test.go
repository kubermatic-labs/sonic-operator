//go:build integration

// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"path/filepath"
	"testing"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestSwitchPortBreakoutSchema(t *testing.T) {
	env := &envtest.Environment{BinaryAssetsDirectory: getFirstFoundEnvTestBinaryDir(), CRDDirectoryPaths: []string{filepath.Join("..", "..", "config", "crd", "bases", "sonic.networking.metal.ironcore.dev_switchportbreakouts.yaml")}, ErrorIfCRDPathMissing: true}
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
	b := &api.SwitchPortBreakout{ObjectMeta: metav1.ObjectMeta{Name: "defaults"}, Spec: api.SwitchPortBreakoutSpec{SwitchRef: api.SwitchPortBreakoutReference{Name: "leaf"}, Port: "Ethernet0", Mode: "4x25G"}}
	if err := c.Create(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	if b.Spec.ManagementPolicy != api.BreakoutManagementPolicyObserve || b.Spec.ChildAdminState != api.AdminStateDown {
		t.Fatalf("unsafe defaults: %+v", b.Spec)
	}
	for _, field := range []string{"reference", "port"} {
		t.Run("immutable-"+field, func(t *testing.T) {
			changed := b.DeepCopy()
			if field == "reference" {
				changed.Spec.SwitchRef.Name = "other"
			} else {
				changed.Spec.Port = "Ethernet4"
			}
			if err := c.Update(t.Context(), changed); !apierrors.IsInvalid(err) {
				t.Fatalf("immutable update accepted: %v", err)
			}
		})
	}
	for _, name := range []string{"alias", "leading-zero", "empty-reference", "empty-mode", "lowercase-policy", "lowercase-admin", "unknown-admin"} {
		t.Run(name, func(t *testing.T) {
			invalid := b.DeepCopy()
			invalid.ObjectMeta = metav1.ObjectMeta{Name: name}
			switch name {
			case "alias":
				invalid.Spec.Port = "eth0-0"
			case "leading-zero":
				invalid.Spec.Port = "Ethernet00"
			case "empty-reference":
				invalid.Spec.SwitchRef.Name = ""
			case "empty-mode":
				invalid.Spec.Mode = ""
			case "lowercase-policy":
				invalid.Spec.ManagementPolicy = "manage"
			case "lowercase-admin":
				invalid.Spec.ChildAdminState = "down"
			case "unknown-admin":
				invalid.Spec.ChildAdminState = api.AdminStateUnknown
			}
			if err := c.Create(t.Context(), invalid); !apierrors.IsInvalid(err) {
				t.Fatalf("invalid spec accepted: %v", err)
			}
		})
	}
}
