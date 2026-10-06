//go:build integration

// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"path/filepath"
	"testing"

	agentclient "github.com/ironcore-dev/sonic-operator/internal/agent/agent_client/client"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// Exercise the shipped CRD, API status subresource and annotation-only updates:
// fake-client JSON tests alone cannot detect the API pruning new status fields.
func TestAdminAdoptionStatusAPIRoundTrip(t *testing.T) {
	env := &envtest.Environment{BinaryAssetsDirectory: getFirstFoundEnvTestBinaryDir(), ErrorIfCRDPathMissing: true,
		CRDDirectoryPaths: []string{filepath.Join("..", "..", "config", "crd", "bases", "sonic.networking.metal.ironcore.dev_switchinterfaces.yaml")},
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
	_, i, a, scheme := adoptionFixture(t)
	i.Annotations = map[string]string{manageAdminAnnotation: "true", adminRequestAnnotation: "api-adoption-a"}
	a.iface.AdminStatus = agent.StatusDown
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Create(t.Context(), i); err != nil {
		t.Fatal(err)
	}
	r := &SwitchInterfaceReconciler{Client: c, Scheme: scheme, NewAgentClient: func(context.Context, client.Reader, *corev1.LocalObjectReference, string) (agentclient.SwitchAgentClient, error) {
		return a, nil
	}}
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(i)}
	for range 2 {
		if _, err := r.Reconcile(t.Context(), request); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(i), i); err != nil {
		t.Fatal(err)
	}
	if i.Status.AdminStateRequest != "api-adoption-a" || !i.Status.AdminStateManaged || i.Status.AdminStateDigest != interfaceAdminDigest(i, false) || !meta.IsStatusConditionTrue(i.Status.Conditions, "AdminPersistenceReady") || len(a.writes) != 1 {
		t.Fatalf("API lost managed adoption evidence: %+v writes=%d", i.Status, len(a.writes))
	}
	gen, digest := i.Generation, i.Status.AdminStateDigest
	i.Annotations[adminRequestAnnotation] = "api-adoption-b"
	if err := c.Update(t.Context(), i); err != nil {
		t.Fatal(err)
	}
	if i.Generation != gen || i.Status.AdminStateRequest != "api-adoption-a" {
		t.Fatal("annotation update must retain old-generation status until reconciliation")
	}
	if _, err := r.Reconcile(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(i), i); err != nil {
		t.Fatal(err)
	}
	if i.Status.AdminStateRequest != "api-adoption-b" || i.Status.AdminStateDigest == digest || len(a.writes) != 2 {
		t.Fatalf("annotation-only request did not round-trip: %+v", i.Status)
	}
}
