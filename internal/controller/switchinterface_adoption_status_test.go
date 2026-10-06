// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	agentclient "github.com/ironcore-dev/sonic-operator/internal/agent/agent_client/client"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const adminRequestAnnotation = "sonic.networking.metal.ironcore.dev/admin-state-request"

func adminStatusWire(t *testing.T, i *api.SwitchInterface) map[string]any {
	t.Helper()
	data, err := json.Marshal(i.Status)
	if err != nil {
		t.Fatal(err)
	}
	var status map[string]any
	if err := json.Unmarshal(data, &status); err != nil {
		t.Fatal(err)
	}
	return status
}

func TestAdminAdoptionAnnotationFreshness(t *testing.T) {
	s, i, a, scheme := adoptionFixture(t)
	i.Generation = 7
	i.Annotations = map[string]string{manageAdminAnnotation: "true", adminRequestAnnotation: "adoption-a"}
	a.iface.AdminStatus = agent.StatusDown // already matching: ensure must still run
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(i).WithObjects(s, i).Build()
	r := &SwitchInterfaceReconciler{Client: c, Scheme: scheme, NewAgentClient: func(context.Context, client.Reader, *corev1.LocalObjectReference, string) (agentclient.SwitchAgentClient, error) {
		return a, nil
	}}
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(i)}
	if _, err := r.Reconcile(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(i), i); err != nil {
		t.Fatal(err)
	}
	status := adminStatusWire(t, i)
	if status["adminStateRequest"] != "adoption-a" || status["adminStateManaged"] != true || status["adminStateDigest"] == nil || status["adminStateDigest"] == "" || len(a.writes) != 1 {
		t.Fatalf("matching adoption lacks request-qualified ensure evidence: %+v writes=%d", status, len(a.writes))
	}
	digest := status["adminStateDigest"]
	i.Annotations[adminRequestAnnotation] = "adoption-b"
	if err := c.Update(t.Context(), i); err != nil {
		t.Fatal(err)
	}
	if !meta.IsStatusConditionTrue(i.Status.Conditions, "AdminPersistenceReady") || adminStatusWire(t, i)["adminStateRequest"] == "adoption-b" {
		t.Fatal("fixture must retain old Ready but not acknowledge new token")
	}
	if _, err := r.Reconcile(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(i), i); err != nil {
		t.Fatal(err)
	}
	status = adminStatusWire(t, i)
	if status["adminStateRequest"] != "adoption-b" || status["adminStateDigest"] == digest || i.Generation != 7 || len(a.writes) != 2 || !meta.IsStatusConditionTrue(i.Status.Conditions, "AdminPersistenceReady") {
		t.Fatalf("annotation-only adoption did not refresh ensure evidence: %+v", status)
	}
	r.ObserveOnly = true
	i.Annotations[adminRequestAnnotation] = "adoption-c"
	if err := c.Update(t.Context(), i); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(i), i); err != nil {
		t.Fatal(err)
	}
	status = adminStatusWire(t, i)
	if status["adminStateRequest"] != "adoption-c" || status["adminStateManaged"] == true || meta.IsStatusConditionTrue(i.Status.Conditions, "AdminPersistenceReady") || len(a.writes) != 2 {
		t.Fatalf("read-only observation claimed managed adoption: %+v", status)
	}
	r.ObserveOnly = false
	a.writeErr = errors.New("save failed")
	i.Annotations[adminRequestAnnotation] = "adoption-d"
	if err := c.Update(t.Context(), i); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(t.Context(), request); err == nil {
		t.Fatal("failed save accepted")
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(i), i); err != nil {
		t.Fatal(err)
	}
	status = adminStatusWire(t, i)
	if status["adminStateRequest"] != "adoption-d" || status["adminStateManaged"] != true || meta.IsStatusConditionTrue(i.Status.Conditions, "AdminPersistenceReady") || len(a.writes) != 3 {
		t.Fatalf("new request inherited stale save success: %+v", status)
	}
	// Future drift must also go through ensure, not reuse baseline saved evidence.
	a.writeErr = nil
	a.iface.AdminStatus = agent.StatusUp
	if _, err := r.Reconcile(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(i), i); err != nil {
		t.Fatal(err)
	}
	if !meta.IsStatusConditionTrue(i.Status.Conditions, "AdminPersistenceReady") || len(a.writes) != 4 || a.writes[3].AdminStatus != agent.StatusDown {
		t.Fatal("future drift bypassed persistence-qualified ensure")
	}
}

func TestAdminAdoptionConcurrentAnnotationCannotPublishOldEvidence(t *testing.T) {
	s, i, a, scheme := adoptionFixture(t)
	i.Annotations = map[string]string{manageAdminAnnotation: "true", adminRequestAnnotation: "old-request"}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(i).WithObjects(s, i).Build()
	r := &SwitchInterfaceReconciler{Client: c, Scheme: scheme, NewAgentClient: func(context.Context, client.Reader, *corev1.LocalObjectReference, string) (agentclient.SwitchAgentClient, error) {
		fresh := &api.SwitchInterface{}
		if err := c.Get(t.Context(), client.ObjectKeyFromObject(i), fresh); err != nil {
			t.Fatal(err)
		}
		fresh.Annotations[adminRequestAnnotation] = "new-request"
		if err := c.Update(t.Context(), fresh); err != nil {
			t.Fatal(err)
		}
		return a, nil
	}}
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(i)}); err == nil {
		t.Fatal("stale status patch was accepted")
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(i), i); err != nil {
		t.Fatal(err)
	}
	if meta.IsStatusConditionTrue(i.Status.Conditions, "AdminPersistenceReady") || adminStatusWire(t, i)["adminStateRequest"] == "old-request" {
		t.Fatal("old request evidence published across metadata edit")
	}
}
