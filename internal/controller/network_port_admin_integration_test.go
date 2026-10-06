//go:build integration

// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	agentclient "github.com/ironcore-dev/sonic-operator/internal/agent/agent_client/client"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// Both controllers write the same API object. Exercise real status-subresource
// pruning, optimistic concurrency and independent finalizer ownership.
func TestNetworkPortAdminStatusAndRecoveryAPIRoundTrip(t *testing.T) {
	env := &envtest.Environment{BinaryAssetsDirectory: getFirstFoundEnvTestBinaryDir(), ErrorIfCRDPathMissing: true,
		CRDDirectoryPaths: []string{
			filepath.Join("..", "..", "config", "crd", "bases", "sonic.networking.metal.ironcore.dev_switchinterfaces.yaml"),
			filepath.Join("..", "..", "config", "crd", "bases", "sonic.networking.metal.ironcore.dev_switches.yaml"),
		},
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
	sw, i, admin, scheme := adoptionFixture(t)
	sw.UID = ""
	sw.Spec.Management = api.Management{Host: "192.0.2.10", Port: "50051"}
	i.OwnerReferences = nil
	i.Annotations = map[string]string{manageAdminAnnotation: "true", adminRequestAnnotation: "combined-a"}
	speed, mtu := uint32(1000), uint32(9100)
	i.Spec.Speed, i.Spec.MTU, i.Spec.ManagementPolicy = &speed, &mtu, api.NetworkManagementPolicyManage
	admin.iface.AdminStatus = agent.StatusDown
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	for _, obj := range []client.Object{sw, i} {
		if err := c.Create(t.Context(), obj); err != nil {
			t.Fatal(err)
		}
	}
	a := &SwitchInterfaceReconciler{Client: c, Scheme: scheme, NewAgentClient: func(context.Context, client.Reader, *corev1.LocalObjectReference, string) (agentclient.SwitchAgentClient, error) {
		return admin, nil
	}}
	native := &networkTestAgent{current: &agent.NetworkResult{Exists: true, ConfigurationVerified: true, RuntimeVerified: true, Observed: json.RawMessage(`{"speed":1000}`)}}
	n := &NetworkReconciler{Client: c, APIReader: c, Kind: "Port", AllowNetworkConfig: true, NewAgentClient: func(context.Context, client.Reader, *corev1.LocalObjectReference, string) (agentclient.SwitchAgentClient, error) {
		return native, nil
	}}
	request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(i)}
	read := func() {
		t.Helper()
		if err := c.Get(t.Context(), request.NamespacedName, i); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if _, err := a.Reconcile(t.Context(), request); err != nil {
			t.Fatal(err)
		}
		if _, err := n.Reconcile(t.Context(), request); err != nil {
			t.Fatal(err)
		}
	}
	read()
	if len(native.requests) != 1 || len(admin.writes) != 1 || !meta.IsStatusConditionTrue(i.Status.Conditions, "AdminPersistenceReady") || !meta.IsStatusConditionTrue(i.Status.PortConfiguration.Conditions, "Ready") || i.Status.AdminStateRequest != "combined-a" || i.Status.AdminStateDigest != interfaceAdminDigest(i, false) {
		t.Fatalf("combined API lost independent proof: %+v", i.Status)
	}
	if !slices.Contains(i.Finalizers, api.SwitchFinalizer) || !slices.Contains(i.Finalizers, networkRecoveryFinalizer) {
		t.Fatalf("missing independent finalizers: %v", i.Finalizers)
	}
	portStatus := i.Status.PortConfiguration.DeepCopy()
	i.Annotations[adminRequestAnnotation] = "combined-b"
	if err := c.Update(t.Context(), i); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Reconcile(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	read()
	if i.Status.AdminStateRequest != "combined-b" || !reflect.DeepEqual(portStatus, &i.Status.PortConfiguration) {
		t.Fatal("admin nonce refresh replaced typed port status")
	}
	// Force an admin status/nonce update in the network observation gap. A stale
	// network patch must conflict rather than replace the new admin evidence.
	native.current.RuntimeVerified = false
	native.onRead = func() {
		read()
		i.Annotations[adminRequestAnnotation] = "combined-c"
		if err := c.Update(t.Context(), i); err != nil {
			t.Fatal(err)
		}
		if _, err := a.Reconcile(t.Context(), request); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := n.Reconcile(t.Context(), request); !apierrors.IsConflict(err) {
		t.Fatalf("stale network status must conflict: %v", err)
	}
	native.onRead = nil
	read()
	if i.Status.AdminStateRequest != "combined-c" || !meta.IsStatusConditionTrue(i.Status.Conditions, "AdminPersistenceReady") || !i.Status.PortConfiguration.RuntimeVerified {
		t.Fatalf("stale network patch overwrote current status: %+v", i.Status)
	}
	// Removing a mutable field cannot replace the durable recovery request.
	i.Spec.MTU = nil
	if err := c.Update(t.Context(), i); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(t.Context(), i); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Reconcile(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	native.recoverErr = errors.New("typed port save pending")
	if _, err := n.Reconcile(t.Context(), request); err == nil {
		t.Fatal("pending typed port recovery allowed deletion")
	}
	read()
	if slices.Contains(i.Finalizers, api.SwitchFinalizer) || !slices.Contains(i.Finalizers, networkRecoveryFinalizer) || i.Status.AdminStateRequest != "combined-c" || !meta.IsStatusConditionTrue(i.Status.Conditions, "AdminPersistenceReady") {
		t.Fatalf("deletion/recovery crossed controller ownership: %+v", i)
	}
	native.recoverErr = nil
	if _, err := n.Reconcile(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(native.recoveries[len(native.recoveries)-1], native.requests[0]) || len(native.requests) != 1 {
		t.Fatal("deletion changed the durable request or issued a new Ensure")
	}
	if err := c.Get(t.Context(), request.NamespacedName, i); !apierrors.IsNotFound(err) {
		t.Fatalf("completed recovery did not release deletion: %v", err)
	}
}
