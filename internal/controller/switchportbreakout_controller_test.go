// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	agentclient "github.com/ironcore-dev/sonic-operator/internal/agent/agent_client/client"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

type breakoutTestAgent struct {
	agentclient.SwitchAgentClient
	current, response *agent.PortBreakout
	otherParents      map[string]*agent.PortBreakout
	readErr, writeErr error
	requests          []agent.PortBreakoutRequest
	onRead, onWrite   func()
	closes            int
}

func (a *breakoutTestAgent) GetPortBreakout(_ context.Context, port string) (*agent.PortBreakout, error) {
	if a.onRead != nil {
		a.onRead()
	}
	if port != a.current.Port {
		if other := a.otherParents[port]; other != nil {
			return other, nil
		}
		return nil, errors.New("unknown parent")
	}
	return a.current, a.readErr
}

func (a *breakoutTestAgent) ReconcilePortBreakout(_ context.Context, request *agent.PortBreakoutRequest) (*agent.PortBreakout, error) {
	a.requests = append(a.requests, *request)
	if a.onWrite != nil {
		a.onWrite()
	}
	if a.writeErr == nil {
		a.current = a.response
	}
	return a.response, a.writeErr
}

func (a *breakoutTestAgent) ListInterfaces(context.Context) (*agent.InterfaceList, error) {
	list := &agent.InterfaceList{}
	for _, child := range a.current.Children {
		handle, _ := agent.NativeNameToAbstractName(child.Name)
		list.Items = append(list.Items, agent.Interface{Name: handle, NativeName: child.Name, AdminStatus: agent.DeviceStatus(child.AdminState)})
	}
	return list, nil
}

func (a *breakoutTestAgent) Close() error { a.closes++; return nil }

func breakoutFixture(t *testing.T) (*api.SwitchPortBreakout, *api.Switch, *breakoutTestAgent, client.WithWatch, *SwitchPortBreakoutReconciler) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := api.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	b := &api.SwitchPortBreakout{ObjectMeta: metav1.ObjectMeta{Name: "leaf-port0", UID: "breakout-uid", Generation: 1}, Spec: api.SwitchPortBreakoutSpec{
		SwitchRef: api.SwitchPortBreakoutReference{Name: "leaf"}, Port: "Ethernet0", Mode: "4x25G", ManagementPolicy: api.BreakoutManagementPolicyManage,
	}}
	s := &api.Switch{ObjectMeta: metav1.ObjectMeta{Name: "leaf", UID: "switch-uid"}, Spec: api.SwitchSpec{Management: api.Management{Host: "192.0.2.10", Port: "50051"}}}
	a := &breakoutTestAgent{current: &agent.PortBreakout{Port: "Ethernet0", Mode: "1x100G", ConfigurationVerified: true, SupportedModes: []string{"1x100G", "4x25G"}, Children: []agent.PortBreakoutChild{{Name: "Ethernet0", Lanes: "1,2,3,4", Speed: "100000", AdminState: "up", MTU: "9100"}}}}
	a.response = &agent.PortBreakout{Port: "Ethernet0", Mode: "4x25G", ConfigurationVerified: true, SupportedModes: a.current.SupportedModes, RuntimeVerified: true, PersistenceVerified: true,
		Children: []agent.PortBreakoutChild{
			{Name: "Ethernet0", Lanes: "1", Speed: "25000", AdminState: "up", MTU: "9100"},
			{Name: "Ethernet1", Lanes: "2", Speed: "25000", AdminState: "down", MTU: "9100"},
			{Name: "Ethernet2", Lanes: "3", Speed: "25000", AdminState: "down", MTU: "9100"},
			{Name: "Ethernet3", Lanes: "4", Speed: "25000", AdminState: "down", MTU: "9100"},
		}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(b).WithObjects(b, s).Build()
	r := &SwitchPortBreakoutReconciler{Client: c, APIReader: c, AllowBreakout: true,
		NewAgentClient: func(context.Context, client.Reader, *corev1.LocalObjectReference, string) (agentclient.SwitchAgentClient, error) {
			return a, nil
		},
	}
	return b, s, a, c, r
}

func reconcileBreakout(t *testing.T, r *SwitchPortBreakoutReconciler, b *api.SwitchPortBreakout) error {
	t.Helper()
	_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(b)})
	return err
}

func getBreakout(t *testing.T, c client.Client, b *api.SwitchPortBreakout) *api.SwitchPortBreakout {
	t.Helper()
	got := &api.SwitchPortBreakout{}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(b), got); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestSwitchPortBreakoutGates(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"default policy", "observe", "manager observe", "manager breakout", "manage", "up", "invalid admin", "invalid mode", "invalid port", "missing reader", "missing UID", "implicit endpoint", "unsupported client"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b, s, a, c, r := breakoutFixture(t)
			switch name {
			case "default policy":
				b.Spec.ManagementPolicy = ""
			case "observe":
				b.Spec.ManagementPolicy = api.BreakoutManagementPolicyObserve
			case "manager observe":
				r.ObserveOnly = true
			case "manager breakout":
				r.AllowBreakout = false
			case "up":
				b.Spec.ChildAdminState = api.AdminStateUp
				for i := range a.response.Children {
					a.response.Children[i].AdminState = "up"
				}
			case "invalid admin":
				b.Spec.ChildAdminState = api.AdminStateUnknown
			case "invalid mode":
				b.Spec.Mode = "4x99G"
			case "invalid port":
				b.Spec.Port = "Ethernet00"
			case "missing reader":
				r.APIReader = nil
			case "missing UID":
				b.UID = ""
			case "implicit endpoint":
				s.Spec.Management = api.Management{}
				if err := c.Update(t.Context(), s); err != nil {
					t.Fatal(err)
				}
			case "unsupported client":
				r.NewAgentClient = func(context.Context, client.Reader, *corev1.LocalObjectReference, string) (agentclient.SwitchAgentClient, error) {
					return &vlanTestAgent{}, nil
				}
			}
			if err := c.Update(t.Context(), b); err != nil {
				t.Fatal(err)
			}
			for range 3 {
				_ = reconcileBreakout(t, r, b)
			}
			want := name == "manage" || name == "up"
			if (len(a.requests) > 0) != want {
				t.Fatalf("unexpected writes: %+v", a.requests)
			}
			if want {
				state := "down"
				if name == "up" {
					state = "up"
				}
				if a.requests[0].ChildAdminState != state {
					t.Fatalf("state: %+v", a.requests[0])
				}
			}
		})
	}
}

func TestSwitchPortBreakoutSplitMergePreservesIntent(t *testing.T) {
	t.Parallel()
	b, s, a, c, r := breakoutFixture(t)
	before := *a.current
	parent := breakoutInventory(s, "Ethernet0", api.AdminStateUp)
	if err := c.Create(t.Context(), parent); err != nil {
		t.Fatal(err)
	}
	originalSpec := parent.Spec
	if err := reconcileBreakout(t, r, b); err != nil {
		t.Fatal(err)
	}
	got := getBreakout(t, c, b)
	if len(a.requests) != 0 || got.Annotations[breakoutTargetAnnotation] == "" || len(got.Finalizers) != 0 {
		t.Fatalf("unsafe preparation: %+v", got)
	}
	if err := reconcileBreakout(t, r, b); err != nil {
		t.Fatal(err)
	}
	got = getBreakout(t, c, b)
	if !meta.IsStatusConditionTrue(got.Status.Conditions, "Ready") || len(got.Status.Children) != 4 || !got.Status.RuntimeVerified || !got.Status.PersistenceVerified {
		t.Fatalf("status: %+v", got.Status)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(parent), parent); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(parent.Spec, originalSpec) {
		t.Fatal("split overwrote existing desired Up")
	}
	got.Spec.Mode = "1x100G"
	if err := c.Update(t.Context(), got); err != nil {
		t.Fatal(err)
	}
	before.RuntimeVerified, before.PersistenceVerified = true, true
	a.response = &before
	for range 2 {
		if err := reconcileBreakout(t, r, b); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"Ethernet1", "Ethernet2", "Ethernet3"} {
		child := breakoutInventory(s, name, api.AdminStateDown)
		if err := c.Get(t.Context(), client.ObjectKeyFromObject(child), child); !apierrors.IsNotFound(err) {
			t.Fatalf("stale %s remains: %v", name, err)
		}
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(parent), parent); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(parent.Spec, originalSpec) {
		t.Fatal("merge overwrote existing desired Up")
	}
	requests := len(a.requests)
	if err := c.Delete(t.Context(), got); err != nil {
		t.Fatal(err)
	}
	if err := reconcileBreakout(t, r, b); err != nil {
		t.Fatal(err)
	}
	if len(a.requests) != requests {
		t.Fatal("deletion mutated hardware")
	}
}

func breakoutInventory(s *api.Switch, native string, state api.AdminState) *api.SwitchInterface {
	handle, _ := agent.NativeNameToAbstractName(native)
	return &api.SwitchInterface{ObjectMeta: metav1.ObjectMeta{Name: s.Name + "-" + handle, UID: types.UID("uid-" + native), OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(s, api.GroupVersion.WithKind("Switch"))}}, Spec: api.SwitchInterfaceSpec{SwitchRef: &corev1.LocalObjectReference{Name: s.Name}, Handle: handle, NativeName: native, AdminState: state}}
}

func TestSwitchPortBreakoutConflicts(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"VLAN", "future VLAN child", "admin managed", "annotation false", "user interface", "foreign owner", "duplicate", "endpoint alias", "owned reference"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b, s, a, c, r := breakoutFixture(t)
			iface := breakoutInventory(s, "Ethernet0", api.AdminStateUp)
			switch name {
			case "VLAN", "future VLAN child":
				port := "Ethernet0"
				if name == "future VLAN child" {
					port = "Ethernet1"
				}
				if err := c.Create(t.Context(), &api.SwitchVLAN{ObjectMeta: metav1.ObjectMeta{Name: "vlan"}, Spec: api.SwitchVLANSpec{SwitchRef: api.SwitchVLANReference{Name: s.Name}, VLANID: 100, Members: []api.SwitchVLANMember{{InterfaceName: port, TaggingMode: "tagged"}}}}); err != nil {
					t.Fatal(err)
				}
			case "admin managed", "annotation false":
				value := "true"
				if name == "annotation false" {
					value = "false"
				}
				iface.Annotations = map[string]string{breakoutManageAdminAnnotation: value}
			case "user interface":
				iface.OwnerReferences = nil
			case "foreign owner":
				iface.OwnerReferences[0].UID = "another-switch"
			case "duplicate", "endpoint alias":
				other := b.DeepCopy()
				other.Name, other.UID, other.ResourceVersion = "other", "other-uid", ""
				if name == "endpoint alias" {
					alias := s.DeepCopy()
					alias.Name, alias.UID, alias.ResourceVersion = "alias", "alias-uid", ""
					if err := c.Create(t.Context(), alias); err != nil {
						t.Fatal(err)
					}
					other.Spec.SwitchRef.Name = alias.Name
				}
				if err := c.Create(t.Context(), other); err != nil {
					t.Fatal(err)
				}
			case "owned reference":
				dependent := breakoutInventory(s, "Ethernet4", api.AdminStateUp)
				dependent.OwnerReferences = []metav1.OwnerReference{*metav1.NewControllerRef(iface, api.GroupVersion.WithKind("SwitchInterface"))}
				if err := c.Create(t.Context(), dependent); err != nil {
					t.Fatal(err)
				}
			}
			if err := c.Create(t.Context(), iface); err != nil {
				t.Fatal(err)
			}
			for range 3 {
				if err := reconcileBreakout(t, r, b); err == nil {
					t.Fatal("conflict was not reported")
				}
			}
			if len(a.requests) != 0 {
				t.Fatal("conflicting CR allowed a hardware command")
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(iface), iface); err != nil {
				t.Fatal("conflict removed interface", err)
			}
		})
	}
}

func TestSwitchPortBreakoutStaleRequest(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"spec", "UID", "endpoint", "switch UID", "delete", "binding", "VLAN during read", "post-write spec", "post-write admin"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b, s, a, c, r := breakoutFixture(t)
			if err := reconcileBreakout(t, r, b); err != nil {
				t.Fatal(err)
			}
			mutate := func() {
				a.onRead, a.onWrite = nil, nil
				got := getBreakout(t, c, b)
				switch name {
				case "spec", "post-write spec":
					got.Spec.Mode = "1x100G"
				case "UID":
					got.UID = "replacement"
				case "binding":
					delete(got.Annotations, breakoutTargetAnnotation)
				case "delete":
					if err := c.Delete(t.Context(), got); err != nil {
						t.Fatal(err)
					}
					return
				case "endpoint", "switch UID":
					if name == "endpoint" {
						s.Spec.Management.Host = "192.0.2.20"
					} else {
						s.UID = "replacement"
					}
					if err := c.Update(t.Context(), s); err != nil {
						t.Fatal(err)
					}
					return
				case "VLAN during read":
					if err := c.Create(t.Context(), &api.SwitchVLAN{ObjectMeta: metav1.ObjectMeta{Name: "vlan"}, Spec: api.SwitchVLANSpec{SwitchRef: api.SwitchVLANReference{Name: s.Name}, VLANID: 100, Members: []api.SwitchVLANMember{{InterfaceName: "Ethernet0", TaggingMode: "tagged"}}}}); err != nil {
						t.Fatal(err)
					}
					return
				case "post-write admin":
					i := breakoutInventory(s, "Ethernet0", api.AdminStateUp)
					i.Annotations = map[string]string{breakoutManageAdminAnnotation: "true"}
					if err := c.Create(t.Context(), i); err != nil {
						t.Fatal(err)
					}
					return
				}
				if err := c.Update(t.Context(), got); err != nil {
					t.Fatal(err)
				}
			}
			postWrite := name == "post-write spec" || name == "post-write admin"
			if postWrite {
				a.onWrite = mutate
			} else {
				a.onRead = mutate
			}
			if err := reconcileBreakout(t, r, b); err == nil {
				t.Fatal("stale request was not rejected")
			}
			want := 0
			if postWrite {
				want = 1
			}
			if len(a.requests) != want {
				t.Fatalf("requests: %+v", a.requests)
			}
			list := &api.SwitchInterfaceList{}
			if err := c.List(t.Context(), list); err != nil {
				t.Fatal(err)
			}
			for _, i := range list.Items {
				if i.Spec.NativeName != "Ethernet0" {
					t.Fatal("stale request created inventory")
				}
			}
		})
	}
}

func TestSwitchPortBreakoutUnconfirmedDoesNotPrune(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"read failure", "save failure", "wrong mode", "wrong parent", "empty children", "overlapping lanes", "runtime", "persistence", "pending"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b, s, a, c, r := breakoutFixture(t)
			// Begin from a split layout and request a merge so there are stale children.
			a.current, a.response = a.response, a.current
			a.response.RuntimeVerified, a.response.PersistenceVerified = true, true
			b.Spec.Mode = "1x100G"
			if err := c.Update(t.Context(), b); err != nil {
				t.Fatal(err)
			}
			for _, child := range a.current.Children {
				if err := c.Create(t.Context(), breakoutInventory(s, child.Name, api.AdminStateDown)); err != nil {
					t.Fatal(err)
				}
			}
			if err := reconcileBreakout(t, r, b); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "read failure":
				a.readErr = errors.New("offline")
			case "save failure":
				a.writeErr = errors.New("save failed")
			case "wrong mode":
				a.response.Mode = "2x50G"
			case "wrong parent":
				a.response.Port = "Ethernet4"
			case "empty children":
				a.response.Children = nil
			case "overlapping lanes":
				a.response.Children = append(a.response.Children, agent.PortBreakoutChild{Name: "Ethernet1", Lanes: "1", Speed: "25000", AdminState: "down"})
			case "runtime":
				a.response.RuntimeVerified = false
			case "persistence":
				a.response.PersistenceVerified = false
			case "pending":
				a.response.Pending = true
			}
			if err := reconcileBreakout(t, r, b); err == nil {
				t.Fatal("unconfirmed state accepted")
			}
			list := &api.SwitchInterfaceList{}
			if err := c.List(t.Context(), list); err != nil {
				t.Fatal(err)
			}
			if len(list.Items) != 4 {
				t.Fatal("unconfirmed operation pruned inventory")
			}
			got := getBreakout(t, c, b)
			if meta.IsStatusConditionTrue(got.Status.Conditions, "Ready") || len(got.Status.PreviousChildren) != 4 {
				t.Fatalf("unsafe status: %+v", got.Status)
			}
		})
	}
}

func TestSwitchPortBreakoutCleanupScope(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"exact generated", "user", "different UID", "annotation", "not previously seen", "still live", "edited during delete"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b, s, a, c, r := breakoutFixture(t)
			i := breakoutInventory(s, "Ethernet1", api.AdminStateDown)
			previous := []api.SwitchPortBreakoutChild{{Name: "Ethernet1", Lanes: "2"}}
			switch name {
			case "user":
				i.OwnerReferences = nil
			case "different UID":
				i.OwnerReferences[0].UID = "old-switch"
			case "annotation":
				i.Annotations = map[string]string{breakoutManageAdminAnnotation: "false"}
			case "not previously seen":
				previous = nil
			case "still live":
				a.current = a.response
			}
			if err := c.Create(t.Context(), i); err != nil {
				t.Fatal(err)
			}
			if err := c.Create(t.Context(), breakoutInventory(s, "Ethernet0", api.AdminStateUp)); err != nil {
				t.Fatal(err)
			}
			if err := observeBreakout(b, a.current); err != nil {
				t.Fatal(err)
			}
			// Cleanup itself must protect user CRs even when called after a successful
			// operation; full preflight rejects them before reaching this path.
			if name == "edited during delete" {
				r.Client = interceptor.NewClient(c, interceptor.Funcs{Delete: func(ctx context.Context, cli client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
					live := &api.SwitchInterface{}
					if err := cli.Get(ctx, client.ObjectKeyFromObject(obj), live); err != nil {
						return err
					}
					live.Annotations = map[string]string{breakoutManageAdminAnnotation: "true"}
					if err := cli.Update(ctx, live); err != nil {
						return err
					}
					return cli.Delete(ctx, obj, opts...)
				}})
			}
			err := r.reconcileBreakoutInventory(t.Context(), b, s, a, a, previous)
			if name == "edited during delete" {
				if err == nil {
					t.Fatal("concurrent edit bypassed delete preconditions")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			err = c.Get(t.Context(), client.ObjectKeyFromObject(i), i)
			if name == "exact generated" {
				if !apierrors.IsNotFound(err) {
					t.Fatalf("not removed: %v", err)
				}
			} else if err != nil {
				t.Fatalf("protected inventory removed: %v", err)
			}
		})
	}
}

func TestSwitchPortBreakoutBindingSurvivesStatusFailure(t *testing.T) {
	t.Parallel()
	b, s, a, c, r := breakoutFixture(t)
	r.Client = interceptor.NewClient(c, interceptor.Funcs{SubResourcePatch: func(context.Context, client.Client, string, client.Object, client.Patch, ...client.SubResourcePatchOption) error {
		return errors.New("status unavailable")
	}})
	if err := reconcileBreakout(t, r, b); err == nil {
		t.Fatal("status failure hidden")
	}
	got := getBreakout(t, c, b)
	if got.Annotations[breakoutTargetAnnotation] == "" || len(a.requests) != 0 {
		t.Fatal("target was not durably bound before writes")
	}
	r.Client = c
	s.Spec.Management.Host = "192.0.2.22"
	if err := c.Update(t.Context(), s); err != nil {
		t.Fatal(err)
	}
	if err := reconcileBreakout(t, r, b); err == nil {
		t.Fatal("target changed despite metadata binding")
	}
	if len(a.requests) != 0 {
		t.Fatal("wrote to replacement target")
	}
}

func TestSwitchPortBreakoutRestartAfterSaveFailure(t *testing.T) {
	t.Parallel()
	b, s, a, c, r := breakoutFixture(t)
	a.current, a.response = a.response, a.current
	a.response.RuntimeVerified, a.response.PersistenceVerified = true, true
	b.Spec.Mode = "1x100G"
	if err := c.Update(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	for _, child := range a.current.Children {
		if err := c.Create(t.Context(), breakoutInventory(s, child.Name, api.AdminStateDown)); err != nil {
			t.Fatal(err)
		}
	}
	if err := reconcileBreakout(t, r, b); err != nil {
		t.Fatal(err)
	}
	a.writeErr = errors.New("save failed after runtime changed")
	a.onWrite = func() { a.current = a.response }
	if err := reconcileBreakout(t, r, b); err == nil {
		t.Fatal("save failure hidden")
	}
	a.writeErr, a.onWrite = nil, nil
	restarted := *r
	if err := reconcileBreakout(t, &restarted, b); err != nil {
		t.Fatal(err)
	}
	i := breakoutInventory(s, "Ethernet1", api.AdminStateDown)
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(i), i); !apierrors.IsNotFound(err) {
		t.Fatal("lost pre-operation cleanup scope on restart", err)
	}
	if len(a.requests) != 2 {
		t.Fatalf("recovery should request agent verification/save: %+v", a.requests)
	}
}

func TestSwitchPortBreakoutDefaultFactoryRequiresTLS(t *testing.T) {
	b, _, a, _, r := breakoutFixture(t)
	for _, key := range []string{"SONIC_AGENT_TLS_CERT_FILE", "SONIC_AGENT_TLS_KEY_FILE", "SONIC_AGENT_TLS_CA_FILE"} {
		t.Setenv(key, "")
	}
	r.NewAgentClient = nil
	if err := reconcileBreakout(t, r, b); err == nil {
		t.Fatal("default factory accepted missing mTLS configuration")
	}
	if len(a.requests) != 0 {
		t.Fatal("TLS failure allowed writes")
	}
}

func TestSwitchPortBreakoutCompetingLanes(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"overlap", "unknown", "disjoint"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b, _, a, c, r := breakoutFixture(t)
			other := b.DeepCopy()
			other.Name, other.UID, other.ResourceVersion, other.Spec.Port = "other", "other-uid", "", "Ethernet4"
			if err := c.Create(t.Context(), other); err != nil {
				t.Fatal(err)
			}
			lanes := "4,5,6,7"
			if name == "disjoint" {
				lanes = "5,6,7,8"
			}
			if name != "unknown" {
				a.otherParents = map[string]*agent.PortBreakout{"Ethernet4": {Port: "Ethernet4", Mode: "1x100G", Children: []agent.PortBreakoutChild{{Name: "Ethernet4", Lanes: lanes, Speed: "100000", AdminState: "down"}}}}
			}
			for range 2 {
				_ = reconcileBreakout(t, r, b)
			}
			if (len(a.requests) == 1) != (name == "disjoint") {
				t.Fatalf("unexpected writes: %+v", a.requests)
			}
		})
	}
}

func TestSwitchPortBreakoutDoesNotTrustDisappearingLanes(t *testing.T) {
	t.Parallel()
	b, _, a, _, r := breakoutFixture(t)
	if err := reconcileBreakout(t, r, b); err != nil {
		t.Fatal(err)
	}
	a.response.Children = a.response.Children[:1]
	if err := reconcileBreakout(t, r, b); err == nil {
		t.Fatal("accepted successful response that lost most parent lanes")
	}
}

func TestSwitchPortBreakoutRejectsWrongNewChildAdmin(t *testing.T) {
	t.Parallel()
	b, _, a, _, r := breakoutFixture(t)
	if err := reconcileBreakout(t, r, b); err != nil {
		t.Fatal(err)
	}
	a.response.Children[1].AdminState = "up"
	if err := reconcileBreakout(t, r, b); err == nil {
		t.Fatal("accepted wrong admin state on newly created child")
	}
}

func TestSwitchPortBreakoutExistingNativeNameWins(t *testing.T) {
	t.Parallel()
	b, s, _, c, r := breakoutFixture(t)
	i := breakoutInventory(s, "Ethernet0", api.AdminStateUp)
	i.Name, i.Spec.Handle = "leaf-previous-handle", "previous-handle"
	if err := c.Create(t.Context(), i); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := reconcileBreakout(t, r, b); err != nil {
			t.Fatal(err)
		}
	}
	got := &api.SwitchInterface{}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(i), got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Spec, i.Spec) {
		t.Fatal("overwrote existing native interface intent")
	}
	duplicate := breakoutInventory(s, "Ethernet0", api.AdminStateDown)
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(duplicate), duplicate); !apierrors.IsNotFound(err) {
		t.Fatalf("duplicated existing native interface: %v", err)
	}
}

func TestSwitchPortBreakoutMatchingStillConfirmsPersistence(t *testing.T) {
	t.Parallel()
	b, _, a, c, r := breakoutFixture(t)
	b.Spec.Mode = a.current.Mode
	if err := c.Update(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	confirmed := *a.current
	confirmed.RuntimeVerified, confirmed.PersistenceVerified = true, true
	a.response = &confirmed
	for range 2 {
		if err := reconcileBreakout(t, r, b); err != nil {
			t.Fatal(err)
		}
	}
	if len(a.requests) != 1 || !meta.IsStatusConditionTrue(getBreakout(t, c, b).Status.Conditions, "Ready") {
		t.Fatal("matching CONFIG_DB bypassed persistence confirmation")
	}
}

func TestSwitchPortBreakoutIndependentConditions(t *testing.T) {
	t.Parallel()
	b, _, a, c, r := breakoutFixture(t)
	b.Spec.Mode, b.Spec.ManagementPolicy = a.current.Mode, api.BreakoutManagementPolicyObserve
	if err := c.Update(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	a.current.RuntimeVerified = true
	if err := reconcileBreakout(t, r, b); err != nil {
		t.Fatal(err)
	}
	got := getBreakout(t, c, b)
	if !meta.IsStatusConditionTrue(got.Status.Conditions, "ConfigurationReady") || !meta.IsStatusConditionTrue(got.Status.Conditions, "RuntimeReady") || meta.IsStatusConditionTrue(got.Status.Conditions, "PersistenceReady") || meta.IsStatusConditionTrue(got.Status.Conditions, "Ready") {
		t.Fatalf("conditions conflate configuration/runtime/persistence: %+v", got.Status)
	}
	for _, cond := range got.Status.Conditions {
		if cond.ObservedGeneration != b.Generation {
			t.Fatal("condition has wrong generation")
		}
	}
	if len(a.requests) != 0 {
		t.Fatal("observation attempted to save")
	}
}

func TestSwitchPortBreakoutUnverifiedLayout(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"missing child", "wrong speed", "empty children"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b, _, a, c, r := breakoutFixture(t)
			b.Spec.ManagementPolicy = api.BreakoutManagementPolicyObserve
			if err := c.Update(t.Context(), b); err != nil {
				t.Fatal(err)
			}
			a.current = a.response
			a.current.ConfigurationVerified = false
			a.current.Message = "CONFIG_DB layout mismatch: " + name
			switch name {
			case "missing child":
				a.current.Children = a.current.Children[:3]
			case "wrong speed":
				a.current.Children[1].Speed = "10000"
			case "empty children":
				a.current.Children = nil
			}
			_ = reconcileBreakout(t, r, b)
			got := getBreakout(t, c, b)
			if got.Status.ConfigurationVerified || meta.IsStatusConditionTrue(got.Status.Conditions, "ConfigurationReady") || meta.IsStatusConditionTrue(got.Status.Conditions, "Ready") {
				t.Errorf("matching mode falsely confirmed layout: %+v", got.Status)
			}
			if !strings.Contains(got.Status.Message, a.current.Message) {
				t.Errorf("lost layout diagnostic: %q", got.Status.Message)
			}
			condition := meta.FindStatusCondition(got.Status.Conditions, "ConfigurationReady")
			if condition == nil || !strings.Contains(condition.Message, a.current.Message) {
				t.Errorf("condition lost layout diagnostic: %+v", condition)
			}
			if len(a.requests) != 0 {
				t.Fatal("observation mutated hardware")
			}
		})
	}
}

func TestObserveBreakoutConfigurationRequiresProofAndMode(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name               string
		verified, matching bool
	}{
		{name: "verified matching", verified: true, matching: true},
		{name: "verified different mode", verified: true},
		{name: "unverified matching", matching: true},
		{name: "unverified different mode"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b, _, a, _, _ := breakoutFixture(t)
			snapshot := a.response
			snapshot.ConfigurationVerified = tc.verified
			if !tc.matching {
				snapshot.Mode = "1x100G"
			}
			if err := observeBreakout(b, snapshot); err != nil {
				t.Fatal(err)
			}
			if b.Status.ConfigurationVerified != (tc.verified && tc.matching) {
				t.Fatalf("configuration verification: %+v", b.Status)
			}
		})
	}
}
