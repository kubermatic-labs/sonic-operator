// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/go-logr/logr"
	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	agentclient "github.com/ironcore-dev/sonic-operator/internal/agent/agent_client/client"
	agenterrors "github.com/ironcore-dev/sonic-operator/internal/agent/errors"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const manageAdminAnnotation = "sonic.networking.metal.ironcore.dev/manage-admin-state"

type adoptionAgent struct {
	agentclient.SwitchAgentClient
	iface                                    *agent.Interface
	device                                   *agent.SwitchDevice
	interfaces                               *agent.InterfaceList
	ports                                    *agent.PortList
	neighbor                                 *agent.InterfaceNeighbor
	readErr, writeErr, neighborErr, closeErr error
	writeResponse                            *agent.Interface
	writes                                   []agent.Interface
	aliases, saves, closes                   int
}

func (a *adoptionAgent) GetInterfaceByAbstractName(context.Context, *agent.Interface) (*agent.Interface, error) {
	return a.iface, a.readErr
}
func (a *adoptionAgent) GetInterfaceNeighbor(context.Context, *agent.Interface) (*agent.InterfaceNeighbor, error) {
	return a.neighbor, a.neighborErr
}
func (a *adoptionAgent) SetInterfaceAdminStatus(_ context.Context, i *agent.Interface) (*agent.Interface, error) {
	a.writes = append(a.writes, *i)
	return a.writeResponse, a.writeErr
}
func (a *adoptionAgent) SetInterfaceAliasName(_ context.Context, i *agent.Interface) (*agent.Interface, error) {
	a.aliases++
	return i, nil
}
func (a *adoptionAgent) SaveConfig(context.Context) error { a.saves++; return nil }
func (a *adoptionAgent) Close() error                     { a.closes++; return a.closeErr }
func (a *adoptionAgent) GetDeviceInfo(context.Context) (*agent.SwitchDevice, error) {
	return a.device, a.readErr
}
func (a *adoptionAgent) ListInterfaces(context.Context) (*agent.InterfaceList, error) {
	return a.interfaces, a.readErr
}
func (a *adoptionAgent) ListPorts(context.Context) (*agent.PortList, error) {
	return a.ports, a.readErr
}

func adoptionFixture(t *testing.T) (*api.Switch, *api.SwitchInterface, *adoptionAgent, *runtime.Scheme) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := api.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	s := &api.Switch{ObjectMeta: metav1.ObjectMeta{Name: "leaf", UID: "switch-uid", Finalizers: []string{api.SwitchFinalizer}}, Status: api.SwitchStatus{State: api.SwitchStateReady}}
	i := &api.SwitchInterface{
		ObjectMeta: metav1.ObjectMeta{Name: "leaf-eth0-0", Finalizers: []string{api.SwitchFinalizer}, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(s, api.GroupVersion.WithKind("Switch"))}},
		Spec:       api.SwitchInterfaceSpec{Handle: "eth0-0", NativeName: "Ethernet0", SwitchRef: &corev1.LocalObjectReference{Name: s.Name}, AdminState: api.AdminStateDown},
		Status:     api.SwitchInterfaceStatus{State: api.SwitchInterfaceStateReady},
	}
	iface := agent.Interface{Name: "eth0-0", NativeName: "Ethernet0", AliasName: "customer-uplink", AdminStatus: agent.StatusUp, OperationStatus: agent.StatusUp}
	response := iface
	response.AdminStatus = agent.StatusDown
	a := &adoptionAgent{iface: &iface, device: &agent.SwitchDevice{}, interfaces: &agent.InterfaceList{Items: []agent.Interface{iface}}, ports: &agent.PortList{}, neighbor: &agent.InterfaceNeighbor{}, writeResponse: &response}
	return s, i, a, scheme
}

func TestSafeAdoptionExistingInterface(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		change   func(*api.SwitchInterface)
		conflict bool
	}{
		{name: "preserve user desired state and annotations", change: func(i *api.SwitchInterface) { i.Annotations = map[string]string{manageAdminAnnotation: "true"} }},
		{name: "different native identity", change: func(i *api.SwitchInterface) { i.Spec.NativeName = "Ethernet4" }, conflict: true},
		{name: "different handle", change: func(i *api.SwitchInterface) { i.Spec.Handle = "eth1-0" }, conflict: true},
		{name: "different switch reference", change: func(i *api.SwitchInterface) { i.Spec.SwitchRef.Name = "other" }, conflict: true},
		{name: "missing switch reference", change: func(i *api.SwitchInterface) { i.Spec.SwitchRef = nil }, conflict: true},
		{name: "unowned", change: func(i *api.SwitchInterface) { i.OwnerReferences = nil }, conflict: true},
		{name: "recreated owner", change: func(i *api.SwitchInterface) { i.OwnerReferences[0].UID = "old-uid" }, conflict: true},
		{name: "wrong owner kind", change: func(i *api.SwitchInterface) { i.OwnerReferences[0].Kind = "Other" }, conflict: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, i, a, scheme := adoptionFixture(t)
			tc.change(i)
			before := i.DeepCopy()
			c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s, i).Build()
			r := SwitchReconciler{Client: c, Scheme: scheme}
			err := r.EnsureInterface(t.Context(), logr.Discard(), s, *a.iface)
			if (err != nil) != tc.conflict {
				t.Errorf("EnsureInterface error = %v, want conflict %v", err, tc.conflict)
			}
			got := &api.SwitchInterface{}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(i), got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before.Spec, got.Spec) || !reflect.DeepEqual(before.Annotations, got.Annotations) || !reflect.DeepEqual(before.OwnerReferences, got.OwnerReferences) {
				t.Fatalf("existing interface was modified: %#v", got)
			}
		})
	}
}

func TestSafeAdoptionDiscoveryUnknown(t *testing.T) {
	t.Parallel()
	s, _, a, scheme := adoptionFixture(t)
	a.iface.AdminStatus = agent.StatusUnknown
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s).Build()
	r := SwitchReconciler{Client: c, Scheme: scheme}
	if err := r.EnsureInterface(t.Context(), logr.Discard(), s, *a.iface); err != nil {
		t.Fatal(err)
	}
	i := &api.SwitchInterface{}
	if err := c.Get(t.Context(), client.ObjectKey{Name: "leaf-eth0-0"}, i); err != nil {
		t.Fatal(err)
	}
	if i.Spec.AdminState != api.AdminStateUnknown || i.Spec.NativeName != "Ethernet0" || !metav1.IsControlledBy(i, s) {
		t.Fatalf("unsafe discovered spec/owner: %#v", i)
	}
	if i.Annotations[manageAdminAnnotation] != "" {
		t.Fatal("discovery must not opt in to management")
	}
}

func TestSafeAdoptionAdminGate(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		observe    bool
		annotation string
		desired    api.AdminState
		current    agent.DeviceStatus
		native     string
		writes     int
		wantErr    bool
	}{
		{name: "observe only", observe: true, annotation: "true", desired: api.AdminStateDown, current: agent.StatusUp, native: "Ethernet0"},
		{name: "no opt in", desired: api.AdminStateDown, current: agent.StatusUp, native: "Ethernet0"},
		{name: "opt in must be exact", annotation: "TRUE", desired: api.AdminStateDown, current: agent.StatusUp, native: "Ethernet0"},
		{name: "explicit change", annotation: "true", desired: api.AdminStateDown, current: agent.StatusUp, native: "Ethernet0", writes: 1},
		{name: "explicit enable", annotation: "true", desired: api.AdminStateUp, current: agent.StatusDown, native: "Ethernet0", writes: 1},
		{name: "unchanged", annotation: "true", desired: api.AdminStateUp, current: agent.StatusUp, native: "Ethernet0"},
		{name: "unknown observation", observe: true, desired: api.AdminStateUnknown, current: agent.StatusUnknown, native: "Ethernet0"},
		{name: "unknown current cannot write", annotation: "true", desired: api.AdminStateDown, current: agent.StatusUnknown, native: "Ethernet0", wantErr: true},
		{name: "invalid current cannot write", annotation: "true", desired: api.AdminStateDown, current: "bad", native: "Ethernet0", wantErr: true},
		{name: "unknown desired cannot write", annotation: "true", desired: api.AdminStateUnknown, current: agent.StatusUp, native: "Ethernet0", wantErr: true},
		{name: "empty desired cannot write", annotation: "true", current: agent.StatusUp, native: "Ethernet0", wantErr: true},
		{name: "invalid desired cannot write", annotation: "true", desired: "bad", current: agent.StatusUp, native: "Ethernet0", wantErr: true},
		{name: "identity mismatch", annotation: "true", desired: api.AdminStateDown, current: agent.StatusUp, native: "Ethernet4", wantErr: true},
		{name: "missing discovered identity", annotation: "true", desired: api.AdminStateDown, current: agent.StatusUp, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, i, a, scheme := adoptionFixture(t)
			i.Annotations = map[string]string{manageAdminAnnotation: tc.annotation}
			i.Spec.AdminState = tc.desired
			if tc.desired == api.AdminStateUp {
				a.writeResponse.AdminStatus = agent.StatusUp
			}
			a.iface.AdminStatus, a.iface.NativeName = tc.current, tc.native
			if tc.current == agent.StatusUnknown {
				a.iface.OperationStatus = agent.StatusUnknown
			}
			c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(i).WithObjects(s, i).Build()
			r := SwitchInterfaceReconciler{Client: c, Scheme: scheme, ObserveOnly: tc.observe,
				NewAgentClient: func(context.Context, client.Reader, *corev1.LocalObjectReference, string) (agentclient.SwitchAgentClient, error) {
					return a, nil
				},
			}
			result, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(i)})
			if (err != nil) != tc.wantErr {
				t.Errorf("error = %v, want error %v", err, tc.wantErr)
			}
			if len(a.writes) != tc.writes || a.aliases != 0 || a.saves != 0 {
				t.Errorf("mutations: admin=%v alias=%d save=%d", a.writes, a.aliases, a.saves)
			}
			if len(a.writes) > 0 && (a.writes[0].Name != "Ethernet0" || a.writes[0].AdminStatus != a.writeResponse.AdminStatus) {
				t.Errorf("wrong mutation target: %#v", a.writes[0])
			}
			if a.closes != 1 {
				t.Errorf("Close calls = %d, want 1", a.closes)
			}
			got := &api.SwitchInterface{}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(i), got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(i.Spec, got.Spec) {
				t.Fatal("reconcile changed desired spec")
			}
			if tc.wantErr {
				if got.Status.State == api.SwitchInterfaceStateReady {
					t.Error("failure reported ready")
				}
			} else {
				if result.RequeueAfter != 60*time.Second {
					t.Errorf("RequeueAfter = %v", result.RequeueAfter)
				}
				if got.Status.State != api.SwitchInterfaceStateReady || got.Status.AliasName != "customer-uplink" {
					t.Errorf("unexpected observation: %#v", got.Status)
				}
				if tc.current == agent.StatusUnknown && (got.Status.AdminState != api.AdminStateUnknown || got.Status.OperationalState != api.OperationStateUnknown) {
					t.Errorf("unknown became known: %#v", got.Status)
				}
			}
		})
	}
}

func TestSafeAdoptionInterfaceFailures(t *testing.T) {
	t.Parallel()
	failure := errors.New("agent failure")
	for _, tc := range []struct {
		name   string
		change func(*adoptionAgent)
		writes int
	}{
		{name: "read error", change: func(a *adoptionAgent) { a.readErr = failure }},
		{name: "nil read", change: func(a *adoptionAgent) { a.iface = nil }},
		{name: "read status error", change: func(a *adoptionAgent) { a.iface.Status.Code = 1 }},
		{name: "nil neighbor", change: func(a *adoptionAgent) { a.neighbor = nil }},
		{name: "neighbor error", change: func(a *adoptionAgent) { a.neighborErr = failure }},
		{name: "write error", change: func(a *adoptionAgent) { a.writeErr = failure }, writes: 1},
		{name: "nil write", change: func(a *adoptionAgent) { a.writeResponse = nil }, writes: 1},
		{name: "write status error", change: func(a *adoptionAgent) { a.writeResponse.Status.Code = 1 }, writes: 1},
		{name: "write unconfirmed", change: func(a *adoptionAgent) { a.writeResponse.AdminStatus = agent.StatusUnknown }, writes: 1},
		{name: "write wrong identity", change: func(a *adoptionAgent) { a.writeResponse.NativeName = "Ethernet4" }, writes: 1},
		{name: "close error", change: func(a *adoptionAgent) { a.closeErr = failure }, writes: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, i, a, scheme := adoptionFixture(t)
			i.Annotations = map[string]string{manageAdminAnnotation: "true"}
			tc.change(a)
			c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(i).WithObjects(s, i).Build()
			r := SwitchInterfaceReconciler{Client: c, Scheme: scheme, NewAgentClient: func(context.Context, client.Reader, *corev1.LocalObjectReference, string) (agentclient.SwitchAgentClient, error) {
				return a, nil
			}}
			_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(i)})
			if err == nil {
				t.Error("expected error")
			}
			if (a.readErr != nil || a.writeErr != nil || a.neighborErr != nil || a.closeErr != nil) && !errors.Is(err, failure) {
				t.Errorf("lost original error: %v", err)
			}
			if len(a.writes) != tc.writes || a.aliases != 0 || a.saves != 0 || a.closes != 1 {
				t.Errorf("unexpected calls: %#v", a)
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(i), i); err != nil {
				t.Fatal(err)
			}
			if i.Status.State != api.SwitchInterfaceStateFailed {
				t.Errorf("failure reported %s", i.Status.State)
			}
		})
	}
}

func TestSafeAdoptionSwitchObservation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		change  func(*adoptionAgent)
		wantErr bool
		// unreachable agents keep the Switch Ready and retry without an error
		unreachable bool
		wantPorts   []api.PortStatus
	}{
		{name: "empty inventory clears old ports", change: func(*adoptionAgent) {}},
		{name: "inventory replaces old ports", change: func(a *adoptionAgent) { a.ports.Items = []agent.Port{{Name: "Ethernet0"}} }, wantPorts: []api.PortStatus{{Name: "Ethernet0"}}},
		{name: "partial inventory error", change: func(a *adoptionAgent) {
			a.ports.Items = []agent.Port{{Name: "Ethernet0"}, {Name: "Ethernet4", Status: agent.Status{Code: 1}}}
		}, wantErr: true},
		{name: "nil device", change: func(a *adoptionAgent) { a.device = nil }, wantErr: true},
		{name: "nil interfaces", change: func(a *adoptionAgent) { a.interfaces = nil }, wantErr: true},
		{name: "nil ports", change: func(a *adoptionAgent) { a.ports = nil }, wantErr: true},
		{name: "device status error", change: func(a *adoptionAgent) { a.device.Status.Code = 1 }, wantErr: true},
		{name: "interface status error", change: func(a *adoptionAgent) { a.interfaces.Status.Code = 1 }, wantErr: true},
		{name: "port status error", change: func(a *adoptionAgent) { a.ports.Status.Code = 1 }, wantErr: true},
		{name: "read error", change: func(a *adoptionAgent) { a.readErr = errors.New("read failed") }, unreachable: true},
		{name: "close error", change: func(a *adoptionAgent) { a.closeErr = errors.New("close failed") }, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, i, a, scheme := adoptionFixture(t)
			s.Status.Ports = []api.PortStatus{{Name: "stale"}}
			tc.change(a)
			c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(s).WithObjects(s, i).Build()
			r := SwitchReconciler{Client: c, Scheme: scheme, NewAgentClient: func(context.Context, *api.Switch) (agentclient.SwitchAgentClient, error) { return a, nil }}
			result, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(s)})
			if (err != nil) != tc.wantErr {
				t.Errorf("error = %v, want error %v", err, tc.wantErr)
			}
			if a.closes != 1 || a.aliases != 0 || a.saves != 0 || len(a.writes) != 0 {
				t.Errorf("unexpected agent calls: %#v", a)
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(s), s); err != nil {
				t.Fatal(err)
			}
			wantPorts := tc.wantPorts
			if tc.wantErr || tc.unreachable {
				wantPorts = []api.PortStatus{{Name: "stale"}}
			}
			if !reflect.DeepEqual(s.Status.Ports, wantPorts) {
				t.Errorf("inventory = %v, want %v", s.Status.Ports, wantPorts)
			}
			if tc.unreachable {
				if s.Status.State != api.SwitchStateReady || result.RequeueAfter != time.Minute {
					t.Errorf("unreachable agent: %#v, %#v", s.Status, result)
				}
			} else if tc.wantErr {
				if s.Status.State != api.SwitchStateFailed {
					t.Errorf("failure reported %s", s.Status.State)
				}
			} else if s.Status.State != api.SwitchStateReady || result.RequeueAfter != 60*time.Second {
				t.Errorf("unexpected observation: %#v, %#v", s.Status, result)
			}
		})
	}
}

func TestSafeAdoptionStatusPatchError(t *testing.T) {
	t.Parallel()
	s, i, a, scheme := adoptionFixture(t)
	patchErr := errors.New("status patch failed")
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(i).WithObjects(s, i).WithInterceptorFuncs(interceptor.Funcs{
		SubResourcePatch: func(context.Context, client.Client, string, client.Object, client.Patch, ...client.SubResourcePatchOption) error {
			return patchErr
		},
	}).Build()
	r := SwitchInterfaceReconciler{Client: c, Scheme: scheme, ObserveOnly: true, NewAgentClient: func(context.Context, client.Reader, *corev1.LocalObjectReference, string) (agentclient.SwitchAgentClient, error) {
		return a, nil
	}}
	_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(i)})
	if !errors.Is(err, patchErr) {
		t.Fatalf("status patch error lost: %v", err)
	}
}

func TestSafeAdoptionNoNeighbor(t *testing.T) {
	t.Parallel()
	s, i, a, scheme := adoptionFixture(t)
	i.Status.Neighbor.SystemName = "stale"
	a.neighbor.Status.Code = agenterrors.NOT_FOUND
	a.neighborErr = errors.New("no neighbor")
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(i).WithObjects(s, i).Build()
	r := SwitchInterfaceReconciler{Client: c, Scheme: scheme, ObserveOnly: true, NewAgentClient: func(context.Context, client.Reader, *corev1.LocalObjectReference, string) (agentclient.SwitchAgentClient, error) {
		return a, nil
	}}
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(i)}); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(i), i); err != nil {
		t.Fatal(err)
	}
	if i.Status.Neighbor != (api.Neighbor{}) {
		t.Fatalf("stale neighbor: %#v", i.Status.Neighbor)
	}
}

func TestSafeAdoptionConcurrentCreation(t *testing.T) {
	t.Parallel()
	for _, conflict := range []bool{false, true} {
		name := "matching identity"
		if conflict {
			name = "conflicting identity"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s, i, a, scheme := adoptionFixture(t)
			if conflict {
				i.Spec.NativeName = "Ethernet4"
			}
			c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s).WithInterceptorFuncs(interceptor.Funcs{
				Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
					if err := c.Create(ctx, i); err != nil {
						return err
					}
					return c.Create(ctx, obj, opts...)
				},
			}).Build()
			r := SwitchReconciler{Client: c, Scheme: scheme}
			err := r.EnsureInterface(t.Context(), logr.Discard(), s, *a.iface)
			if (err != nil) != conflict {
				t.Errorf("error = %v, want conflict %v", err, conflict)
			}
			got := &api.SwitchInterface{}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(i), got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.Spec, i.Spec) {
				t.Fatal("concurrent creator's desired spec overwritten")
			}
		})
	}
}

func TestSafeAdoptionAgentConstructionFailure(t *testing.T) {
	t.Parallel()
	for _, factoryErr := range []error{nil, errors.New("construction failed")} {
		name := "nil client"
		if factoryErr != nil {
			name = "factory error"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s, i, _, scheme := adoptionFixture(t)
			s.Status.Ports = []api.PortStatus{{Name: "last-known"}}
			c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(s, i).WithObjects(s, i).Build()
			r := SwitchReconciler{Client: c, NewAgentClient: func(context.Context, *api.Switch) (agentclient.SwitchAgentClient, error) { return nil, factoryErr }}
			ir := SwitchInterfaceReconciler{Client: c, ObserveOnly: true, NewAgentClient: func(context.Context, client.Reader, *corev1.LocalObjectReference, string) (agentclient.SwitchAgentClient, error) {
				return nil, factoryErr
			}}
			switchResult, switchErr := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(s)})
			_, interfaceErr := ir.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(i)})
			if interfaceErr == nil {
				t.Fatal("missing interface failure")
			}
			if factoryErr != nil {
				// An unreachable agent keeps the Switch Ready and retries later.
				if switchErr != nil || switchResult.RequeueAfter != time.Minute {
					t.Fatalf("unreachable agent: err=%v result=%#v", switchErr, switchResult)
				}
				if !errors.Is(interfaceErr, factoryErr) {
					t.Fatal("factory error lost")
				}
			} else if switchErr == nil {
				t.Fatal("nil client accepted")
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(s), s); err != nil {
				t.Fatal(err)
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(i), i); err != nil {
				t.Fatal(err)
			}
			wantSwitch := api.SwitchStateFailed
			if factoryErr != nil {
				wantSwitch = api.SwitchStateReady
			}
			if s.Status.State != wantSwitch || i.Status.State != api.SwitchInterfaceStateFailed {
				t.Fatalf("switch=%s interface=%s", s.Status.State, i.Status.State)
			}
			if !reflect.DeepEqual(s.Status.Ports, []api.PortStatus{{Name: "last-known"}}) {
				t.Fatal("factory failure discarded last-known inventory")
			}
		})
	}
}
