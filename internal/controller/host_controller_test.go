// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	agentclient "github.com/ironcore-dev/sonic-operator/internal/agent/agent_client/client"
	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestHostSecretResolutionUsesReferencesOnly(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = api.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "system", Name: "snmp", UID: "secret-uid", ResourceVersion: "7"}, Data: map[string][]byte{"community": []byte("test-private-community")}}
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	obj := &api.SwitchSystem{ObjectMeta: metav1.ObjectMeta{Name: "system", UID: "uid", Generation: 1}, Spec: api.SwitchSystemSpec{NetworkResourceSpec: api.NetworkResourceSpec{SwitchRef: api.NetworkSwitchReference{Name: "sw"}, ManagementPolicy: api.NetworkManagementPolicyManage}, SNMP: &api.SystemSNMP{CommunitySecretRef: &api.HostSecretKeyReference{Namespace: "system", Name: "snmp", Key: "community"}}}}
	r := HostReconciler{APIReader: reader}
	request, _, err := r.hostDesired(context.Background(), obj, "switch-uid")
	if err != nil {
		t.Fatal(err)
	}
	if string(request.System.SNMP.Community) != "test-private-community" {
		t.Fatal("secret not resolved")
	}
	if strings.Contains(request.Revision, "test-private") {
		t.Fatal("credential in public revision")
	}
	public, _ := json.Marshal(obj)
	if strings.Contains(string(public), "test-private") {
		t.Fatal("credential inserted into public object")
	}
	obj.Spec.SNMP.CommunitySecretRef.Key = "absent"
	if _, _, err = r.hostDesired(context.Background(), obj, "switch-uid"); err == nil || strings.Contains(err.Error(), "test-private") {
		t.Fatal("secret failure not sanitized")
	}
}

func TestHostSecretChangesBetweenObservationAndWriteBlockEnsure(t *testing.T) {
	for _, operation := range []string{"rotate", "delete"} {
		t.Run(operation, func(t *testing.T) {
			scheme := runtime.NewScheme()
			_ = api.AddToScheme(scheme)
			_ = corev1.AddToScheme(scheme)
			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "system", Name: "snmp", UID: "secret-uid", ResourceVersion: "7"}, Data: map[string][]byte{"community": []byte("old-fixture-secret")}}
			sw := &api.Switch{ObjectMeta: metav1.ObjectMeta{Name: "sw", UID: "switch-uid"}, Spec: api.SwitchSpec{MacAddress: "00:11:22:33:44:55", Management: api.Management{Host: "10.0.0.11", Port: "50051"}}}
			obj := &api.SwitchSystem{ObjectMeta: metav1.ObjectMeta{Name: "system", UID: "owner", Generation: 1, Annotations: map[string]string{hostBindingAnnotation: encodeHostBinding(bindingForHost(sw))}}, Spec: api.SwitchSystemSpec{NetworkResourceSpec: api.NetworkResourceSpec{SwitchRef: api.NetworkSwitchReference{Name: "sw"}, ManagementPolicy: api.NetworkManagementPolicyManage}, SNMP: &api.SystemSNMP{CommunitySecretRef: &api.HostSecretKeyReference{Namespace: "system", Name: "snmp", Key: "community"}}}}
			kube := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(obj, sw).WithObjects(obj, sw, secret).Build()
			writes := 0
			r := HostReconciler{Client: kube, APIReader: kube, Kind: "System", AllowHostConfig: true, NewAgentClient: func(ctx context.Context, _ client.Reader, _ *corev1.LocalObjectReference, _ string) (agentclient.SwitchAgentClient, error) {
				return &hostControllerFake{get: func(int, host.Request) (host.Result, error) {
					var err error
					if operation == "delete" {
						err = kube.Delete(ctx, secret)
					} else {
						secret.Data["community"] = []byte("rotated-fixture-secret")
						err = kube.Update(ctx, secret)
					}
					if err != nil {
						t.Fatal(err)
					}
					return host.Result{}, nil
				}, ensure: func(int, host.Request) (host.Result, error) { writes++; return host.Result{}, nil }}, nil
			}}
			if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKey{Name: "system"}}); err == nil {
				t.Fatal("stale Secret was accepted for write")
			}
			if writes != 0 {
				t.Fatal("Secret change reached agent Ensure")
			}
			_ = kube.Get(t.Context(), client.ObjectKey{Name: "system"}, obj)
			public, _ := json.Marshal(obj)
			if strings.Contains(string(public), "fixture-secret") {
				t.Fatal("credential leaked into public resource")
			}
		})
	}
}

type hostControllerFake struct {
	agentclient.SwitchAgentClient
	connection int
	get        func(int, host.Request) (host.Result, error)
	ensure     func(int, host.Request) (host.Result, error)
	confirm    func(int, host.Confirmation) (host.Result, error)
	closed     bool
}

func (f *hostControllerFake) GetDeviceInfo(context.Context) (*agent.SwitchDevice, error) {
	return &agent.SwitchDevice{LocalMacAddress: "00:11:22:33:44:55"}, nil
}
func (f *hostControllerFake) GetHost(_ context.Context, q host.Request) (host.Result, error) {
	return f.get(f.connection, q)
}
func (f *hostControllerFake) EnsureHost(_ context.Context, q host.Request) (host.Result, error) {
	return f.ensure(f.connection, q)
}
func (f *hostControllerFake) ConfirmHost(_ context.Context, q host.Confirmation) (host.Result, error) {
	return f.confirm(f.connection, q)
}
func (f *hostControllerFake) Close() error { f.closed = true; return nil }

func TestHostControllerConfirmsOnFreshConnectionAndMovesEndpoint(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = api.AddToScheme(scheme)
	obj := &api.SwitchManagement{ObjectMeta: metav1.ObjectMeta{Name: "mgmt", UID: "owner", Generation: 1}, Spec: api.SwitchManagementSpec{NetworkResourceSpec: api.NetworkResourceSpec{SwitchRef: api.NetworkSwitchReference{Name: "sw"}, ManagementPolicy: api.NetworkManagementPolicyManage}, Addresses: []api.ManagementAddress{{Prefix: "10.0.0.99/24", Gateway: "10.0.0.1"}}}}
	sw := &api.Switch{ObjectMeta: metav1.ObjectMeta{Name: "sw", UID: "switch-uid"}, Spec: api.SwitchSpec{MacAddress: "00:11:22:33:44:55", Management: api.Management{Host: "10.0.0.11", Port: "50051"}}}
	kube := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(obj, sw).WithObjects(obj, sw).Build()
	var clients []*hostControllerFake
	ensures, confirmations := 0, 0
	r := &HostReconciler{Client: kube, APIReader: kube, Kind: "Management", AllowHostConfig: true, NewAgentClient: func(ctx context.Context, reader client.Reader, _ *corev1.LocalObjectReference, _ string) (agentclient.SwitchAgentClient, error) {
		target := &api.Switch{}
		if err := reader.Get(ctx, client.ObjectKey{Name: "sw"}, target); err != nil {
			return nil, err
		}
		index := len(clients)
		if index == 1 && (target.Spec.Management.Host != "10.0.0.99" || !clients[0].closed) {
			t.Fatal("fresh connection not established after closing original")
		}
		f := &hostControllerFake{connection: index, get: func(c int, q host.Request) (host.Result, error) {
			if c == 0 {
				return host.Result{}, nil
			}
			return host.Result{ConfigurationVerified: true, RuntimeVerified: true, PersistenceVerified: true, GatewayVerified: true, Recovery: "Pending", Transaction: "tx", Challenge: "challenge", Owner: q.Owner}, nil
		}, ensure: func(c int, q host.Request) (host.Result, error) {
			ensures++
			return host.Result{Recovery: "Pending", Transaction: "tx", Owner: q.Owner}, nil
		}, confirm: func(c int, q host.Confirmation) (host.Result, error) {
			confirmations++
			if c != 1 || q.Target != "switch-uid" || q.Challenge != "challenge" {
				t.Fatal("wrong confirmation binding")
			}
			return host.Result{ConfigurationVerified: true, RuntimeVerified: true, PersistenceVerified: true, GatewayVerified: true, Recovery: "Confirmed", Owner: q.Owner}, nil
		}}
		clients = append(clients, f)
		return f, nil
	}}
	key := ctrl.Request{NamespacedName: client.ObjectKey{Name: "mgmt"}}
	for i := 0; i < 2; i++ {
		if _, err := r.Reconcile(context.Background(), key); err != nil {
			t.Fatal(err)
		}
	}
	if ensures != 1 || confirmations != 1 {
		t.Fatalf("ensure=%d confirm=%d", ensures, confirmations)
	}
	if err := kube.Get(context.Background(), client.ObjectKey{Name: "sw"}, sw); err != nil {
		t.Fatal(err)
	}
	if sw.Spec.Management.Host != "10.0.0.99" {
		t.Fatal("confirmed endpoint not persisted")
	}
	if err := kube.Get(context.Background(), client.ObjectKey{Name: "mgmt"}, obj); err != nil {
		t.Fatal(err)
	}
	var binding hostBinding
	if json.Unmarshal([]byte(obj.Annotations[hostBindingAnnotation]), &binding) != nil || binding.Host != "10.0.0.99" {
		t.Fatal("stale binding prevents subsequent management address changes")
	}
}
func TestHostDesiredRejectsUnsafeManagementWithoutAgent(t *testing.T) {
	r := HostReconciler{}
	obj := &api.SwitchManagement{ObjectMeta: metav1.ObjectMeta{Name: "mgmt", UID: "uid", Generation: 1}, Spec: api.SwitchManagementSpec{NetworkResourceSpec: api.NetworkResourceSpec{SwitchRef: api.NetworkSwitchReference{Name: "sw"}}, Addresses: []api.ManagementAddress{{Prefix: "10.0.0.11/24", Gateway: "10.5.0.1"}}}}
	if _, _, err := r.hostDesired(context.Background(), obj, "switch-uid"); err == nil {
		t.Fatal("off-link gateway accepted")
	}
}

func TestHostObserveStatusIsStableAndNeverManagedReady(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = api.AddToScheme(scheme)
	obj := &api.SwitchManagement{ObjectMeta: metav1.ObjectMeta{Name: "mgmt", UID: "owner", Generation: 1}, Spec: api.SwitchManagementSpec{NetworkResourceSpec: api.NetworkResourceSpec{SwitchRef: api.NetworkSwitchReference{Name: "sw"}}, Addresses: []api.ManagementAddress{{Prefix: "10.0.0.11/24", Gateway: "10.0.0.1"}}}}
	sw := &api.Switch{ObjectMeta: metav1.ObjectMeta{Name: "sw", UID: "switch-uid"}, Spec: api.SwitchSpec{MacAddress: "00:11:22:33:44:55", Management: api.Management{Host: "10.0.0.11", Port: "50051"}}}
	kube := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(obj, sw).WithObjects(obj, sw).Build()
	r := HostReconciler{Client: kube, APIReader: kube, Kind: "Management", NewAgentClient: func(context.Context, client.Reader, *corev1.LocalObjectReference, string) (agentclient.SwitchAgentClient, error) {
		return &hostControllerFake{get: func(int, host.Request) (host.Result, error) {
			return host.Result{ConfigurationVerified: true, RuntimeVerified: true, PersistenceVerified: true, GatewayVerified: true, Recovery: "Idle"}, nil
		}}, nil
	}}
	key := ctrl.Request{NamespacedName: client.ObjectKey{Name: "mgmt"}}
	if _, err := r.Reconcile(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	_ = kube.Get(context.Background(), key.NamespacedName, obj)
	rv := obj.ResourceVersion
	if _, err := r.Reconcile(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	_ = kube.Get(context.Background(), key.NamespacedName, obj)
	if rv != obj.ResourceVersion {
		t.Fatal("unchanged evidence causes status update loop")
	}
	for _, c := range obj.Status.Conditions {
		if c.Type == "Ready" && c.Status == metav1.ConditionTrue {
			t.Fatal("Observe reported managed Ready")
		}
	}
}
