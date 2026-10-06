// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	agentclient "github.com/ironcore-dev/sonic-operator/internal/agent/agent_client/client"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestSwitchVLANAuthoritativeDefaultGate(t *testing.T) {
	v, a, scheme := vlanFixture(t)
	// Decode the new policy as a client would; before implementation it is
	// silently ignored and the additive path incorrectly writes to the device.
	if err := json.Unmarshal([]byte(`{"reconcilePolicy":"Authoritative"}`), &v.Spec); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(v).WithObjects(v).Build()
	r := vlanReconciler(c, a)
	_, _ = r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(v)})
	if len(a.writes) != 0 {
		t.Fatal("authoritative request fell through to additive writes with the default gate disabled")
	}
}

type vlanTestAgent struct {
	agentclient.SwitchAgentClient
	current, response           *agent.VLAN
	readErr, writeErr, closeErr error
	reads, closes               int
	writes                      []agent.VLAN
	onRead                      func()
	applyBeforeError            bool
}

func (a *vlanTestAgent) GetVLAN(_ context.Context, id uint32) (*agent.VLAN, error) {
	a.reads++
	if a.onRead != nil {
		a.onRead()
	}
	if id != 100 {
		return nil, fmt.Errorf("unexpected VLAN ID %d", id)
	}
	return a.current, a.readErr
}

func (a *vlanTestAgent) EnsureVLAN(_ context.Context, vlan *agent.VLAN) (*agent.VLAN, error) {
	a.writes = append(a.writes, agent.VLAN{ID: vlan.ID, Members: append([]agent.VLANMember(nil), vlan.Members...)})
	if a.writeErr == nil || a.applyBeforeError {
		a.current, a.readErr = a.response, nil
	}
	return a.response, a.writeErr
}

func (a *vlanTestAgent) Close() error { a.closes++; return a.closeErr }

func vlanFixture(t *testing.T) (*api.SwitchVLAN, *vlanTestAgent, *runtime.Scheme) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := api.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	v := &api.SwitchVLAN{
		ObjectMeta: metav1.ObjectMeta{Name: "leaf-vlan100", Generation: 3},
		Spec: api.SwitchVLANSpec{
			SwitchRef: api.SwitchVLANReference{Name: "leaf"}, VLANID: 100,
			ManagementPolicy: api.VLANManagementPolicyManage,
			Members:          []api.SwitchVLANMember{{InterfaceName: "Ethernet0", TaggingMode: "untagged"}},
		},
	}
	a := &vlanTestAgent{
		current: &agent.VLAN{ID: 100},
		response: &agent.VLAN{ID: 100, Members: []agent.VLANMember{
			{InterfaceName: "Ethernet0", TaggingMode: "untagged"},
		}},
	}
	return v, a, scheme
}

func vlanReconciler(c client.Client, a agentclient.SwitchAgentClient) *SwitchVLANReconciler {
	return &SwitchVLANReconciler{
		Client: c,
		NewAgentClient: func(_ context.Context, _ client.Reader, ref *corev1.LocalObjectReference, namespace string) (agentclient.SwitchAgentClient, error) {
			if ref.Name != "leaf" || namespace != "" {
				return nil, fmt.Errorf("unexpected switch reference: %v / %q", ref, namespace)
			}
			return a, nil
		},
	}
}

func TestSwitchVLANGates(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		policy  api.VLANManagementPolicy
		guard   bool
		missing bool
		match   bool
		writes  int
		synced  bool
	}{
		{name: "default observes"},
		{name: "Observe never writes", policy: api.VLANManagementPolicyObserve},
		{name: "global guard", policy: api.VLANManagementPolicyManage, guard: true},
		{name: "Observe missing", policy: api.VLANManagementPolicyObserve, missing: true},
		{name: "global guard missing", policy: api.VLANManagementPolicyManage, guard: true, missing: true},
		{name: "Manage adds missing member", policy: api.VLANManagementPolicyManage, writes: 1, synced: true},
		{name: "Manage creates missing VLAN", policy: api.VLANManagementPolicyManage, missing: true, writes: 1, synced: true},
		{name: "Manage matching confirms persistence", policy: api.VLANManagementPolicyManage, match: true, writes: 1, synced: true},
		{name: "global guard matching", policy: api.VLANManagementPolicyManage, guard: true, match: true, synced: true},
		{name: "Observe matching", policy: api.VLANManagementPolicyObserve, match: true, synced: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v, a, scheme := vlanFixture(t)
			v.Spec.ManagementPolicy = tc.policy
			if tc.match {
				a.current = a.response
				// An unmanaged member must neither prevent sync nor be pruned.
				a.current.Members = append(a.current.Members, agent.VLANMember{InterfaceName: "Ethernet129", TaggingMode: "tagged"})
			}
			if tc.missing {
				a.current, a.readErr = nil, fmt.Errorf("get: %w", agentclient.ErrVLANNotFound)
			}
			c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(v).WithObjects(v).Build()
			r := vlanReconciler(c, a)
			r.ObserveOnly = tc.guard
			for iteration := range 2 {
				result, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(v)})
				if err != nil {
					t.Fatal(err)
				}
				if result.RequeueAfter < 30*time.Second || result.RequeueAfter > 60*time.Second {
					t.Errorf("unexpected poll interval %v", result.RequeueAfter)
				}
				if len(a.writes) != tc.writes*(iteration+1) || a.closes != iteration+1 {
					t.Fatalf("writes=%v closes=%d", a.writes, a.closes)
				}
			}
			got := &api.SwitchVLAN{}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(v), got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(v.Spec, got.Spec) || len(got.Finalizers) != 0 {
				t.Fatalf("spec or finalizers mutated: %#v", got)
			}
			if got.Status.ObservedGeneration != v.Generation {
				t.Errorf("observed generation=%d", got.Status.ObservedGeneration)
			}
			for _, name := range []string{"Ready", "Synced"} {
				condition := meta.FindStatusCondition(got.Status.Conditions, name)
				if condition == nil || (condition.Status == metav1.ConditionTrue) != tc.synced || condition.ObservedGeneration != v.Generation {
					t.Errorf("unexpected %s: %#v", name, condition)
				}
			}
			if got.Status.Exists == nil || *got.Status.Exists != (!tc.missing || tc.writes > 0) {
				t.Errorf("unexpected existence: %#v", got.Status.Exists)
			}
			if tc.match && len(got.Status.Members) != 2 {
				t.Error("unmanaged member missing from observation")
			}
			if tc.writes > 0 && !reflect.DeepEqual(a.writes[0], agent.VLAN{ID: 100, Members: []agent.VLANMember{{InterfaceName: "Ethernet0", TaggingMode: "untagged"}}}) {
				t.Errorf("unexpected write: %#v", a.writes[0])
			}
		})
	}
}

func TestSwitchVLANPortChannelAcceptance(t *testing.T) {
	t.Parallel()
	for _, policy := range []api.VLANManagementPolicy{api.VLANManagementPolicyObserve, api.VLANManagementPolicyManage} {
		t.Run(string(policy), func(t *testing.T) {
			v, a, scheme := vlanFixture(t)
			v.Spec.ManagementPolicy = policy
			v.Spec.Members[0].InterfaceName = "PortChannel10"
			a.response.Members[0].InterfaceName = "PortChannel10"
			c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(v).WithObjects(v).Build()
			r := vlanReconciler(c, a)
			if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(v)}); err != nil {
				t.Fatal(err)
			}
			want := 0
			if policy == api.VLANManagementPolicyManage {
				want = 1
			}
			if len(a.writes) != want || a.closes != 1 {
				t.Fatalf("writes=%v closes=%d", a.writes, a.closes)
			}
		})
	}
}

func TestSwitchVLANFailures(t *testing.T) {
	t.Parallel()
	failure := errors.New("agent unavailable")
	for _, tc := range []struct {
		name   string
		change func(*api.SwitchVLAN, *vlanTestAgent)
		writes int
	}{
		{name: "read error", change: func(_ *api.SwitchVLAN, a *vlanTestAgent) { a.readErr = failure }},
		{name: "nil observation", change: func(_ *api.SwitchVLAN, a *vlanTestAgent) { a.current = nil }},
		{name: "wrong observed ID", change: func(_ *api.SwitchVLAN, a *vlanTestAgent) { a.current.ID = 200 }},
		{name: "conflicting tagging mode", change: func(_ *api.SwitchVLAN, a *vlanTestAgent) {
			a.current.Members = []agent.VLANMember{{InterfaceName: "Ethernet0", TaggingMode: "tagged"}}
		}},
		{name: "duplicate observed member", change: func(_ *api.SwitchVLAN, a *vlanTestAgent) {
			a.current.Members = []agent.VLANMember{{InterfaceName: "Ethernet0", TaggingMode: "tagged"}, {InterfaceName: "Ethernet0", TaggingMode: "untagged"}}
		}},
		{name: "write error", change: func(_ *api.SwitchVLAN, a *vlanTestAgent) { a.writeErr = failure }, writes: 1},
		{name: "nil write confirmation", change: func(_ *api.SwitchVLAN, a *vlanTestAgent) { a.response = nil }, writes: 1},
		{name: "wrong confirmed ID", change: func(_ *api.SwitchVLAN, a *vlanTestAgent) { a.response.ID = 200 }, writes: 1},
		{name: "missing confirmed member", change: func(_ *api.SwitchVLAN, a *vlanTestAgent) { a.response.Members = nil }, writes: 1},
		{name: "wrong confirmed mode", change: func(_ *api.SwitchVLAN, a *vlanTestAgent) { a.response.Members[0].TaggingMode = "tagged" }, writes: 1},
		{name: "close error", change: func(_ *api.SwitchVLAN, a *vlanTestAgent) { a.closeErr = failure }, writes: 1},
		{name: "empty switch", change: func(v *api.SwitchVLAN, _ *vlanTestAgent) { v.Spec.SwitchRef.Name = "" }},
		{name: "zero VLAN", change: func(v *api.SwitchVLAN, _ *vlanTestAgent) { v.Spec.VLANID = 0 }},
		{name: "reserved VLAN", change: func(v *api.SwitchVLAN, _ *vlanTestAgent) { v.Spec.VLANID = 4095 }},
		{name: "unknown policy", change: func(v *api.SwitchVLAN, _ *vlanTestAgent) { v.Spec.ManagementPolicy = "manage" }},
		{name: "noncanonical LAG port", change: func(v *api.SwitchVLAN, _ *vlanTestAgent) { v.Spec.Members[0].InterfaceName = "PortChannel01" }},
		{name: "noncanonical port", change: func(v *api.SwitchVLAN, _ *vlanTestAgent) { v.Spec.Members[0].InterfaceName = "Ethernet00" }},
		{name: "missing tagging mode", change: func(v *api.SwitchVLAN, _ *vlanTestAgent) { v.Spec.Members[0].TaggingMode = "" }},
		{name: "invalid tagging mode", change: func(v *api.SwitchVLAN, _ *vlanTestAgent) { v.Spec.Members[0].TaggingMode = "TAGGED" }},
		{name: "duplicate desired member", change: func(v *api.SwitchVLAN, _ *vlanTestAgent) { v.Spec.Members = append(v.Spec.Members, v.Spec.Members[0]) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v, a, scheme := vlanFixture(t)
			tc.change(v, a)
			c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(v).WithObjects(v).Build()
			r := vlanReconciler(c, a)
			_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(v)})
			if err == nil {
				t.Fatal("expected reconcile failure")
			}
			if len(a.writes) != tc.writes {
				t.Fatalf("writes=%v, want %d", a.writes, tc.writes)
			}
			got := &api.SwitchVLAN{}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(v), got); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"Ready", "Synced"} {
				if !meta.IsStatusConditionFalse(got.Status.Conditions, name) {
					t.Errorf("failure not reported in %s: %#v", name, got.Status)
				}
			}
		})
	}
}

func TestSwitchVLANClaims(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		switchName string
		id         uint32
		deleting   bool
		conflict   bool
	}{
		{name: "duplicate Observe claim", switchName: "leaf", id: 100, conflict: true},
		{name: "terminating claim", switchName: "leaf", id: 100, deleting: true, conflict: true},
		{name: "other switch", switchName: "spine", id: 100},
		{name: "other VLAN", switchName: "leaf", id: 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v, a, scheme := vlanFixture(t)
			other := v.DeepCopy()
			other.Name = "other"
			other.Spec.SwitchRef.Name, other.Spec.VLANID = tc.switchName, tc.id
			other.Spec.ManagementPolicy = api.VLANManagementPolicyObserve
			if tc.deleting {
				now := metav1.Now()
				other.DeletionTimestamp, other.Finalizers = &now, []string{"test/block"}
			}
			c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(v).WithObjects(v).Build()
			// The cache intentionally has no competing claim; use the authoritative reader.
			reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(v, other).Build()
			r := vlanReconciler(c, a)
			r.APIReader = reader
			_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(v)})
			if (err != nil) != tc.conflict {
				t.Fatalf("error=%v conflict=%v", err, tc.conflict)
			}
			if tc.conflict && (a.reads != 0 || len(a.writes) != 0) {
				t.Fatal("ambiguous ownership contacted agent")
			}
		})
	}
}

func TestSwitchVLANDeletion(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"absent CR", "deleting CR"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v, a, scheme := vlanFixture(t)
			builder := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(v)
			if name == "deleting CR" {
				now := metav1.Now()
				v.DeletionTimestamp, v.Finalizers = &now, []string{"test/block"}
				builder.WithObjects(v)
			}
			c := builder.Build()
			r := vlanReconciler(c, a)
			r.NewAgentClient = func(context.Context, client.Reader, *corev1.LocalObjectReference, string) (agentclient.SwitchAgentClient, error) {
				t.Error("deletion must not contact device")
				return a, nil
			}
			if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(v)}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSwitchVLANPreWriteRecheck(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"deleted", "spec changed", "duplicate created"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v, a, scheme := vlanFixture(t)
			c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(v).WithObjects(v).Build()
			a.onRead = func() {
				switch name {
				case "deleted":
					if err := c.Delete(t.Context(), v); err != nil {
						t.Fatal(err)
					}
				case "spec changed":
					latest := &api.SwitchVLAN{}
					if err := c.Get(t.Context(), client.ObjectKeyFromObject(v), latest); err != nil {
						t.Fatal(err)
					}
					latest.Spec.ManagementPolicy = api.VLANManagementPolicyObserve
					if err := c.Update(t.Context(), latest); err != nil {
						t.Fatal(err)
					}
				case "duplicate created":
					other := v.DeepCopy()
					other.Name, other.ResourceVersion = "other", ""
					if err := c.Create(t.Context(), other); err != nil {
						t.Fatal(err)
					}
				}
			}
			r := vlanReconciler(c, a)
			if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(v)}); err == nil {
				t.Fatal("expected pre-write recheck to fail")
			}
			if len(a.writes) != 0 || a.reads != 1 || a.closes != 1 {
				t.Fatalf("writes=%v reads=%d closes=%d", a.writes, a.reads, a.closes)
			}
		})
	}
}

func TestSwitchVLANEmptyAndUnmanagedMembers(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"empty desired", "unmanaged LAG", "add without pruning"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v, a, scheme := vlanFixture(t)
			if name == "empty desired" {
				v.Spec.Members = nil
				a.response = a.current
			} else {
				unmanaged := agent.VLANMember{InterfaceName: "PortChannel10", TaggingMode: "tagged"}
				a.current.Members = []agent.VLANMember{unmanaged}
				a.response.Members = append(a.response.Members, unmanaged)
				if name == "unmanaged LAG" {
					a.current = a.response
				}
			}
			patches := 0
			c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(v).WithObjects(v).
				WithInterceptorFuncs(interceptor.Funcs{SubResourcePatch: func(ctx context.Context, c client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
					patches++
					return c.SubResource(sub).Patch(ctx, obj, patch, opts...)
				}}).Build()
			r := vlanReconciler(c, a)
			for range 2 {
				if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(v)}); err != nil {
					t.Fatal(err)
				}
			}
			if patches != 1 {
				t.Errorf("unchanged observation patched status %d times", patches)
			}
			if len(a.writes) != 2 {
				t.Fatalf("each Manage reconcile must confirm persistence: %#v", a.writes)
			}
			for _, write := range a.writes {
				if name == "empty desired" {
					if len(write.Members) != 0 {
						t.Fatalf("empty spec requested members: %#v", write)
					}
				} else if len(write.Members) != 1 || write.Members[0].InterfaceName != "Ethernet0" {
					t.Fatalf("ensure must request only declared members: %#v", write)
				}
			}
		})
	}
}

func TestSwitchVLANObservationRefresh(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"read error", "VLAN disappeared", "mode drift", "stable status"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v, a, scheme := vlanFixture(t)
			v.Spec.ManagementPolicy = api.VLANManagementPolicyObserve
			a.current = a.response
			c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(v).WithObjects(v).Build()
			r := vlanReconciler(c, a)
			req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(v)}
			if _, err := r.Reconcile(t.Context(), req); err != nil {
				t.Fatal(err)
			}
			before := &api.SwitchVLAN{}
			if err := c.Get(t.Context(), req.NamespacedName, before); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "read error":
				a.readErr = errors.New("read failed")
			case "VLAN disappeared":
				a.current, a.readErr = nil, agentclient.ErrVLANNotFound
			case "mode drift":
				a.current.Members[0].TaggingMode = "tagged"
			}
			_, err := r.Reconcile(t.Context(), req)
			if (err != nil) != (name == "read error" || name == "mode drift") {
				t.Fatalf("unexpected error: %v", err)
			}
			got := &api.SwitchVLAN{}
			if err := c.Get(t.Context(), req.NamespacedName, got); err != nil {
				t.Fatal(err)
			}
			if name == "stable status" {
				if got.ResourceVersion != before.ResourceVersion || !reflect.DeepEqual(got.Status, before.Status) {
					t.Fatal("stable observation needlessly patched status")
				}
				return
			}
			if !meta.IsStatusConditionFalse(got.Status.Conditions, "Ready") || !meta.IsStatusConditionFalse(got.Status.Conditions, "Synced") {
				t.Fatalf("stale success conditions: %#v", got.Status)
			}
			if name == "read error" && got.Status.Exists != nil {
				t.Fatal("read failure presented stale existence as current")
			}
			if name == "VLAN disappeared" && (got.Status.Exists == nil || *got.Status.Exists) {
				t.Fatal("missing VLAN not reported absent")
			}
			if name != "mode drift" && len(got.Status.Members) != 0 {
				t.Fatal("stale members retained after unavailable observation")
			}
			if len(a.writes) != 0 {
				t.Fatal("Observe performed a write")
			}
		})
	}
}

func TestSwitchVLANPersistenceRetry(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"same reconciler", "restarted reconciler", "already matching after restart"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v, a, scheme := vlanFixture(t)
			failure := errors.New("Redis applied; SaveConfig failed")
			a.applyBeforeError, a.writeErr = true, failure
			if name == "already matching after restart" {
				a.current = a.response
			}
			c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(v).WithObjects(v).Build()
			r := vlanReconciler(c, a)
			req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(v)}
			for attempt := range 4 {
				if name != "same reconciler" {
					r = vlanReconciler(c, a)
				}
				if attempt == 2 {
					a.writeErr = nil
				}
				_, err := r.Reconcile(t.Context(), req)
				if attempt < 2 && !errors.Is(err, failure) {
					t.Fatalf("attempt %d skipped persistence retry: %v", attempt, err)
				}
				if attempt >= 2 && err != nil {
					t.Fatal(err)
				}
				if len(a.writes) != attempt+1 || !reflect.DeepEqual(a.current, a.response) {
					t.Fatalf("matching Redis state must still Ensure: calls=%d current=%#v", len(a.writes), a.current)
				}
				got := &api.SwitchVLAN{}
				if err := c.Get(t.Context(), req.NamespacedName, got); err != nil {
					t.Fatal(err)
				}
				for _, condition := range []string{"Ready", "Synced"} {
					if meta.IsStatusConditionTrue(got.Status.Conditions, condition) != (attempt >= 2) {
						t.Fatalf("attempt %d dishonest %s: %#v", attempt, condition, got.Status)
					}
				}
				if attempt < 2 && (got.Status.Exists != nil || len(got.Status.Members) != 0) {
					t.Fatal("uncertain persistence reported as confirmed observation")
				}
				if attempt >= 2 && (got.Status.Exists == nil || !*got.Status.Exists || len(got.Status.Members) != 1) {
					t.Fatalf("successful retry did not restore observed status: %#v", got.Status)
				}
				if !reflect.DeepEqual(a.writes[attempt], *a.response) {
					t.Fatalf("retry changed the requested configuration: %#v", a.writes[attempt])
				}
				if !reflect.DeepEqual(v.Spec, got.Spec) {
					t.Fatal("retry mutated spec")
				}
			}
		})
	}
}

func TestSwitchVLANClientAndStatusErrors(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"factory error", "nil client", "unsupported VLAN", "claim list error", "status error"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v, a, scheme := vlanFixture(t)
			failure := errors.New(name)
			builder := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(v).WithObjects(v)
			if name == "claim list error" {
				builder.WithInterceptorFuncs(interceptor.Funcs{List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error { return failure }})
			}
			if name == "status error" {
				builder.WithInterceptorFuncs(interceptor.Funcs{SubResourcePatch: func(context.Context, client.Client, string, client.Object, client.Patch, ...client.SubResourcePatchOption) error {
					return failure
				}})
			}
			c := builder.Build()
			r := vlanReconciler(c, a)
			if name == "factory error" || name == "nil client" || name == "unsupported VLAN" {
				r.NewAgentClient = func(context.Context, client.Reader, *corev1.LocalObjectReference, string) (agentclient.SwitchAgentClient, error) {
					switch name {
					case "factory error":
						return nil, failure
					case "nil client":
						return nil, nil
					default:
						return &adoptionAgent{}, nil
					}
				}
			}
			if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(v)}); err == nil {
				t.Fatal("expected failure")
			}
			if name != "status error" && len(a.writes) != 0 {
				t.Fatal("unsafe write after client/claim error")
			}
		})
	}
}
