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
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

type vlanAuthorityTestAgent struct {
	*vlanTestAgent
	snapshot                         *agent.VLANAuthorityResult
	response                         *agent.VLANAuthorityResult
	getErr, reconcileErr, releaseErr error
	requests                         []agent.VLANAuthorityRequest
	releases                         []string
	onAuthorityRead                  func()
	onRelease                        func()
}

func (a *vlanAuthorityTestAgent) GetVLANAuthority(context.Context, uint32) (*agent.VLANAuthorityResult, error) {
	if a.onAuthorityRead != nil {
		a.onAuthorityRead()
	}
	return a.snapshot, a.getErr
}

func (a *vlanAuthorityTestAgent) ReconcileVLANAuthority(_ context.Context, request *agent.VLANAuthorityRequest) (*agent.VLANAuthorityResult, error) {
	a.requests = append(a.requests, *request)
	if a.reconcileErr != nil {
		return nil, a.reconcileErr
	}
	if a.response != nil {
		return a.response, nil
	}
	v := request.VLAN
	if request.Delete {
		v = nil
	}
	a.snapshot = &agent.VLANAuthorityResult{VLAN: v, OwnerID: request.OwnerID, OwnershipKnown: true, Digest: strings.Repeat("b", 64), RuntimeVerified: true, PersistenceVerified: true}
	return a.snapshot, nil
}

func (a *vlanAuthorityTestAgent) ReleaseVLANAuthority(_ context.Context, id uint32, owner string) error {
	a.releases = append(a.releases, owner)
	if id != 100 {
		return errors.New("wrong VLAN")
	}
	if a.releaseErr != nil {
		return a.releaseErr
	}
	a.snapshot.OwnerID = ""
	if a.onRelease != nil {
		a.onRelease()
	}
	return nil
}

func authorityFixture(t *testing.T) (*api.SwitchVLAN, *api.Switch, *vlanAuthorityTestAgent, client.WithWatch, *SwitchVLANReconciler) {
	t.Helper()
	v, base, scheme := vlanFixture(t)
	v.UID = "vlan-owner-uid"
	v.Spec.ReconcilePolicy = api.VLANReconcilePolicyAuthoritative
	v.Spec.AdoptionDigest = strings.Repeat("a", 64)
	s := &api.Switch{ObjectMeta: metav1.ObjectMeta{Name: "leaf", UID: "switch-uid"}, Spec: api.SwitchSpec{Management: api.Management{Host: "192.0.2.10", Port: "50051"}}}
	a := &vlanAuthorityTestAgent{vlanTestAgent: base, snapshot: &agent.VLANAuthorityResult{
		VLAN:           &agent.VLAN{ID: 100, Members: []agent.VLANMember{{InterfaceName: "Ethernet0", TaggingMode: "tagged"}, {InterfaceName: "Ethernet4", TaggingMode: "tagged"}}},
		Digest:         v.Spec.AdoptionDigest,
		OwnershipKnown: true,
	}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(v).WithObjects(v, s).Build()
	r := vlanReconciler(c, a)
	r.APIReader, r.AllowAuthoritativeVLANs = c, true
	return v, s, a, c, r
}

func authorityReconcile(t *testing.T, r *SwitchVLANReconciler, v *api.SwitchVLAN) error {
	t.Helper()
	_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(v)})
	return err
}

func getAuthorityVLAN(t *testing.T, c client.Client, v *api.SwitchVLAN) *api.SwitchVLAN {
	t.Helper()
	got := &api.SwitchVLAN{}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(v), got); err != nil {
		t.Fatal(err)
	}
	return got
}

func acquireAuthority(t *testing.T, r *SwitchVLANReconciler, v *api.SwitchVLAN, a *vlanAuthorityTestAgent) {
	t.Helper()
	for range 4 {
		if err := authorityReconcile(t, r, v); err != nil {
			t.Fatal(err)
		}
		if len(a.requests) > 0 {
			return
		}
	}
	t.Fatal("authority was not acquired")
}

func TestSwitchVLANAuthorityLifecycle(t *testing.T) {
	t.Parallel()
	v, _, a, c, r := authorityFixture(t)
	if err := authorityReconcile(t, r, v); err != nil {
		t.Fatal(err)
	}
	if len(a.requests) != 0 {
		t.Fatal("wrote before persisting target binding and finalizer")
	}
	acquireAuthority(t, r, v, a)
	got := getAuthorityVLAN(t, c, v)
	if len(got.Finalizers) != 1 || got.Status.OwnerID != string(v.UID) || got.Status.TargetIdentity == "" || !got.Status.RuntimeVerified || !got.Status.PersistenceVerified {
		t.Fatalf("missing durable lifecycle/status: %#v", got)
	}
	if len(a.writes) != 0 || len(a.requests) != 1 || a.requests[0].OwnerID != string(v.UID) || !reflect.DeepEqual(a.requests[0].VLAN.Members, a.vlanTestAgent.response.Members) {
		t.Fatalf("must send complete desired membership via authority only: %#v", a.requests)
	}
	got.Spec.Members = nil
	got.Spec.AdoptionDigest = "" // ordinary edits must not require another adoption.
	if err := c.Update(t.Context(), got); err != nil {
		t.Fatal(err)
	}
	r = vlanReconciler(c, a) // controller restart must rediscover ownership.
	r.APIReader, r.AllowAuthoritativeVLANs = c, true
	if err := authorityReconcile(t, r, v); err != nil {
		t.Fatal(err)
	}
	if len(a.requests) != 2 || len(a.requests[1].VLAN.Members) != 0 {
		t.Fatal("empty membership did not request full pruning")
	}
	if !meta.IsStatusConditionTrue(getAuthorityVLAN(t, c, v).Status.Conditions, "Ready") {
		t.Fatal("not ready after persisted exact match")
	}
}

func TestSwitchVLANAuthorityGatesAndAdoption(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"Observe", "observe gate", "authority gate", "no adoption", "stale adoption", "new VLAN", "other owner", "missing reader", "empty UID", "implicit endpoint"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v, s, a, c, r := authorityFixture(t)
			got := getAuthorityVLAN(t, c, v)
			switch name {
			case "Observe":
				got.Spec.ManagementPolicy = api.VLANManagementPolicyObserve
			case "observe gate":
				r.ObserveOnly = true
			case "authority gate":
				r.AllowAuthoritativeVLANs = false
			case "no adoption":
				got.Spec.AdoptionDigest = ""
			case "stale adoption":
				got.Spec.AdoptionDigest = strings.Repeat("c", 64)
			case "new VLAN":
				got.Spec.AdoptionDigest = ""
				a.snapshot.VLAN = nil
			case "other owner":
				a.snapshot.OwnerID = "other-uid"
			case "missing reader":
				r.APIReader = nil
			case "empty UID":
				got.UID = ""
			case "implicit endpoint":
				s.Spec.Management = api.Management{}
				if err := c.Update(t.Context(), s); err != nil {
					t.Fatal(err)
				}
			}
			if err := c.Update(t.Context(), got); err != nil {
				t.Fatal(err)
			}
			for range 4 {
				_ = authorityReconcile(t, r, v)
			}
			if len(a.writes) != 0 {
				t.Fatal("authority fell through to additive")
			}
			if (len(a.requests) > 0) != (name == "new VLAN") {
				t.Fatalf("unexpected requests: %#v", a.requests)
			}
			if name == "no adoption" || name == "stale adoption" {
				got = getAuthorityVLAN(t, c, v)
				if got.Status.AdoptionDigest != a.snapshot.Digest || len(got.Finalizers) != 0 || meta.IsStatusConditionTrue(got.Status.Conditions, "Ready") {
					t.Fatalf("missing safe adoption preview: %#v", got)
				}
			}
		})
	}
}

func TestSwitchVLANAuthorityDeletion(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"Orphan", "Delete", "guard", "observe", "Observe policy", "foreign owner", "unowned", "read failure", "pending release", "save failure", "unconfirmed delete", "lost delete response"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v, _, a, c, r := authorityFixture(t)
			acquireAuthority(t, r, v, a)
			got := getAuthorityVLAN(t, c, v)
			before := a.snapshot.VLAN
			switch name {
			case "Delete", "save failure", "unconfirmed delete", "lost delete response":
				got.Spec.DeletionPolicy = api.VLANDeletionPolicyDelete
			case "guard":
				r.AllowAuthoritativeVLANs = false
			case "observe":
				r.ObserveOnly = true
			case "Observe policy":
				got.Spec.ManagementPolicy = api.VLANManagementPolicyObserve
			case "foreign owner":
				a.snapshot.OwnerID = "someone-else"
			case "unowned":
				a.snapshot.OwnerID = ""
			case "read failure":
				a.getErr = errors.New("offline")
			case "pending release":
				a.releaseErr = errors.New("persistence pending")
			}
			if name == "save failure" {
				a.reconcileErr = errors.New("save failed")
			}
			if name == "unconfirmed delete" {
				a.response = &agent.VLANAuthorityResult{OwnerID: string(v.UID), OwnershipKnown: true, Digest: strings.Repeat("b", 64)}
			}
			if name == "lost delete response" {
				a.snapshot.VLAN = nil
			}
			if err := c.Update(t.Context(), got); err != nil {
				t.Fatal(err)
			}
			if err := c.Delete(t.Context(), got); err != nil {
				t.Fatal(err)
			}
			writes := len(a.requests)
			err := authorityReconcile(t, r, v)
			removed := name == "Orphan" || name == "Delete" || name == "unowned" || name == "lost delete response"
			if (err == nil) != removed {
				t.Fatalf("error=%v, removed=%v", err, removed)
			}
			lookup := c.Get(t.Context(), client.ObjectKeyFromObject(v), &api.SwitchVLAN{})
			if apierrors.IsNotFound(lookup) != removed {
				t.Fatalf("unexpected finalizer lifecycle: %v", lookup)
			}
			deleteCalled := name == "Delete" || name == "save failure" || name == "unconfirmed delete" || name == "lost delete response"
			if (len(a.requests) > writes) != deleteCalled {
				t.Fatalf("unexpected deletion requests: %#v", a.requests)
			}
			if deleteCalled && (!a.requests[writes].Delete || a.requests[writes].OwnerID != string(v.UID)) {
				t.Fatal("delete not UID scoped")
			}
			if name == "Orphan" && (len(a.releases) != 1 || a.releases[0] != string(v.UID) || !reflect.DeepEqual(before, a.snapshot.VLAN)) {
				t.Fatal("Orphan must release only")
			}
			if name == "unowned" && len(a.releases) != 0 {
				t.Fatal("unowned deletion must not write")
			}
		})
	}
}

func TestSwitchVLANAuthorityFailsClosed(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"downshift", "owner disappeared", "binding disappeared", "endpoint changed", "switch recreated", "nil snapshot", "invalid digest", "wrong VLAN", "wrong response owner", "extra response members", "unverified persistence", "lost response", "duplicate claim", "endpoint alias claim", "deleted during read", "endpoint changed during read"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v, s, a, c, r := authorityFixture(t)
			acquireAuthority(t, r, v, a)
			got := getAuthorityVLAN(t, c, v)
			switch name {
			case "downshift":
				got.Spec.ReconcilePolicy = api.VLANReconcilePolicyAdditive
				if err := c.Update(t.Context(), got); err != nil {
					t.Fatal(err)
				}
			case "owner disappeared":
				a.snapshot.OwnerID = ""
			case "binding disappeared":
				delete(got.Annotations, vlanAuthorityTargetAnnotation)
				if err := c.Update(t.Context(), got); err != nil {
					t.Fatal(err)
				}
				a.snapshot.OwnerID = ""
				got.Status.OwnerID, got.Status.TargetIdentity = "", ""
				if err := c.Status().Update(t.Context(), got); err != nil {
					t.Fatal(err)
				}
			case "endpoint changed":
				s.Spec.Management.Host = "192.0.2.20"
				if err := c.Update(t.Context(), s); err != nil {
					t.Fatal(err)
				}
			case "switch recreated":
				s.UID = "replacement"
				if err := c.Update(t.Context(), s); err != nil {
					t.Fatal(err)
				}
			case "nil snapshot":
				a.snapshot = nil
			case "invalid digest":
				a.snapshot.Digest = ""
			case "wrong VLAN":
				a.snapshot.VLAN.ID = 200
			case "wrong response owner":
				response := *a.snapshot
				response.OwnerID = "other"
				a.response = &response
			case "extra response members":
				response := *a.snapshot
				response.VLAN = &agent.VLAN{ID: 100, Members: append(append([]agent.VLANMember{}, a.snapshot.VLAN.Members...), agent.VLANMember{InterfaceName: "Ethernet4", TaggingMode: "tagged"})}
				a.response = &response
			case "unverified persistence":
				response := *a.snapshot
				response.PersistenceVerified = false
				a.response = &response
			case "lost response":
				a.reconcileErr = errors.New("response lost after apply")
			case "duplicate claim":
				other := v.DeepCopy()
				other.Name = "other"
				other.UID = "other"
				other.ResourceVersion = ""
				if err := c.Create(t.Context(), other); err != nil {
					t.Fatal(err)
				}
			case "endpoint alias claim":
				alias := s.DeepCopy()
				alias.Name, alias.UID, alias.ResourceVersion = "alias", "alias-uid", ""
				if err := c.Create(t.Context(), alias); err != nil {
					t.Fatal(err)
				}
				other := v.DeepCopy()
				other.Name, other.UID, other.ResourceVersion, other.Spec.SwitchRef.Name = "other", "other", "", "alias"
				if err := c.Create(t.Context(), other); err != nil {
					t.Fatal(err)
				}
			case "deleted during read":
				a.onAuthorityRead = func() {
					if err := c.Delete(t.Context(), got); err != nil {
						t.Fatal(err)
					}
				}
			case "endpoint changed during read":
				a.onAuthorityRead = func() {
					s.Spec.Management.Host = "192.0.2.20"
					if err := c.Update(t.Context(), s); err != nil {
						t.Fatal(err)
					}
				}
			}
			writes := len(a.requests)
			if err := authorityReconcile(t, r, v); err == nil {
				t.Fatal("expected fail closed")
			}
			postWriteFailure := name == "wrong response owner" || name == "extra response members" || name == "unverified persistence" || name == "lost response"
			if (len(a.requests) > writes) != postWriteFailure || len(a.writes) != 0 {
				t.Fatalf("unsafe writes: %#v", a.requests)
			}
			got = getAuthorityVLAN(t, c, v)
			// A concurrent API deletion also conflicts with the optimistic status
			// patch. Preserve the error rather than overwriting newer API state.
			if (name != "deleted during read" && meta.IsStatusConditionTrue(got.Status.Conditions, "Ready")) || len(got.Finalizers) != 1 {
				t.Fatalf("failure lost finalizer or reported success: %#v", got)
			}
		})
	}
}

func TestSwitchVLANAuthorityLiveDeletion(t *testing.T) {
	t.Parallel()
	v, _, a, c, r := authorityFixture(t)
	acquireAuthority(t, r, v, a)
	cached := getAuthorityVLAN(t, c, v)
	if err := c.Delete(t.Context(), cached); err != nil {
		t.Fatal(err)
	}
	r.Client = interceptor.NewClient(c, interceptor.Funcs{Get: func(ctx context.Context, underlying client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
		if got, ok := obj.(*api.SwitchVLAN); ok {
			cached.DeepCopyInto(got)
			return nil
		}
		return underlying.Get(ctx, key, obj, opts...)
	}})
	writes := len(a.requests)
	if err := authorityReconcile(t, r, v); err != nil {
		t.Fatal(err)
	}
	if len(a.requests) != writes || len(a.releases) != 1 {
		t.Fatal("live deletion must release, never reapply stale cached spec")
	}
}

func TestSwitchVLANAuthorityRecoveryAfterLostStatus(t *testing.T) {
	t.Parallel()
	v, _, a, c, r := authorityFixture(t)
	if err := authorityReconcile(t, r, v); err != nil {
		t.Fatal(err)
	}
	r.Client = interceptor.NewClient(c, interceptor.Funcs{SubResourcePatch: func(context.Context, client.Client, string, client.Object, client.Patch, ...client.SubResourcePatchOption) error {
		return errors.New("status unavailable")
	}})
	if err := authorityReconcile(t, r, v); err == nil {
		t.Fatal("expected status failure")
	}
	if a.snapshot.OwnerID != string(v.UID) {
		t.Fatal("agent did not acquire ownership")
	}
	r.Client = c
	if err := authorityReconcile(t, r, v); err != nil {
		t.Fatal(err)
	}
	if getAuthorityVLAN(t, c, v).Status.OwnerID != string(v.UID) {
		t.Fatal("owner not recovered via agent read")
	}
}

func TestSwitchVLANAuthorityMetadataFailurePreventsWrite(t *testing.T) {
	t.Parallel()
	v, _, a, c, r := authorityFixture(t)
	r.Client = interceptor.NewClient(c, interceptor.Funcs{Patch: func(context.Context, client.WithWatch, client.Object, client.Patch, ...client.PatchOption) error {
		return errors.New("finalizer unavailable")
	}})
	if err := authorityReconcile(t, r, v); err == nil {
		t.Fatal("expected metadata failure")
	}
	if len(a.requests) != 0 || len(getAuthorityVLAN(t, c, v).Finalizers) != 0 {
		t.Fatal("write without durable finalizer")
	}
}

func TestSwitchVLANAuthorityDeleteRetry(t *testing.T) {
	t.Parallel()
	v, _, a, c, r := authorityFixture(t)
	acquireAuthority(t, r, v, a)
	got := getAuthorityVLAN(t, c, v)
	got.Spec.DeletionPolicy = api.VLANDeletionPolicyDelete
	if err := c.Update(t.Context(), got); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(t.Context(), got); err != nil {
		t.Fatal(err)
	}
	a.snapshot.VLAN = nil
	a.snapshot.PersistenceVerified = false
	a.reconcileErr = errors.New("save failed after removal")
	if err := authorityReconcile(t, r, v); err == nil {
		t.Fatal("expected persistence failure")
	}
	if len(getAuthorityVLAN(t, c, v).Finalizers) != 1 || len(a.releases) != 0 {
		t.Fatal("premature release")
	}
	a.reconcileErr = nil
	r = vlanReconciler(c, a)
	r.APIReader, r.AllowAuthoritativeVLANs = c, true
	if err := authorityReconcile(t, r, v); err != nil {
		t.Fatal(err)
	}
	if len(a.requests) != 3 || len(a.releases) != 1 {
		t.Fatal("absent VLAN skipped persistence retry")
	}
}

func TestSwitchVLANAdditiveDoesNotQueryAuthority(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"old agent RPC unavailable", "strict snapshot rejected", "backend owner guard"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v, _, a, c, r := authorityFixture(t)
			got := getAuthorityVLAN(t, c, v)
			got.Spec.ReconcilePolicy = api.VLANReconcilePolicyAdditive
			if err := c.Update(t.Context(), got); err != nil {
				t.Fatal(err)
			}
			a.getErr = errors.New(name)
			a.onAuthorityRead = func() { t.Error("additive reconciliation must not query authority") }
			if name == "backend owner guard" {
				a.writeErr = errors.New("EnsureVLAN rejected owned VLAN")
			}
			err := authorityReconcile(t, r, v)
			if !errors.Is(err, a.writeErr) {
				t.Fatalf("unexpected ensure result: %v", err)
			}
			if len(a.writes) != 1 || len(a.requests) != 0 {
				t.Fatal("must use additive EnsureVLAN only")
			}
		})
	}
}

func TestSwitchVLANAuthorityUnknownOwnership(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"adoption", "new VLAN", "Observe preview", "owned reconcile", "reconcile response", "Orphan after restart without journal", "Delete after restart without journal", "delete response", "release confirmation"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v, _, a, c, r := authorityFixture(t)
			owned := name != "adoption" && name != "new VLAN" && name != "Observe preview"
			if owned {
				acquireAuthority(t, r, v, a)
			}
			got := getAuthorityVLAN(t, c, v)
			deleting := strings.Contains(name, "restart") || name == "delete response" || name == "release confirmation"
			if name == "Observe preview" {
				got.Spec.ManagementPolicy = api.VLANManagementPolicyObserve
			}
			if strings.HasPrefix(name, "Delete") || name == "delete response" {
				got.Spec.DeletionPolicy = api.VLANDeletionPolicyDelete
			}
			if err := c.Update(t.Context(), got); err != nil {
				t.Fatal(err)
			}
			if deleting {
				if err := c.Delete(t.Context(), got); err != nil {
					t.Fatal(err)
				}
			}
			switch name {
			case "reconcile response", "delete response":
				response := *a.snapshot
				response.OwnershipKnown = false
				if name == "delete response" {
					response.VLAN = nil
				}
				a.response = &response
			case "release confirmation":
				a.onRelease = func() { a.snapshot.OwnershipKnown = false }
			default:
				a.snapshot.OwnershipKnown = false
				if name != "owned reconcile" {
					a.snapshot.OwnerID = ""
				}
				if name == "new VLAN" {
					a.snapshot.VLAN = nil
				}
			}
			writes := len(a.requests)
			err := authorityReconcile(t, r, v)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), "ownership") {
				t.Fatalf("expected actionable unknown ownership error, got %v", err)
			}
			got = getAuthorityVLAN(t, c, v)
			if (len(got.Finalizers) == 1) != owned {
				t.Fatal("unknown ownership changed finalizer lifecycle")
			}
			if owned && got.Status.OwnerID != string(v.UID) {
				t.Fatal("unknown snapshot erased last confirmed owner")
			}
			if got.Status.AdoptionDigest != a.snapshot.Digest || got.Status.Exists == nil {
				t.Fatal("unknown ownership discarded valid read preview")
			}
			if name == "Observe preview" && len(got.Status.Members) != len(a.snapshot.VLAN.Members) {
				t.Fatal("preview lost observed members")
			}
			for _, condition := range []string{"Ready", "Synced"} {
				if !meta.IsStatusConditionFalse(got.Status.Conditions, condition) {
					t.Fatalf("unknown ownership reported %s success", condition)
				}
			}
			postWrite := name == "reconcile response" || name == "delete response"
			if (len(a.requests) > writes) != postWrite {
				t.Fatal("unknown ownership permitted a mutation")
			}
			if (len(a.releases) == 1) != (name == "release confirmation") {
				t.Fatal("unknown ownership permitted release")
			}
		})
	}
}
