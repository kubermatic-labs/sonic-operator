// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	agentclient "github.com/ironcore-dev/sonic-operator/internal/agent/agent_client/client"
	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
	switchutil "github.com/ironcore-dev/sonic-operator/internal/switch_util"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

type HostReconciler struct {
	client.Client
	APIReader       client.Reader
	Kind            string
	ObserveOnly     bool
	AllowHostConfig bool
	NewAgentClient  func(context.Context, client.Reader, *corev1.LocalObjectReference, string) (agentclient.SwitchAgentClient, error)
}

// +kubebuilder:rbac:groups=sonic.networking.metal.ironcore.dev,resources=switchmanagements;switchsystems,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups=sonic.networking.metal.ironcore.dev,resources=switchmanagements/status;switchsystems/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=sonic.networking.metal.ironcore.dev,resources=switches,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get

func (r *HostReconciler) Reconcile(ctx context.Context, key ctrl.Request) (result ctrl.Result, retErr error) {
	if r.APIReader == nil {
		return result, fmt.Errorf("host resources require uncached APIReader")
	}
	obj, _, err := hostObjects(r.Kind)
	if err != nil {
		return result, err
	}
	if err = r.APIReader.Get(ctx, key.NamespacedName, obj); err != nil {
		return result, client.IgnoreNotFound(err)
	}
	// Deletion is Orphan. Pending management transactions are independently
	// rolled back by the local watchdog even after the Kubernetes object is gone.
	if !obj.GetDeletionTimestamp().IsZero() {
		return result, nil
	}
	common, st := hostFields(obj)
	original := obj.DeepCopyObject().(client.Object)
	*st = api.HostResourceStatus{ObservedGeneration: obj.GetGeneration(), Conditions: append([]metav1.Condition{}, st.Conditions...)}
	observed := host.Result{}
	managed := false
	defer func() {
		st.ConfigurationVerified = observed.ConfigurationVerified
		st.RuntimeVerified = observed.RuntimeVerified
		st.PersistenceVerified = observed.PersistenceVerified
		st.GatewayVerified = observed.GatewayVerified
		st.Recovery = observed.Recovery
		for _, v := range []struct {
			name string
			ok   bool
		}{{"Ready", managed && observed.Ready()}, {"ConfigurationReady", observed.ConfigurationVerified}, {"RuntimeReady", observed.RuntimeVerified}, {"PersistenceReady", observed.PersistenceVerified}, {"RecoveryReady", observed.Recovery != "Pending" && observed.Recovery != "RollbackRequired" && observed.Recovery != ""}} {
			state := metav1.ConditionFalse
			reason, message := "Unverified", "Host evidence is incomplete"
			if retErr != nil {
				reason = "HostOperationFailed"
				message = "Typed host configuration could not be verified"
			} else if v.ok {
				state = metav1.ConditionTrue
				reason = "Verified"
				message = "Independent host evidence verified"
			}
			meta.SetStatusCondition(&st.Conditions, metav1.Condition{Type: v.name, Status: state, Reason: reason, Message: message, ObservedGeneration: obj.GetGeneration()})
		}
		_, oldStatus := hostFields(original)
		if reflect.DeepEqual(*oldStatus, *st) {
			return
		}
		if e := r.Status().Patch(ctx, obj, client.MergeFromWithOptions(original, client.MergeFromWithOptimisticLock{})); e != nil && retErr == nil {
			retErr = e
		}
	}()
	result.RequeueAfter = 30 * time.Second
	sw := &api.Switch{}
	if r.APIReader.Get(ctx, client.ObjectKey{Name: common.SwitchRef.Name}, sw) != nil {
		return result, fmt.Errorf("host Switch reference unavailable")
	}
	port, e := strconv.Atoi(sw.Spec.Management.Port)
	if e != nil || port < 1 || port > 65535 || sw.UID == "" || sw.Spec.MacAddress == "" || sw.Spec.Management.Host == "" || !sw.DeletionTimestamp.IsZero() {
		return result, fmt.Errorf("host target identity and endpoint required")
	}
	q, secretFresh, err := r.hostDesired(ctx, obj, string(sw.UID))
	if err != nil {
		return result, err
	}
	write := r.AllowHostConfig && !r.ObserveOnly && common.ManagementPolicy == api.NetworkManagementPolicyManage
	if err = r.checkHostClaims(ctx, obj, common.SwitchRef.Name); err != nil {
		return result, err
	}
	bound := bindingForHost(sw)
	saved := obj.GetAnnotations()[hostBindingAnnotation]
	if saved != "" {
		var prior hostBinding
		if json.Unmarshal([]byte(saved), &prior) != nil || !sameHostIdentity(prior, bound) || (prior.Host != bound.Host && candidateHost(q, prior.Host) != bound.Host) {
			return result, fmt.Errorf("host target binding changed")
		}
	}
	if write && saved == "" {
		patch := client.MergeFromWithOptions(obj.DeepCopyObject().(client.Object), client.MergeFromWithOptimisticLock{})
		annotations := obj.GetAnnotations()
		if annotations == nil {
			annotations = map[string]string{}
		}
		annotations[hostBindingAnnotation] = encodeHostBinding(bound)
		obj.SetAnnotations(annotations)
		if err = r.Patch(ctx, obj, patch); err != nil {
			return result, err
		}
		original = obj.DeepCopyObject().(client.Object)
		return ctrl.Result{RequeueAfter: time.Second}, nil
	}
	fresh := func() error {
		latest := obj.DeepCopyObject().(client.Object)
		if r.APIReader.Get(ctx, client.ObjectKeyFromObject(obj), latest) != nil || latest.GetUID() != obj.GetUID() || latest.GetGeneration() != obj.GetGeneration() || latest.GetResourceVersion() != obj.GetResourceVersion() || !latest.GetDeletionTimestamp().IsZero() {
			return fmt.Errorf("host declaration changed before write")
		}
		latestSW := &api.Switch{}
		if r.APIReader.Get(ctx, client.ObjectKeyFromObject(sw), latestSW) != nil || !reflect.DeepEqual(latestSW.Spec, sw.Spec) || latestSW.UID != sw.UID || !latestSW.DeletionTimestamp.IsZero() {
			return fmt.Errorf("host Switch changed before write")
		}
		if r.checkHostClaims(ctx, obj, common.SwitchRef.Name) != nil {
			return host.ErrConflict
		}
		return secretFresh()
	}
	a, nc, err := r.hostClient(ctx, sw, sw.Spec.Management.Host)
	if err != nil && q.Kind == "Management" && candidateHost(q, sw.Spec.Management.Host) != sw.Spec.Management.Host {
		a, nc, err = r.hostClient(ctx, sw, candidateHost(q, sw.Spec.Management.Host))
	}
	if err != nil {
		return result, err
	}
	defer closeAgentClient(a)
	observed, err = nc.GetHost(ctx, q)
	if err != nil {
		return result, err
	}
	if !write {
		return result, nil
	}
	if err = fresh(); err != nil {
		return result, err
	}
	observed, err = nc.EnsureHost(ctx, q)
	if err != nil {
		return result, err
	}
	if observed.Recovery == "Pending" {
		// The first transport must close before obtaining native readback and
		// confirmation on a newly authenticated connection at the desired address.
		if err = closeAgentClient(a); err != nil {
			return result, err
		}
		freshAgent, freshHost, e := r.hostClient(ctx, sw, candidateHost(q, sw.Spec.Management.Host))
		if e != nil {
			return result, e
		}
		defer closeAgentClient(freshAgent)
		observed, e = freshHost.GetHost(ctx, q)
		if e != nil {
			return result, e
		}
		if observed.Challenge == "" {
			return result, fmt.Errorf("fresh host runtime/gateway confirmation is incomplete")
		}
		if e = fresh(); e != nil {
			return result, e
		}
		observed, e = freshHost.ConfirmHost(ctx, host.Confirmation{Owner: q.Owner, Target: q.Target, Transaction: observed.Transaction, Challenge: observed.Challenge})
		if e != nil {
			return result, e
		}
	}
	managed = observed.Owner == q.Owner && observed.Ready()
	if managed && q.Kind == "Management" && candidateHost(q, sw.Spec.Management.Host) != sw.Spec.Management.Host {
		if err = fresh(); err != nil {
			return result, err
		}
		patch := client.MergeFromWithOptions(sw.DeepCopy(), client.MergeFromWithOptimisticLock{})
		sw.Spec.Management.Host = candidateHost(q, sw.Spec.Management.Host)
		if err = r.Patch(ctx, sw, patch); err != nil {
			return result, err
		}
	}
	if managed && q.Kind == "Management" && obj.GetAnnotations()[hostBindingAnnotation] != encodeHostBinding(bindingForHost(sw)) {
		patch := client.MergeFromWithOptions(obj.DeepCopyObject().(client.Object), client.MergeFromWithOptimisticLock{})
		annotations := obj.GetAnnotations()
		annotations[hostBindingAnnotation] = encodeHostBinding(bindingForHost(sw))
		obj.SetAnnotations(annotations)
		if err = r.Patch(ctx, obj, patch); err != nil {
			return result, err
		}
		original = obj.DeepCopyObject().(client.Object)
	}
	return result, nil
}
func (r *HostReconciler) hostClient(ctx context.Context, sw *api.Switch, address string) (agentclient.SwitchAgentClient, agentclient.HostClient, error) {
	factory := r.NewAgentClient
	if factory == nil {
		factory = switchutil.NewAgentClientFromSwitchRef
	}
	target := sw.DeepCopy()
	target.Spec.Management.Host = address
	a, e := factory(ctx, networkBoundReader{Reader: r.APIReader, target: target}, &corev1.LocalObjectReference{Name: sw.Name}, "")
	if e != nil || a == nil {
		return nil, nil, fmt.Errorf("host agent connection unavailable")
	}
	nc, ok := a.(agentclient.HostClient)
	if !ok {
		_ = closeAgentClient(a)
		return nil, nil, fmt.Errorf("host agent capability unavailable")
	}
	d, e := a.GetDeviceInfo(ctx)
	if e != nil || d == nil || !strings.EqualFold(d.LocalMacAddress, sw.Spec.MacAddress) {
		_ = closeAgentClient(a)
		return nil, nil, fmt.Errorf("host agent identity mismatch")
	}
	return a, nc, nil
}
func (r *HostReconciler) checkHostClaims(ctx context.Context, obj client.Object, sw string) error {
	_, list, e := hostObjects(r.Kind)
	if e != nil {
		return e
	}
	if r.APIReader.List(ctx, list) != nil {
		return host.ErrConflict
	}
	var items []client.Object
	switch l := list.(type) {
	case *api.SwitchManagementList:
		for i := range l.Items {
			items = append(items, &l.Items[i])
		}
	case *api.SwitchSystemList:
		for i := range l.Items {
			items = append(items, &l.Items[i])
		}
	}
	for _, other := range items {
		common, _ := hostFields(other)
		if other.GetUID() != obj.GetUID() && common.SwitchRef.Name == sw {
			return host.ErrConflict
		}
	}
	return nil
}
func (r *HostReconciler) SetupWithManager(mgr ctrl.Manager) error {
	obj, _, e := hostObjects(r.Kind)
	if e != nil {
		return e
	}
	return ctrl.NewControllerManagedBy(mgr).Named("host-" + strings.ToLower(r.Kind)).For(obj).WithEventFilter(predicate.GenerationChangedPredicate{}).Complete(r)
}
