// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	agentclient "github.com/ironcore-dev/sonic-operator/internal/agent/agent_client/client"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	switchutil "github.com/ironcore-dev/sonic-operator/internal/switch_util"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	networkTargetAnnotation  = "sonic.networking.metal.ironcore.dev/network-target"
	networkRequestAnnotation = "sonic.networking.metal.ironcore.dev/network-request"
	networkRecoveryFinalizer = "sonic.networking.metal.ironcore.dev/network-recovery"
)

// NetworkReconciler shares safety checks but accepts only the eight known kinds.
// Deletion is Orphan after the recovery finalizer confirms no unsaved operation.
type NetworkReconciler struct {
	client.Client
	APIReader          client.Reader
	Kind               string
	ObserveOnly        bool
	AllowNetworkConfig bool
	AllowFRRMigration  bool
	NewAgentClient     func(context.Context, client.Reader, *corev1.LocalObjectReference, string) (agentclient.SwitchAgentClient, error)
}

// +kubebuilder:rbac:groups=sonic.networking.metal.ironcore.dev,resources=switchportchannels;switchvrfs;switchl3interfaces;switchstaticroutes;switchbgps;switchbgppeers;switchdhcprelays;switchfrrmigrations,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups=sonic.networking.metal.ironcore.dev,resources=switchportchannels/status;switchvrfs/status;switchl3interfaces/status;switchstaticroutes/status;switchbgps/status;switchbgppeers/status;switchdhcprelays/status;switchfrrmigrations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=sonic.networking.metal.ironcore.dev,resources=switchportchannels/finalizers;switchvrfs/finalizers;switchl3interfaces/finalizers;switchstaticroutes/finalizers;switchbgps/finalizers;switchbgppeers/finalizers;switchdhcprelays/finalizers;switchfrrmigrations/finalizers,verbs=update;patch
// +kubebuilder:rbac:groups=sonic.networking.metal.ironcore.dev,resources=switches,verbs=get;list;watch

func (r *NetworkReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, retErr error) {
	if r.APIReader == nil {
		return result, fmt.Errorf("network resources require an uncached APIReader")
	}
	obj, _, err := networkObjects(r.Kind)
	if err != nil {
		return result, err
	}
	if err := r.APIReader.Get(ctx, req.NamespacedName, obj); err != nil {
		return result, client.IgnoreNotFound(err)
	}
	if !obj.GetDeletionTimestamp().IsZero() {
		if !controllerutil.ContainsFinalizer(obj, networkRecoveryFinalizer) {
			return result, nil
		}
		if err := r.recoverNetwork(ctx, obj); err != nil {
			return ctrl.Result{}, r.networkRecoveryFailed(ctx, obj, err)
		}
		patch := client.MergeFromWithOptions(obj.DeepCopyObject().(client.Object), client.MergeFromWithOptimisticLock{})
		controllerutil.RemoveFinalizer(obj, networkRecoveryFinalizer)
		return result, r.Patch(ctx, obj, patch)
	}
	original := obj.DeepCopyObject().(client.Object)
	_, status, common := networkFields(obj)
	_, oldStatus, _ := networkFields(original)
	status.ObservedGeneration = obj.GetGeneration()
	status.Exists, status.ConfigurationVerified, status.RuntimeVerified, status.PersistenceVerified = false, false, false, false
	status.Observed.Raw = nil
	status.Observed.Object = nil
	observed := false
	reason, message := "ObservationFailed", "Network observation could not be verified"
	defer func() {
		if retErr != nil {
			message = retErr.Error()
		}
		for _, condition := range []struct {
			name     string
			verified bool
		}{
			{"Ready", status.Exists && status.ConfigurationVerified && status.RuntimeVerified && status.PersistenceVerified},
			{"Synced", status.ConfigurationVerified && status.PersistenceVerified},
			{"ConfigurationReady", status.ConfigurationVerified}, {"RuntimeReady", status.RuntimeVerified}, {"PersistenceReady", status.PersistenceVerified},
		} {
			state := metav1.ConditionUnknown
			if observed && retErr == nil {
				state = metav1.ConditionFalse
				if condition.verified {
					state = metav1.ConditionTrue
				}
			} else if observed && condition.verified && condition.name != "Ready" && condition.name != "Synced" {
				state = metav1.ConditionTrue
			}
			meta.SetStatusCondition(&status.Conditions, metav1.Condition{Type: condition.name, Status: state, Reason: reason, Message: message, ObservedGeneration: obj.GetGeneration()})
		}
		if !reflect.DeepEqual(oldStatus, status) {
			if err := r.Status().Patch(ctx, obj, client.MergeFromWithOptions(original, client.MergeFromWithOptimisticLock{})); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("update network status: %w", err))
			}
		}
	}()
	result.RequeueAfter = time.Minute
	// Resolve the recorded operation before validating a newer desired spec.
	// Recovery never applies that newer spec or replaces durable ownership.
	if controllerutil.ContainsFinalizer(obj, networkRecoveryFinalizer) {
		if err := r.recoverNetwork(ctx, obj); err != nil {
			reason = "RecoveryBlocked"
			return result, err
		}
	}
	desired, target, err := networkDesired(r.Kind, obj)
	if err != nil {
		reason = "InvalidConfiguration"
		return result, err
	}
	sw := &api.Switch{}
	if err := r.APIReader.Get(ctx, client.ObjectKey{Name: common.SwitchRef.Name}, sw); err != nil {
		return result, err
	}
	port, err := strconv.Atoi(sw.Spec.Management.Port)
	if sw.UID == "" || !sw.DeletionTimestamp.IsZero() || sw.Spec.Management.Host == "" || err != nil || port < 1 || port > 65535 {
		return result, fmt.Errorf("a live Switch UID and explicit agent endpoint are required")
	}
	binding := networkBinding(obj, sw, r.Kind, target)
	if saved := obj.GetAnnotations()[networkTargetAnnotation]; saved != "" && saved != binding {
		reason = "TargetChanged"
		return result, fmt.Errorf("Switch identity, endpoint or target binding changed; restore the original target")
	}
	if err := r.checkNetworkClaims(ctx, obj, sw, target); err != nil {
		reason = "ConflictingClaim"
		return result, err
	}
	factory := r.NewAgentClient
	if factory == nil {
		factory = switchutil.NewAgentClientFromSwitchRef
	}
	a, err := factory(ctx, networkBoundReader{Reader: r.APIReader, target: sw}, &corev1.LocalObjectReference{Name: sw.Name}, "")
	if err != nil {
		return result, err
	}
	if a == nil || (reflect.ValueOf(a).Kind() == reflect.Pointer && reflect.ValueOf(a).IsNil()) {
		return result, fmt.Errorf("agent client is nil")
	}
	defer func() { retErr = errors.Join(retErr, closeAgentClient(a)) }()
	nc, ok := a.(agentclient.NetworkClient)
	if !ok {
		return result, fmt.Errorf("agent client does not support network resources")
	}
	readCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	current, err := nc.GetNetworkResource(readCtx, desired)
	cancel()
	if err != nil {
		// A failed runtime probe can still carry independent configuration/save
		// proof. Preserve it without allowing a failed observation to cause writes.
		if current != nil && observeNetwork(status, current) == nil {
			observed = true
		}
		return result, fmt.Errorf("observe network resource: %w", err)
	}
	if err := observeNetwork(status, current); err != nil {
		return result, err
	}
	observed = true
	reason, message = "Observed", current.Message
	if message == "" {
		message = "Configuration, runtime and persistence are reported independently"
	}
	if r.networkWritesDisabled(common) {
		reason = "WritesDisabled"
		return result, nil
	}
	// A matching running config without durable save proof still needs Ensure.
	// Runtime failure alone must not cause repeated configuration writes.
	if current.Exists && current.ConfigurationVerified && current.PersistenceVerified {
		return result, nil
	}
	if migration, ok := obj.(*api.SwitchFRRMigration); ok {
		if err := approveNetworkFRRMigration(migration, sw, current); err != nil {
			reason = "ApprovalRequired"
			return result, err
		}
	}
	if _, ok := a.(agentclient.NetworkRecoveryClient); !ok {
		reason = "RecoveryUnsupported"
		return result, fmt.Errorf("agent client must support network recovery before Ensure")
	}
	if err := r.checkNetworkClaims(ctx, obj, sw, target); err != nil {
		reason = "ConflictingClaim"
		return result, err
	}
	if err := r.checkNetworkCurrent(ctx, obj, sw, target); err != nil {
		reason = "TargetChanged"
		return result, err
	}
	if obj.GetAnnotations()[networkTargetAnnotation] == "" || !controllerutil.ContainsFinalizer(obj, networkRecoveryFinalizer) || obj.GetAnnotations()[networkRequestAnnotation] != string(desired.Spec) {
		patch := client.MergeFromWithOptions(obj.DeepCopyObject().(client.Object), client.MergeFromWithOptimisticLock{})
		annotations := obj.GetAnnotations()
		if annotations == nil {
			annotations = map[string]string{}
		}
		annotations[networkTargetAnnotation] = binding
		annotations[networkRequestAnnotation] = string(desired.Spec)
		obj.SetAnnotations(annotations)
		controllerutil.AddFinalizer(obj, networkRecoveryFinalizer)
		if err := r.Patch(ctx, obj, patch); err != nil {
			return result, err
		}
		original.SetResourceVersion(obj.GetResourceVersion())
		reason, message = "TargetBound", "Target, request and recovery finalizer persisted; retry before writing"
		return ctrl.Result{RequeueAfter: time.Second}, nil
	}
	// Once Ensure starts, the pre-write snapshot no longer proves current state.
	observed = false
	status.Exists, status.ConfigurationVerified, status.RuntimeVerified, status.PersistenceVerified = false, false, false, false
	status.Observed.Raw = nil
	writeCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	response, err := nc.EnsureNetworkResource(writeCtx, desired)
	cancel()
	if err != nil {
		if response != nil && observeNetwork(status, response) == nil {
			observed = true
		}
		reason = "WriteOutcomeUnknown"
		return result, fmt.Errorf("ensure network resource (outcome may be pending): %w", err)
	}
	if err := observeNetwork(status, response); err != nil {
		return result, err
	}
	observed = true
	reason, message = "Reconciled", response.Message
	if message == "" {
		message = "Agent completed additive reconciliation; verification results are independent"
	}
	return result, nil
}

func observeNetwork(status *api.NetworkResourceStatus, result *agent.NetworkResult) error {
	if result == nil {
		return fmt.Errorf("agent returned a nil network result")
	}
	var object map[string]json.RawMessage
	if len(result.Observed) != 0 {
		if err := json.Unmarshal(result.Observed, &object); err != nil || object == nil {
			return fmt.Errorf("agent observation must be a JSON object")
		}
	}
	status.Exists = result.Exists
	status.ConfigurationVerified = result.ConfigurationVerified
	status.RuntimeVerified = result.RuntimeVerified
	status.PersistenceVerified = result.PersistenceVerified
	status.Observed.Raw = append([]byte(nil), result.Observed...)
	return nil
}

func (r *NetworkReconciler) SetupWithManager(mgr ctrl.Manager) error {
	obj, _, err := networkObjects(r.Kind)
	if err != nil {
		return err
	}
	if r.APIReader == nil {
		r.APIReader = mgr.GetAPIReader()
	}
	return ctrl.NewControllerManagedBy(mgr).For(obj).
		Watches(&api.Switch{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, sw client.Object) []reconcile.Request {
			_, list, _ := networkObjects(r.Kind)
			if err := r.List(ctx, list); err != nil {
				ctrl.LoggerFrom(ctx).Error(err, "list network claims for switch event")
				return nil
			}
			var requests []reconcile.Request
			_ = meta.EachListItem(list, func(item runtime.Object) error {
				obj := item.(client.Object)
				_, _, common := networkFields(obj)
				if common.SwitchRef.Name == sw.GetName() {
					requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(obj)})
				}
				return nil
			})
			return requests
		})).WithEventFilter(predicate.Or(predicate.GenerationChangedPredicate{}, predicate.Funcs{UpdateFunc: func(e event.UpdateEvent) bool {
		return !e.ObjectOld.GetDeletionTimestamp().Equal(e.ObjectNew.GetDeletionTimestamp()) || !reflect.DeepEqual(e.ObjectOld.GetFinalizers(), e.ObjectNew.GetFinalizers())
	}})).Named("switch" + strings.ToLower(r.Kind)).Complete(r)
}
