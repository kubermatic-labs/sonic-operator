// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"time"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	agentclient "github.com/ironcore-dev/sonic-operator/internal/agent/agent_client/client"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	switchUtil "github.com/ironcore-dev/sonic-operator/internal/switch_util"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

var vlanEthernetName = regexp.MustCompile(`^(Ethernet(0|[1-9][0-9]*)|PortChannel(0|[1-9][0-9]{0,3}))$`)

// SwitchVLANReconciler observes VLANs and optionally adds configuration.
type SwitchVLANReconciler struct {
	client.Client
	// APIReader bypasses the cache for competing claims and pre-write checks.
	APIReader client.Reader
	// ObserveOnly disables device writes; the manager defaults this to true.
	ObserveOnly             bool
	AllowAuthoritativeVLANs bool
	NewAgentClient          func(context.Context, client.Reader, *corev1.LocalObjectReference, string) (agentclient.SwitchAgentClient, error)
}

// +kubebuilder:rbac:groups=sonic.networking.metal.ironcore.dev,resources=switchvlans,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=sonic.networking.metal.ironcore.dev,resources=switchvlans/finalizers,verbs=update
// +kubebuilder:rbac:groups=sonic.networking.metal.ironcore.dev,resources=switchvlans/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=sonic.networking.metal.ironcore.dev,resources=switches,verbs=get;list;watch

//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func (r *SwitchVLANReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, retErr error) {
	v := &api.SwitchVLAN{}
	if err := r.Get(ctx, req.NamespacedName, v); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if v.Spec.ReconcilePolicy == api.VLANReconcilePolicyAuthoritative || controllerutil.ContainsFinalizer(v, vlanAuthorityFinalizer) || v.Status.OwnerID != "" || v.Annotations[vlanAuthorityTargetAnnotation] != "" {
		return r.reconcileVLANAuthority(ctx, req)
	}
	if !v.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	original := v.DeepCopy()
	reason, message := "ReconcileError", "VLAN configuration could not be confirmed"
	synced := false
	v.Status.ObservedGeneration = v.Generation
	v.Status.Exists, v.Status.Members = nil, nil
	defer func() {
		state := metav1.ConditionFalse
		if retErr != nil {
			message = retErr.Error()
		} else if synced {
			state = metav1.ConditionTrue
		}
		for _, name := range []string{"Ready", "Synced"} {
			meta.SetStatusCondition(&v.Status.Conditions, metav1.Condition{
				Type: name, Status: state, Reason: reason, Message: message, ObservedGeneration: v.Generation,
			})
		}
		if !reflect.DeepEqual(original.Status, v.Status) {
			if err := r.Status().Patch(ctx, v, client.MergeFrom(original)); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("update SwitchVLAN status: %w", err))
			}
		}
	}()

	if v.Spec.SwitchRef.Name == "" || v.Spec.VLANID < 1 || v.Spec.VLANID > 4094 {
		return ctrl.Result{}, fmt.Errorf("SwitchVLAN requires a switch reference and VLAN ID in 1-4094")
	}
	if v.Spec.ReconcilePolicy != "" && v.Spec.ReconcilePolicy != api.VLANReconcilePolicyAdditive {
		return ctrl.Result{}, fmt.Errorf("invalid reconcile policy %q", v.Spec.ReconcilePolicy)
	}
	policy := v.Spec.ManagementPolicy
	if policy != "" && policy != api.VLANManagementPolicyObserve && policy != api.VLANManagementPolicyManage {
		return ctrl.Result{}, fmt.Errorf("invalid management policy %q", policy)
	}
	desired := &agent.VLAN{ID: v.Spec.VLANID}
	seen := make(map[string]bool, len(v.Spec.Members))
	for _, member := range v.Spec.Members {
		if !vlanEthernetName.MatchString(member.InterfaceName) || (member.TaggingMode != "tagged" && member.TaggingMode != "untagged") || seen[member.InterfaceName] {
			return ctrl.Result{}, fmt.Errorf("invalid or duplicate desired VLAN member %q with mode %q", member.InterfaceName, member.TaggingMode)
		}
		seen[member.InterfaceName] = true
		desired.Members = append(desired.Members, agent.VLANMember{InterfaceName: member.InterfaceName, TaggingMode: member.TaggingMode})
	}
	if err := r.checkVLANClaim(ctx, v); err != nil {
		reason = "ClaimConflict"
		return ctrl.Result{}, err
	}

	factory := r.NewAgentClient
	if factory == nil {
		factory = switchUtil.NewAgentClientFromSwitchRef
	}
	a, err := factory(ctx, r.Client, &corev1.LocalObjectReference{Name: v.Spec.SwitchRef.Name}, "")
	if err != nil {
		return ctrl.Result{}, err
	}
	if a == nil {
		return ctrl.Result{}, fmt.Errorf("agent client is nil")
	}
	defer func() {
		if err := closeAgentClient(a); err != nil {
			reason = "AgentCloseError"
			retErr = errors.Join(retErr, err)
		}
	}()
	vlanClient, ok := a.(agentclient.VLANClient)
	if !ok {
		return ctrl.Result{}, fmt.Errorf("agent client does not support VLAN operations")
	}
	current, err := vlanClient.GetVLAN(ctx, v.Spec.VLANID)
	if errors.Is(err, agentclient.ErrVLANNotFound) {
		v.Status.Exists = new(false)
		reason, message = "VLANNotFound", "VLAN does not exist on the switch"
	} else if err != nil {
		return ctrl.Result{}, fmt.Errorf("observe VLAN: %w", err)
	} else {
		synced, err = observeVLAN(v, current)
		if err != nil {
			return ctrl.Result{}, err
		}
		reason, message = "ConfigurationMismatch", "One or more desired members are missing"
	}
	if policy == api.VLANManagementPolicyManage && !r.ObserveOnly {
		// Matching Redis state does not prove SaveConfig succeeded. Ensure also
		// saves no-op configurations, making persistence retries restart-safe.
		// Recheck after the device read: never write for a CR deleted or changed
		// during that read, or for a claim hidden by a stale informer cache.
		if err := r.checkVLANClaim(ctx, v); err != nil {
			reason = "ClaimConflict"
			return ctrl.Result{}, err
		}
		updated, err := vlanClient.EnsureVLAN(ctx, desired)
		if err != nil {
			// A failed write may have partially applied. Do not report the old
			// observation as a confirmed post-write state.
			v.Status.Exists, v.Status.Members = nil, nil
			return ctrl.Result{}, fmt.Errorf("ensure VLAN: %w", err)
		}
		v.Status.Exists, v.Status.Members = nil, nil
		synced, err = observeVLAN(v, updated)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("confirm VLAN: %w", err)
		}
		if !synced {
			return ctrl.Result{}, fmt.Errorf("agent did not confirm desired VLAN configuration")
		}
	}
	if synced {
		reason, message = "ConfigurationConfirmed", "VLAN and all desired members are present; forwarding health is not checked"
	}
	return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
}

func (r *SwitchVLANReconciler) checkVLANClaim(ctx context.Context, v *api.SwitchVLAN) error {
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	latest := &api.SwitchVLAN{}
	if err := reader.Get(ctx, client.ObjectKeyFromObject(v), latest); err != nil {
		return fmt.Errorf("verify current VLAN claim: %w", err)
	}
	if !latest.DeletionTimestamp.IsZero() || latest.UID != v.UID || latest.Generation != v.Generation || !reflect.DeepEqual(latest.Spec, v.Spec) {
		return fmt.Errorf("VLAN claim changed or is being deleted; retry before contacting device")
	}
	claims := &api.SwitchVLANList{}
	if err := reader.List(ctx, claims); err != nil {
		return fmt.Errorf("list VLAN claims: %w", err)
	}
	for _, other := range claims.Items {
		if other.Name != v.Name && other.Spec.SwitchRef.Name == v.Spec.SwitchRef.Name && other.Spec.VLANID == v.Spec.VLANID {
			return fmt.Errorf("SwitchVLAN %q also claims switch %q VLAN %d; no device operations allowed", other.Name, v.Spec.SwitchRef.Name, v.Spec.VLANID)
		}
	}
	return nil
}

// observeVLAN compares only requested members, but records every observed member.
// Existing mode conflicts fail closed even in Observe mode; Ensure must never
// implement destructive replacement as a side effect of adding other members.
func observeVLAN(v *api.SwitchVLAN, current *agent.VLAN) (bool, error) {
	if current == nil || current.ID != v.Spec.VLANID {
		return false, fmt.Errorf("agent returned nil VLAN or unexpected VLAN identity")
	}
	members := make(map[string]string, len(current.Members))
	var observed []api.SwitchVLANObservedMember
	for _, member := range current.Members {
		if member.InterfaceName == "" || members[member.InterfaceName] != "" || (member.TaggingMode != "tagged" && member.TaggingMode != "untagged") {
			return false, fmt.Errorf("agent returned invalid or duplicate member %q with mode %q", member.InterfaceName, member.TaggingMode)
		}
		members[member.InterfaceName] = member.TaggingMode
		observed = append(observed, api.SwitchVLANObservedMember{InterfaceName: member.InterfaceName, TaggingMode: member.TaggingMode})
	}
	sort.Slice(observed, func(i, j int) bool { return observed[i].InterfaceName < observed[j].InterfaceName })
	v.Status.Exists, v.Status.Members = new(true), observed
	synced := true
	for _, desired := range v.Spec.Members {
		mode, exists := members[desired.InterfaceName]
		if !exists {
			synced = false
		} else if mode != desired.TaggingMode {
			return false, fmt.Errorf("member %q exists with mode %q, refusing replacement with %q", desired.InterfaceName, mode, desired.TaggingMode)
		}
	}
	return synced, nil
}

func (r *SwitchVLANReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.APIReader == nil {
		r.APIReader = mgr.GetAPIReader()
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&api.SwitchVLAN{}).
		WithEventFilter(predicate.Or(predicate.GenerationChangedPredicate{}, predicate.AnnotationChangedPredicate{}, predicate.Funcs{
			UpdateFunc: func(e event.UpdateEvent) bool {
				return !reflect.DeepEqual(e.ObjectOld.GetFinalizers(), e.ObjectNew.GetFinalizers()) || !reflect.DeepEqual(e.ObjectOld.GetDeletionTimestamp(), e.ObjectNew.GetDeletionTimestamp())
			},
		})).
		Named("switchvlan").
		Complete(r)
}
