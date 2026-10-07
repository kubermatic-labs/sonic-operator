// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
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
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

const reasonBreakoutPrepared = "BreakoutPrepared"

const (
	breakoutTargetAnnotation      = "sonic.networking.metal.ironcore.dev/breakout-target"
	breakoutManageAdminAnnotation = "sonic.networking.metal.ironcore.dev/manage-admin-state"
)

// SwitchPortBreakoutReconciler changes layouts only with explicit write opt-ins.
type SwitchPortBreakoutReconciler struct {
	client.Client
	APIReader      client.Reader
	ObserveOnly    bool
	AllowBreakout  bool
	NewAgentClient func(context.Context, client.Reader, *corev1.LocalObjectReference, string) (agentclient.SwitchAgentClient, error)
}

// +kubebuilder:rbac:groups=sonic.networking.metal.ironcore.dev,resources=switchportbreakouts,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=sonic.networking.metal.ironcore.dev,resources=switchportbreakouts/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=sonic.networking.metal.ironcore.dev,resources=switches;switchvlans,verbs=get;list;watch
// +kubebuilder:rbac:groups=sonic.networking.metal.ironcore.dev,resources=switchinterfaces,verbs=get;list;watch;create;delete

//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func (r *SwitchPortBreakoutReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, retErr error) {
	if r.APIReader == nil {
		return result, fmt.Errorf("breakout requires an uncached APIReader")
	}
	b := &api.SwitchPortBreakout{}
	if err := r.APIReader.Get(ctx, req.NamespacedName, b); err != nil {
		return result, client.IgnoreNotFound(err)
	}
	if !b.DeletionTimestamp.IsZero() {
		return result, nil
	}
	original := b.DeepCopy()
	reason, message := "BreakoutBlocked", "Breakout configuration is not confirmed"
	b.Status.ObservedGeneration = b.Generation
	b.Status.ConfigurationVerified, b.Status.RuntimeVerified, b.Status.PersistenceVerified = false, false, false
	b.Status.Mode, b.Status.Children, b.Status.SupportedModes = "", nil, nil
	b.Status.Message = ""
	defer func() {
		if retErr != nil {
			message = retErr.Error()
		}
		if b.Status.Message != "" && !strings.Contains(message, b.Status.Message) {
			message += ": " + b.Status.Message
		}
		b.Status.Message = message
		for _, condition := range []struct {
			name     string
			verified bool
		}{
			{"Ready", retErr == nil && b.Status.ConfigurationVerified && b.Status.RuntimeVerified && b.Status.PersistenceVerified && !b.Status.Pending},
			{"ConfigurationReady", b.Status.ConfigurationVerified}, {"RuntimeReady", b.Status.RuntimeVerified},
			{"PersistenceReady", b.Status.PersistenceVerified}, {"Progressing", b.Status.Pending},
		} {
			state := metav1.ConditionFalse
			if condition.verified {
				state = metav1.ConditionTrue
			}
			meta.SetStatusCondition(&b.Status.Conditions, metav1.Condition{Type: condition.name, Status: state, Reason: reason, Message: message, ObservedGeneration: b.Generation})
		}
		if !reflect.DeepEqual(original.Status, b.Status) {
			if err := r.Status().Patch(ctx, b, client.MergeFromWithOptions(original, client.MergeFromWithOptimisticLock{})); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("update breakout status: %w", err))
			}
		}
	}()
	result.RequeueAfter = time.Minute
	if b.UID == "" || b.Spec.SwitchRef.Name == "" || !vlanEthernetName.MatchString(b.Spec.Port) || b.Spec.Mode == "" || len(b.Spec.Mode) > 128 {
		return result, fmt.Errorf("breakout requires a CR UID, Switch reference, canonical parent port and exact supported mode")
	}
	if p := b.Spec.ManagementPolicy; p != "" && p != api.BreakoutManagementPolicyObserve && p != api.BreakoutManagementPolicyManage {
		return result, fmt.Errorf("invalid management policy %q", p)
	}
	admin := b.Spec.ChildAdminState
	if admin == "" {
		admin = api.AdminStateDown
	}
	state, err := agent.APIAdminStateToAgentDeviceStatus(admin)
	if err != nil {
		return result, err
	}
	s := &api.Switch{}
	if err := r.APIReader.Get(ctx, client.ObjectKey{Name: b.Spec.SwitchRef.Name}, s); err != nil {
		return result, err
	}
	port, err := strconv.Atoi(s.Spec.Management.Port)
	if s.UID == "" || !s.DeletionTimestamp.IsZero() || s.Spec.Management.Host == "" || err != nil || port < 1 || port > 65535 {
		return result, fmt.Errorf("a live Switch UID and explicit valid agent host/port are required")
	}
	identity := breakoutTargetIdentity(b, s)
	binding := b.Annotations[breakoutTargetAnnotation]
	if (binding != "" && binding != identity) || (original.Status.TargetIdentity != "" && (original.Status.TargetIdentity != identity || binding == "")) {
		return result, fmt.Errorf("switch identity, endpoint or target binding changed; restore the original target before writing")
	}
	factory := r.NewAgentClient
	if factory == nil {
		factory = switchutil.NewAgentClientFromSwitchRef
	}
	a, err := factory(ctx, vlanAuthorityReader{Reader: r.APIReader, target: s}, &corev1.LocalObjectReference{Name: s.Name}, "")
	if err != nil {
		return result, err
	}
	if a == nil {
		return result, fmt.Errorf("agent client is nil")
	}
	defer func() { retErr = errors.Join(retErr, closeAgentClient(a)) }()
	bc, ok := a.(agentclient.PortBreakoutClient)
	if !ok {
		return result, fmt.Errorf("agent client does not support port breakout")
	}
	current, err := bc.GetPortBreakout(ctx, b.Spec.Port)
	if err != nil {
		return result, fmt.Errorf("observe breakout: %w", err)
	}
	if err := observeBreakout(b, current); err != nil {
		return result, err
	}
	if !slices.Contains(current.SupportedModes, b.Spec.Mode) {
		return result, fmt.Errorf("mode %q is not supported by the platform", b.Spec.Mode)
	}
	if r.ObserveOnly || !r.AllowBreakout || b.Spec.ManagementPolicy != api.BreakoutManagementPolicyManage {
		reason, message = "WritesDisabled", "Observation only; writes require managementPolicy=Manage, observe-only=false, allow-breakout=true and agent gates"
		return result, nil
	}
	// Preparation records cleanup scope, not immutable admin/MTU intent. Only
	// layout differences keep a previous operation on the transition path; an
	// independent attribute update must not block exact populated adoption.
	adoptOnly := current.ConfigurationVerified && current.Mode == b.Spec.Mode && (len(b.Status.PreviousChildren) == 0 || slices.EqualFunc(b.Status.PreviousChildren, b.Status.Children, func(before, after api.SwitchPortBreakoutChild) bool {
		return before.Name == after.Name && before.Lanes == after.Lanes && before.Speed == after.Speed
	}))
	if adoptOnly && !current.AdoptionSupported {
		return result, fmt.Errorf("agent does not advertise guarded no-op breakout adoption")
	}
	// Preserve the full fresh snapshot for post-RPC attribute preservation checks.
	adoptedChildren := append([]api.SwitchPortBreakoutChild(nil), b.Status.Children...)
	// Persist the pre-operation child set before issuing any command. A timeout,
	// failed save or controller restart must not lose the only safe cleanup scope.
	previous := append([]api.SwitchPortBreakoutChild(nil), b.Status.PreviousChildren...)
	for _, child := range b.Status.Children {
		if !slices.ContainsFunc(previous, func(c api.SwitchPortBreakoutChild) bool { return c.Name == child.Name }) {
			previous = append(previous, child)
		}
	}
	if err := r.checkBreakoutCurrent(ctx, b, s, a, bc, previous, adoptOnly); err != nil {
		return result, err
	}
	if binding == "" {
		patch := client.MergeFromWithOptions(b.DeepCopy(), client.MergeFromWithOptimisticLock{})
		if b.Annotations == nil {
			b.Annotations = map[string]string{}
		}
		b.Annotations[breakoutTargetAnnotation] = identity
		if err := r.Patch(ctx, b, patch); err != nil {
			return result, err
		}
		// A metadata patch does not persist status. Keep the old status as the
		// baseline, but use the new resourceVersion for the optimistic status patch.
		original.ResourceVersion = b.ResourceVersion
		b.Status.TargetIdentity = identity
		b.Status.PreviousChildren = previous
		reason, message = reasonBreakoutPrepared, "Target binding and prior children persisted before the first operation"
		return ctrl.Result{RequeueAfter: time.Second}, nil
	}
	b.Status.TargetIdentity = identity
	if !reflect.DeepEqual(previous, original.Status.PreviousChildren) {
		b.Status.PreviousChildren = previous
		reason, message = reasonBreakoutPrepared, "Prior children recorded; retry before the operation"
		return ctrl.Result{RequeueAfter: time.Second}, nil
	}
	b.Status.Pending = true
	b.Status.ConfigurationVerified, b.Status.RuntimeVerified, b.Status.PersistenceVerified = false, false, false
	b.Status.Mode, b.Status.Children = "", nil
	b.Status.Message = ""
	writeCtx, cancel := context.WithTimeout(ctx, 180*time.Second)
	response, err := bc.ReconcilePortBreakout(writeCtx, &agent.PortBreakoutRequest{Port: b.Spec.Port, Mode: b.Spec.Mode, ChildAdminState: string(state), AdoptOnly: adoptOnly})
	cancel()
	if err != nil {
		// Keep pending on an unknown outcome; the agent's durable journal decides
		// whether the next request can finish saving or needs manual recovery.
		return result, fmt.Errorf("reconcile breakout (outcome may be pending): %w", err)
	}
	if err := observeBreakout(b, response); err != nil {
		return result, err
	}
	if !b.Status.ConfigurationVerified || !b.Status.RuntimeVerified || !b.Status.PersistenceVerified || b.Status.Pending {
		return result, fmt.Errorf("agent did not confirm desired configuration, runtime and persistence: %s", response.Message)
	}
	if adoptOnly && !reflect.DeepEqual(adoptedChildren, b.Status.Children) {
		b.Status.ConfigurationVerified, b.Status.RuntimeVerified, b.Status.PersistenceVerified = false, false, false
		return result, fmt.Errorf("no-op adoption changed the observed children or admin states")
	}
	beforeLanes, afterLanes := map[string]bool{}, map[string]bool{}
	for _, child := range previous {
		for _, lane := range strings.Split(child.Lanes, ",") {
			beforeLanes[lane] = true
		}
	}
	for _, child := range b.Status.Children {
		for _, lane := range strings.Split(child.Lanes, ",") {
			afterLanes[lane] = true
		}
	}
	if !reflect.DeepEqual(beforeLanes, afterLanes) {
		b.Status.ConfigurationVerified, b.Status.RuntimeVerified, b.Status.PersistenceVerified = false, false, false
		return result, fmt.Errorf("confirmed breakout children changed the parent lane set; refusing inventory cleanup")
	}
	for _, child := range b.Status.Children {
		if !slices.ContainsFunc(previous, func(old api.SwitchPortBreakoutChild) bool { return old.Name == child.Name }) && child.AdminState != admin {
			b.Status.ConfigurationVerified = false
			return result, fmt.Errorf("new child %q has admin state %q, expected %q", child.Name, child.AdminState, admin)
		}
	}
	// This check also fences inventory writes after a spec/endpoint change during
	// the long-running device operation. It never uses the informer cache.
	if err := r.checkBreakoutCurrent(ctx, b, s, a, bc, previous, adoptOnly); err != nil {
		return result, err
	}
	if err := r.reconcileBreakoutInventory(ctx, b, s, a, bc, previous, adoptOnly); err != nil {
		return result, err
	}
	b.Status.PreviousChildren = nil
	reason, message = "BreakoutConfirmed", "Configuration, APPL_DB/kernel layout and persistence confirmed; cable and forwarding health are not checked"
	return result, nil
}

func observeBreakout(b *api.SwitchPortBreakout, snapshot *agent.PortBreakout) error {
	if snapshot != nil {
		b.Status.Message = snapshot.Message
	}
	if snapshot == nil || snapshot.Port != b.Spec.Port || snapshot.Mode == "" || len(snapshot.Children) == 0 {
		return fmt.Errorf("agent returned incomplete or wrong-parent breakout observation")
	}
	names, lanes := map[string]bool{}, map[string]bool{}
	children := make([]api.SwitchPortBreakoutChild, 0, len(snapshot.Children))
	for _, child := range snapshot.Children {
		if !vlanEthernetName.MatchString(child.Name) || names[child.Name] || child.Lanes == "" || child.Speed == "" {
			return fmt.Errorf("invalid or duplicate breakout child %q", child.Name)
		}
		names[child.Name] = true
		for _, lane := range strings.Split(child.Lanes, ",") {
			n, err := strconv.ParseUint(lane, 10, 32)
			if err != nil || strconv.FormatUint(n, 10) != lane || lanes[lane] {
				return fmt.Errorf("invalid or overlapping child lane %q", lane)
			}
			lanes[lane] = true
		}
		state, err := agent.AgentDeviceStatusToAPIAdminState(agent.DeviceStatus(child.AdminState))
		if err != nil {
			return err
		}
		children = append(children, api.SwitchPortBreakoutChild{Name: child.Name, Lanes: child.Lanes, Speed: child.Speed, AdminState: state, MTU: child.MTU})
	}
	b.Status.Mode, b.Status.Children = snapshot.Mode, children
	b.Status.SupportedModes = slices.Clone(snapshot.SupportedModes)
	b.Status.ConfigurationVerified = snapshot.ConfigurationVerified && snapshot.Mode == b.Spec.Mode
	b.Status.RuntimeVerified, b.Status.PersistenceVerified, b.Status.Pending = snapshot.RuntimeVerified, snapshot.PersistenceVerified, snapshot.Pending
	return nil
}

func (r *SwitchPortBreakoutReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.APIReader == nil {
		r.APIReader = mgr.GetAPIReader()
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&api.SwitchPortBreakout{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Named("switchportbreakout").Complete(r)
}
