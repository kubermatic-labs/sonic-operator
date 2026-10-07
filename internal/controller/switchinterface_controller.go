// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	agentclient "github.com/ironcore-dev/sonic-operator/internal/agent/agent_client/client"
	corev1 "k8s.io/api/core/v1"

	"github.com/go-logr/logr"
	"github.com/ironcore-dev/controller-utils/clientutils"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	networkingv1alpha1 "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	agenterrors "github.com/ironcore-dev/sonic-operator/internal/agent/errors"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	switchUtil "github.com/ironcore-dev/sonic-operator/internal/switch_util"
)

// SwitchInterfaceReconciler reconciles a SwitchInterface object
type SwitchInterfaceReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// ObserveOnly disables all device writes. The manager defaults this to true.
	ObserveOnly bool
	// NewAgentClient optionally overrides agent construction.
	NewAgentClient func(context.Context, client.Reader, *corev1.LocalObjectReference, string) (agentclient.SwitchAgentClient, error)
}

// +kubebuilder:rbac:groups=sonic.networking.metal.ironcore.dev,resources=switchinterfaces,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=sonic.networking.metal.ironcore.dev,resources=switchinterfaces/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=sonic.networking.metal.ironcore.dev,resources=switchinterfaces/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *SwitchInterfaceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	i := &networkingv1alpha1.SwitchInterface{}
	if err := r.Get(ctx, req.NamespacedName, i); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	return r.reconileExists(ctx, log, i)
}

func (r *SwitchInterfaceReconciler) reconileExists(ctx context.Context, log logr.Logger, i *networkingv1alpha1.SwitchInterface) (ctrl.Result, error) {
	if !i.DeletionTimestamp.IsZero() {
		return r.delete(ctx, log, i)
	}
	return r.reconcile(ctx, log, i)
}

func (r *SwitchInterfaceReconciler) delete(ctx context.Context, log logr.Logger, i *networkingv1alpha1.SwitchInterface) (ctrl.Result, error) {
	log.Info("Deleting SwitchInterface")

	// TODO: do cleanup

	if _, err := clientutils.PatchEnsureNoFinalizer(ctx, r.Client, i, networkingv1alpha1.SwitchFinalizer); err != nil {
		return ctrl.Result{}, err
	}

	log.Info("Deleted SwitchInterface")
	return ctrl.Result{}, nil
}

//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func (r *SwitchInterfaceReconciler) reconcile(ctx context.Context, log logr.Logger, i *networkingv1alpha1.SwitchInterface) (result ctrl.Result, retErr error) {
	log.Info("Reconciling SwitchInterface")

	if modified, err := clientutils.PatchEnsureFinalizer(ctx, r.Client, i, networkingv1alpha1.SwitchFinalizer); err != nil || modified {
		return ctrl.Result{}, err
	}

	original := i.DeepCopy()
	i.Status.AdminStateManaged = !r.ObserveOnly && i.Annotations[interfaceManageAdminAnnotation] == "true"
	i.Status.AdminStateRequest = i.Annotations[interfaceAdminRequestAnnotation]
	i.Status.AdminStateDigest = interfaceAdminDigest(i, r.ObserveOnly)
	persistenceVerified := false
	defer func() {
		if retErr != nil {
			i.Status.State = networkingv1alpha1.SwitchInterfaceStateFailed
		}
		condition := metav1.Condition{Type: "AdminPersistenceReady", Status: metav1.ConditionFalse, Reason: "NotVerified", Message: "Managed admin persistence has not been verified", ObservedGeneration: i.Generation}
		if !i.Status.AdminStateManaged {
			condition.Reason, condition.Message = "WritesDisabled", "Admin state is observed only; explicit admin opt-in and manager write gate are required"
		}
		if persistenceVerified && retErr == nil {
			condition.Status, condition.Reason, condition.Message = metav1.ConditionTrue, "SavedStateVerified", "Desired admin state verified in live and saved PORT configuration"
		}
		meta.SetStatusCondition(&i.Status.Conditions, condition)
		if err := r.Status().Patch(ctx, i, client.MergeFromWithOptions(original, client.MergeFromWithOptimisticLock{})); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("update SwitchInterface status: %w", err))
		}
	}()

	if i.Status.State == "" {
		i.Status.State = networkingv1alpha1.SwitchInterfaceStatePending
		return ctrl.Result{RequeueAfter: time.Second}, nil
	}

	i.Status.State = networkingv1alpha1.SwitchInterfaceStateFailed
	if i.Spec.SwitchRef == nil || i.Spec.SwitchRef.Name == "" {
		return ctrl.Result{}, fmt.Errorf("SwitchInterface has no switch reference")
	}
	if i.Spec.Handle == "" || i.Spec.NativeName == "" {
		return ctrl.Result{}, fmt.Errorf("SwitchInterface has incomplete interface identity")
	}

	newAgentClient := r.NewAgentClient
	if newAgentClient == nil {
		newAgentClient = switchUtil.NewAgentClientFromSwitchRef
	}
	switchAgentClient, err := newAgentClient(ctx, r.Client, i.Spec.SwitchRef, i.Namespace)
	if err != nil {
		return ctrl.Result{}, err
	}
	if switchAgentClient == nil {
		return ctrl.Result{}, fmt.Errorf("agent client is nil")
	}
	defer func() { retErr = errors.Join(retErr, closeAgentClient(switchAgentClient)) }()

	iface, err := switchAgentClient.GetInterfaceByAbstractName(ctx, &agent.Interface{
		TypeMeta: agent.TypeMeta{
			Kind: agent.InterfaceKind,
		},
		Name: i.Spec.Handle,
	})
	if err != nil {
		return ctrl.Result{}, err
	}
	if iface == nil {
		return ctrl.Result{}, fmt.Errorf("agent returned nil interface")
	}
	if iface.Status.Code != 0 {
		return ctrl.Result{}, fmt.Errorf("get interface: %s", iface.Status.String())
	}
	if iface.NativeName == "" || iface.NativeName != i.Spec.NativeName {
		return ctrl.Result{}, fmt.Errorf("interface identity conflict: discovered native name %q differs from spec %q", iface.NativeName, i.Spec.NativeName)
	}
	nativeName := iface.NativeName
	i.Status.AliasName = iface.AliasName
	i.Status.MacAddress = iface.MacAddress
	// Unknown observations stay Unknown; they are never interpreted as Down.
	i.Status.AdminState, _ = agent.AgentDeviceStatusToAPIAdminState(iface.AdminStatus)
	i.Status.OperationalState, _ = agent.AgentDeviceStatusToAPIOperationState(iface.OperationStatus)

	neighbor, err := switchAgentClient.GetInterfaceNeighbor(ctx, &agent.Interface{
		TypeMeta: agent.TypeMeta{
			Kind: agent.InterfaceKind,
		},
		Name: nativeName,
	})
	if neighbor != nil && neighbor.Status.Code == agenterrors.NOT_FOUND {
		i.Status.Neighbor = networkingv1alpha1.Neighbor{}
	} else {
		if err != nil {
			return ctrl.Result{}, err
		}
		if neighbor == nil {
			return ctrl.Result{}, fmt.Errorf("agent returned nil neighbor")
		}
		if neighbor.Status.Code != 0 {
			return ctrl.Result{}, fmt.Errorf("get neighbor: %s", neighbor.Status.String())
		}
		i.Status.Neighbor = networkingv1alpha1.Neighbor{
			MacAddress:      neighbor.MacAddress,
			SystemName:      neighbor.SystemName,
			InterfaceHandle: neighbor.Handle,
		}
	}

	if i.Status.AdminStateManaged {
		desiredState, err := agent.APIAdminStateToAgentDeviceStatus(i.Spec.AdminState)
		if err != nil {
			return ctrl.Result{}, err
		}
		if desiredState != agent.StatusUp && desiredState != agent.StatusDown {
			return ctrl.Result{}, fmt.Errorf("invalid desired admin state %q", i.Spec.AdminState)
		}
		if iface.AdminStatus != agent.StatusUp && iface.AdminStatus != agent.StatusDown {
			return ctrl.Result{}, fmt.Errorf("cannot manage unknown current admin state %q", iface.AdminStatus)
		}
		// Always reconcile persistence, including adoption and interrupted-save
		// recovery when the live value already matches the desired state.
		updated, err := switchAgentClient.SetInterfaceAdminStatus(ctx, &agent.Interface{
			TypeMeta:    agent.TypeMeta{Kind: agent.InterfaceKind},
			Name:        nativeName,
			NativeName:  nativeName,
			AdminStatus: desiredState,
		})
		if err != nil {
			return ctrl.Result{}, err
		}
		if updated == nil {
			return ctrl.Result{}, fmt.Errorf("agent returned nil interface after admin update")
		}
		if updated.Status.Code != 0 {
			return ctrl.Result{}, fmt.Errorf("set admin state: %s", updated.Status.String())
		}
		if updated.NativeName != nativeName || updated.AdminStatus != desiredState {
			return ctrl.Result{}, fmt.Errorf("agent did not confirm admin state for native interface %q", nativeName)
		}
		if !updated.AdminPersistenceVerified {
			return ctrl.Result{}, fmt.Errorf("agent did not verify saved admin state for native interface %q", nativeName)
		}
		persistenceVerified = true
		i.Status.AdminState, _ = agent.AgentDeviceStatusToAPIAdminState(updated.AdminStatus)
		i.Status.OperationalState, _ = agent.AgentDeviceStatusToAPIOperationState(updated.OperationStatus)
	}
	i.Status.State = networkingv1alpha1.SwitchInterfaceStateReady
	log.Info("Reconciled SwitchInterface")
	return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *SwitchInterfaceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&networkingv1alpha1.SwitchInterface{}).
		Named("switchinterface").
		Complete(r)
}
