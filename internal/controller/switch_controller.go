// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	agentclient "github.com/ironcore-dev/sonic-operator/internal/agent/agent_client/client"

	"github.com/go-logr/logr"
	"github.com/ironcore-dev/controller-utils/clientutils"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"

	switchUtil "github.com/ironcore-dev/sonic-operator/internal/switch_util"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	networkingv1alpha1 "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
)

var (
	agentRetryAfter = time.Minute
)

// SwitchReconciler reconciles a Switch object
type SwitchReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// NewAgentClient optionally overrides agent construction.
	NewAgentClient func(context.Context, *networkingv1alpha1.Switch) (agentclient.SwitchAgentClient, error)
}

// +kubebuilder:rbac:groups=sonic.networking.metal.ironcore.dev,resources=switches,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=sonic.networking.metal.ironcore.dev,resources=switches/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=sonic.networking.metal.ironcore.dev,resources=switches/finalizers,verbs=update
// +kubebuilder:rbac:groups=sonic.networking.metal.ironcore.dev,resources=interfaces,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *SwitchReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	s := &networkingv1alpha1.Switch{}
	if err := r.Get(ctx, req.NamespacedName, s); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	return r.reconileExists(ctx, log, s)
}

func (r *SwitchReconciler) reconileExists(ctx context.Context, log logr.Logger, s *networkingv1alpha1.Switch) (ctrl.Result, error) {
	if !s.DeletionTimestamp.IsZero() {
		return r.delete(ctx, log, s)
	}
	return r.reconcile(ctx, log, s)
}

func (r *SwitchReconciler) delete(ctx context.Context, log logr.Logger, s *networkingv1alpha1.Switch) (ctrl.Result, error) {
	log.Info("Deleting Switch")

	// TODO: do cleanup

	if _, err := clientutils.PatchEnsureNoFinalizer(ctx, r.Client, s, networkingv1alpha1.SwitchFinalizer); err != nil {
		return ctrl.Result{}, err
	}

	log.Info("Deleted Switch")
	return ctrl.Result{}, nil
}

func (r *SwitchReconciler) reconcile(ctx context.Context, log logr.Logger, s *networkingv1alpha1.Switch) (result ctrl.Result, retErr error) {
	log.Info("Reconciling Switch")

	if modified, err := clientutils.PatchEnsureFinalizer(ctx, r.Client, s, networkingv1alpha1.SwitchFinalizer); err != nil || modified {
		return ctrl.Result{}, err
	}

	original := s.DeepCopy()
	defer func() {
		if retErr != nil {
			s.Status.State = networkingv1alpha1.SwitchStateFailed
			s.Status.Ports = original.Status.Ports
		}
		if err := r.Status().Patch(ctx, s, client.MergeFrom(original)); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("update Switch status: %w", err))
		}
	}()

	// A Switch is declaratively ready as soon as it is accepted by the
	// controller. The SONiC agent enriches status when reachable, but agent
	// availability must not prevent ZTP/bootstrap workflows.
	if s.Status.State != networkingv1alpha1.SwitchStateReady {
		s.Status.State = networkingv1alpha1.SwitchStateReady
		return ctrl.Result{}, nil
	}

	newAgentClient := r.NewAgentClient
	if newAgentClient == nil {
		newAgentClient = switchUtil.NewAgentClientForSwitch
	}
	switchAgentClient, err := newAgentClient(ctx, s)
	if err != nil {
		log.Info("Switch agent is unavailable; keeping Switch ready", "err", err)
		return ctrl.Result{RequeueAfter: agentRetryAfter}, nil
	}
	if switchAgentClient == nil {
		return ctrl.Result{}, fmt.Errorf("agent client is nil")
	}
	defer func() { retErr = errors.Join(retErr, closeAgentClient(switchAgentClient)) }()

	switchDevice, err := switchAgentClient.GetDeviceInfo(ctx)
	if err != nil {
		log.Info("Switch agent is unavailable; keeping Switch ready", "err", err)
		return ctrl.Result{RequeueAfter: agentRetryAfter}, nil
	}
	if switchDevice == nil {
		return ctrl.Result{}, fmt.Errorf("agent returned nil device info")
	}
	if switchDevice.Status.Code != 0 {
		return ctrl.Result{}, fmt.Errorf("get device info: %s", switchDevice.Status.String())
	}

	s.Status.MACAddress = switchDevice.LocalMacAddress
	s.Status.FirmwareVersion = switchDevice.SonicOSVersion
	s.Status.SKU = switchDevice.Hwsku

	interfaceList, err := switchAgentClient.ListInterfaces(ctx)
	if err != nil {
		log.Info("Switch agent is unavailable; keeping Switch ready", "err", err)
		return ctrl.Result{RequeueAfter: agentRetryAfter}, nil
	}
	if interfaceList == nil {
		return ctrl.Result{}, fmt.Errorf("agent returned nil interface list")
	}
	if interfaceList.Status.Code != 0 {
		return ctrl.Result{}, fmt.Errorf("list interfaces: %s", interfaceList.Status.String())
	}

	for _, iface := range interfaceList.Items {
		if err := r.EnsureInterface(ctx, log, s, iface); err != nil {
			return ctrl.Result{}, err
		}
	}

	portList, err := switchAgentClient.ListPorts(ctx)
	if err != nil {
		log.Info("Switch agent is unavailable; keeping Switch ready", "err", err)
		return ctrl.Result{RequeueAfter: agentRetryAfter}, nil
	}
	if portList == nil {
		return ctrl.Result{}, fmt.Errorf("agent returned nil port list")
	}
	if portList.Status.Code != 0 {
		return ctrl.Result{}, fmt.Errorf("list ports: %s", portList.Status.String())
	}

	var ports []networkingv1alpha1.PortStatus
	for _, p := range portList.Items {
		if p.Status.Code != 0 {
			return ctrl.Result{}, fmt.Errorf("port %q: %s", p.Name, p.Status.String())
		}
		ports = append(ports, networkingv1alpha1.PortStatus{Name: p.Name})
	}
	s.Status.Ports = ports

	s.Status.State = networkingv1alpha1.SwitchStateReady

	log.Info("Reconciled Switch")
	return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
}

func (r *SwitchReconciler) EnsureInterface(ctx context.Context, log logr.Logger, s *networkingv1alpha1.Switch, iface agent.Interface) error {
	log.Info("Ensuring Interface")

	if iface.Status.Code != 0 {
		return fmt.Errorf("discovered interface %q: %s", iface.Name, iface.Status.String())
	}
	if iface.Name == "" || iface.NativeName == "" || s.UID == "" {
		return fmt.Errorf("cannot adopt interface with incomplete identity or switch UID")
	}

	key := client.ObjectKey{Name: strings.ToLower(fmt.Sprintf("%s-%s", s.Name, iface.Name))}
	existing := &networkingv1alpha1.SwitchInterface{}
	err := r.Get(ctx, key, existing)
	if apierrors.IsNotFound(err) {
		// Seed desired state only at creation. Discovery must never overwrite user intent.
		adminState, _ := agent.AgentDeviceStatusToAPIAdminState(iface.AdminStatus)
		discovered := &networkingv1alpha1.SwitchInterface{
			ObjectMeta: metav1.ObjectMeta{
				Name:            key.Name,
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(s, networkingv1alpha1.GroupVersion.WithKind("Switch"))},
			},
			Spec: networkingv1alpha1.SwitchInterfaceSpec{
				Handle:     iface.Name,
				NativeName: iface.NativeName,
				SwitchRef:  &corev1.LocalObjectReference{Name: s.Name},
				AdminState: adminState,
			},
		}
		if err := r.Create(ctx, discovered); !apierrors.IsAlreadyExists(err) {
			return err
		}
		// A concurrent creator wins; validate its object without applying over it.
		err = r.Get(ctx, key, existing)
	}
	if err != nil {
		return err
	}
	owner := metav1.GetControllerOf(existing)
	if owner == nil || owner.UID != s.UID || owner.Name != s.Name || owner.Kind != "Switch" || owner.APIVersion != networkingv1alpha1.GroupVersion.String() ||
		existing.Spec.SwitchRef == nil || existing.Spec.SwitchRef.Name != s.Name || existing.Spec.NativeName != iface.NativeName || existing.Spec.Handle != iface.Name || !existing.DeletionTimestamp.IsZero() {
		return fmt.Errorf("interface adoption conflict for %q: existing ownership or identity does not match switch %q and native interface %q", key.Name, s.Name, iface.NativeName)
	}

	log.Info("Ensured Interface")
	return nil
}

func closeAgentClient(agentClient agentclient.SwitchAgentClient) error {
	if closer, ok := agentClient.(interface{ Close() error }); ok {
		if err := closer.Close(); err != nil {
			return fmt.Errorf("close agent client: %w", err)
		}
	}
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *SwitchReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&networkingv1alpha1.Switch{}).
		Owns(&networkingv1alpha1.SwitchInterface{}).
		Named("switch").
		Complete(r)
}
