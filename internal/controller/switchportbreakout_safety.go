// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"slices"
	"strings"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	agentclient "github.com/ironcore-dev/sonic-operator/internal/agent/agent_client/client"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func breakoutTargetIdentity(b *api.SwitchPortBreakout, s *api.Switch) string {
	data, _ := json.Marshal([]any{b.UID, b.Spec.SwitchRef.Name, b.Spec.Port, s.UID, s.Spec.Management, s.Spec.MacAddress})
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func (r *SwitchPortBreakoutReconciler) checkBreakoutCurrent(ctx context.Context, b *api.SwitchPortBreakout, s *api.Switch, a agentclient.SwitchAgentClient, bc agentclient.PortBreakoutClient, previous []api.SwitchPortBreakoutChild, adoptOnly bool) error {
	latest := &api.SwitchPortBreakout{}
	if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(b), latest); err != nil {
		return err
	}
	if latest.UID != b.UID || latest.Generation != b.Generation || !reflect.DeepEqual(latest.Spec, b.Spec) || !latest.DeletionTimestamp.IsZero() || latest.Annotations[breakoutTargetAnnotation] != b.Annotations[breakoutTargetAnnotation] {
		return fmt.Errorf("breakout claim changed or deletion started; retry without writing")
	}
	sw := &api.Switch{}
	if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(s), sw); err != nil {
		return err
	}
	if !sw.DeletionTimestamp.IsZero() || breakoutTargetIdentity(b, sw) != breakoutTargetIdentity(b, s) {
		return fmt.Errorf("switch identity or endpoint changed; no breakout operations allowed")
	}
	switches := &api.SwitchList{}
	if err := r.APIReader.List(ctx, switches); err != nil {
		return err
	}
	aliases := map[string]bool{s.Name: true}
	for _, other := range switches.Items {
		if net.JoinHostPort(other.Spec.Management.Host, other.Spec.Management.Port) == net.JoinHostPort(s.Spec.Management.Host, s.Spec.Management.Port) {
			aliases[other.Name] = true
		}
	}
	affected, lanes := map[string]bool{b.Spec.Port: true}, map[string]bool{}
	for _, children := range [][]api.SwitchPortBreakoutChild{previous, b.Status.Children} {
		for _, child := range children {
			affected[child.Name] = true
			for _, lane := range strings.Split(child.Lanes, ",") {
				if lane != "" {
					lanes[lane] = true
				}
			}
		}
	}
	claims := &api.SwitchPortBreakoutList{}
	if err := r.APIReader.List(ctx, claims); err != nil {
		return err
	}
	for _, other := range claims.Items {
		if other.UID == b.UID || !aliases[other.Spec.SwitchRef.Name] {
			continue
		}
		if affected[other.Spec.Port] {
			return fmt.Errorf("SwitchPortBreakout %q also claims an affected port", other.Name)
		}
		// Never use another CR's stale status to prove lanes are disjoint.
		observed, err := bc.GetPortBreakout(ctx, other.Spec.Port)
		if err != nil {
			return fmt.Errorf("cannot establish competing claim %q lane scope: %w", other.Name, err)
		}
		if err := observeBreakout(&other, observed); err != nil {
			return err
		}
		for _, child := range other.Status.Children {
			if affected[child.Name] {
				return fmt.Errorf("breakout child overlaps claim %q", other.Name)
			}
			for _, lane := range strings.Split(child.Lanes, ",") {
				if lanes[lane] {
					return fmt.Errorf("breakout lanes overlap claim %q", other.Name)
				}
			}
		}
	}
	// Unknown/nonexistent interface references may name future children. Without
	// a platform lane map for that name, they cannot safely be declared unrelated.
	interfaces, err := a.ListInterfaces(ctx)
	if err != nil {
		return err
	}
	if interfaces == nil || interfaces.Status.Code != 0 {
		return fmt.Errorf("cannot establish live interface inventory")
	}
	live := map[string]bool{}
	for _, i := range interfaces.Items {
		if i.Status.Code != 0 || i.NativeName == "" {
			return fmt.Errorf("incomplete interface inventory")
		}
		live[i.NativeName] = true
	}
	vlans := &api.SwitchVLANList{}
	if err := r.APIReader.List(ctx, vlans); err != nil {
		return err
	}
	for _, vlan := range vlans.Items {
		if !aliases[vlan.Spec.SwitchRef.Name] {
			continue
		}
		for _, member := range vlan.Spec.Members {
			if (!adoptOnly && affected[member.InterfaceName]) || !live[member.InterfaceName] {
				return fmt.Errorf("SwitchVLAN %q references affected or unresolved interface %q", vlan.Name, member.InterfaceName)
			}
		}
	}
	inventory := &api.SwitchInterfaceList{}
	if err := r.APIReader.List(ctx, inventory); err != nil {
		return err
	}
	for _, iface := range inventory.Items {
		if iface.Spec.SwitchRef == nil || !aliases[iface.Spec.SwitchRef.Name] {
			continue
		}
		if !affected[iface.Spec.NativeName] && live[iface.Spec.NativeName] {
			continue
		}
		if breakoutHasTypedPortIntent(&iface) && (!adoptOnly || !live[iface.Spec.NativeName]) {
			return fmt.Errorf("SwitchInterface %q has typed port intent or retained network recovery ownership", iface.Name)
		}
		if _, managed := iface.Annotations[breakoutManageAdminAnnotation]; managed && !adoptOnly {
			return fmt.Errorf("SwitchInterface %q has an admin-management annotation", iface.Name)
		}
		if !breakoutGeneratedInterface(&iface, s) {
			return fmt.Errorf("SwitchInterface %q is user-managed or has foreign ownership", iface.Name)
		}
		if adoptOnly && live[iface.Spec.NativeName] {
			// Exact no-op adoption neither changes nor deletes referenced inventory.
			continue
		}
		// References to an interface CR through ownerReferences represent another
		// controller's intent, even if the interface itself is generated inventory.
		for _, dependent := range inventory.Items {
			for _, owner := range dependent.OwnerReferences {
				if iface.UID != "" && owner.UID == iface.UID {
					return fmt.Errorf("SwitchInterface %q is referenced by %q", iface.Name, dependent.Name)
				}
			}
		}
		for _, p := range sw.Status.Ports {
			for _, ref := range p.InterfaceRefs {
				if ref.Name == iface.Name {
					return fmt.Errorf("switch port %q has an owned/routed reference to %q", p.Name, iface.Name)
				}
			}
		}
	}
	// Device reads above can be slow: fence the primary CR and target once more
	// after them, not just before checking the dependent API objects.
	if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(b), latest); err != nil {
		return err
	}
	if latest.UID != b.UID || latest.Generation != b.Generation || !reflect.DeepEqual(latest.Spec, b.Spec) || !latest.DeletionTimestamp.IsZero() || latest.Annotations[breakoutTargetAnnotation] != b.Annotations[breakoutTargetAnnotation] {
		return fmt.Errorf("breakout claim changed during preflight")
	}
	if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(s), sw); err != nil {
		return err
	}
	if !sw.DeletionTimestamp.IsZero() || breakoutTargetIdentity(b, sw) != breakoutTargetIdentity(b, s) {
		return fmt.Errorf("switch target changed during preflight")
	}
	return nil
}

// Typed intent is independent of admin opt-in and remains protected in Observe,
// including when fields have been removed but recovery ownership is retained.
func breakoutHasTypedPortIntent(i *api.SwitchInterface) bool {
	_, bound := i.Annotations[networkTargetAnnotation]
	_, recorded := i.Annotations[networkRequestAnnotation]
	return i.Spec.Speed != nil || i.Spec.MTU != nil || i.Spec.FEC != "" || bound || recorded || slices.Contains(i.Finalizers, networkRecoveryFinalizer)
}

func breakoutGeneratedInterface(i *api.SwitchInterface, s *api.Switch) bool {
	owner := metav1.GetControllerOf(i)
	return s.UID != "" && owner != nil && owner.UID == s.UID && owner.Name == s.Name && owner.Kind == "Switch" && owner.APIVersion == api.GroupVersion.String() && len(i.OwnerReferences) == 1 &&
		i.Spec.SwitchRef != nil && i.Spec.SwitchRef.Name == s.Name && i.Spec.Handle != "" && i.Name == strings.ToLower(s.Name+"-"+i.Spec.Handle)
}

//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func (r *SwitchPortBreakoutReconciler) reconcileBreakoutInventory(ctx context.Context, b *api.SwitchPortBreakout, s *api.Switch, a agentclient.SwitchAgentClient, bc agentclient.PortBreakoutClient, previous []api.SwitchPortBreakoutChild, adoptOnly bool) error {
	list, err := a.ListInterfaces(ctx)
	if err != nil {
		return err
	}
	if list == nil || list.Status.Code != 0 {
		return fmt.Errorf("cannot confirm post-breakout interface inventory")
	}
	live := map[string]agent.Interface{}
	for _, iface := range list.Items {
		if iface.Status.Code != 0 || iface.Name == "" || iface.NativeName == "" {
			return fmt.Errorf("incomplete post-breakout interface inventory")
		}
		if _, duplicate := live[iface.NativeName]; duplicate {
			return fmt.Errorf("duplicate native interface %q", iface.NativeName)
		}
		live[iface.NativeName] = iface
	}
	current := map[string]bool{}
	for _, child := range b.Status.Children {
		if _, ok := live[child.Name]; !ok {
			return fmt.Errorf("confirmed child %q missing from interface inventory", child.Name)
		}
		current[child.Name] = true
	}
	inventory := &api.SwitchInterfaceList{}
	if err := r.APIReader.List(ctx, inventory); err != nil {
		return err
	}
	for _, child := range b.Status.Children {
		exists := false
		for _, i := range inventory.Items {
			if i.Spec.SwitchRef != nil && i.Spec.SwitchRef.Name == s.Name && i.Spec.NativeName == child.Name {
				// Existing desired intent wins, including Up on a surviving Ethernet0.
				exists = true
			}
		}
		if exists {
			continue
		}
		iface := live[child.Name]
		admin, err := agent.AgentDeviceStatusToAPIAdminState(iface.AdminStatus)
		if err != nil {
			return err
		}
		if err := r.checkBreakoutCurrent(ctx, b, s, a, bc, previous, adoptOnly); err != nil {
			return err
		}
		i := &api.SwitchInterface{ObjectMeta: metav1.ObjectMeta{Name: strings.ToLower(s.Name + "-" + iface.Name), OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(s, api.GroupVersion.WithKind("Switch"))}}, Spec: api.SwitchInterfaceSpec{SwitchRef: &corev1.LocalObjectReference{Name: s.Name}, Handle: iface.Name, NativeName: child.Name, AdminState: admin}}
		if err := r.Create(ctx, i); err != nil {
			return fmt.Errorf("create child inventory without overwriting existing intent: %w", err)
		}
	}
	missing := map[string]bool{}
	for _, child := range previous {
		_, present := live[child.Name]
		if !current[child.Name] && !present {
			missing[child.Name] = true
		}
	}
	for _, i := range inventory.Items {
		if !missing[i.Spec.NativeName] || !breakoutGeneratedInterface(&i, s) {
			continue
		}
		if _, managed := i.Annotations[breakoutManageAdminAnnotation]; managed {
			continue
		}
		if breakoutHasTypedPortIntent(&i) {
			return fmt.Errorf("stale child %q retains typed port intent or network recovery ownership; refusing cleanup", i.Name)
		}
		if err := r.checkBreakoutCurrent(ctx, b, s, a, bc, previous, adoptOnly); err != nil {
			return err
		}
		latest := &api.SwitchInterface{}
		if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(&i), latest); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return err
		}
		if latest.UID != i.UID || !missing[latest.Spec.NativeName] || !breakoutGeneratedInterface(latest, s) {
			return fmt.Errorf("stale child inventory changed before cleanup")
		}
		if _, managed := latest.Annotations[breakoutManageAdminAnnotation]; managed {
			return fmt.Errorf("stale child opted into admin management before cleanup")
		}
		if breakoutHasTypedPortIntent(latest) {
			return fmt.Errorf("stale child acquired typed port intent or network recovery ownership before cleanup")
		}
		// Both UID and resourceVersion fence a concurrent recreation or user edit.
		if err := r.Delete(ctx, latest, client.Preconditions{UID: &latest.UID, ResourceVersion: &latest.ResourceVersion}); client.IgnoreNotFound(err) != nil {
			return err
		}
	}
	return nil
}
