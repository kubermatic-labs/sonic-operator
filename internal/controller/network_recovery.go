// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"time"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	agentclient "github.com/ironcore-dev/sonic-operator/internal/agent/agent_client/client"
	switchutil "github.com/ironcore-dev/sonic-operator/internal/switch_util"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// recoverNetwork only completes an already journaled operation. The request
// persisted before Ensure avoids validating or applying subsequently edited intent.
func (r *NetworkReconciler) recoverNetwork(ctx context.Context, obj client.Object) (retErr error) {
	_, _, common := networkFields(obj)
	if r.networkWritesDisabled(common) {
		return fmt.Errorf("network recovery requires all manager and resource write gates; retaining finalizer")
	}
	saved, _, err := networkObjects(r.Kind)
	if err != nil {
		return err
	}
	raw := obj.GetAnnotations()[networkRequestAnnotation]
	if raw == "" {
		return fmt.Errorf("missing recorded network request; retaining finalizer")
	}
	saved.SetUID(obj.GetUID())
	spec, _, savedCommon := networkFields(saved)
	if err := json.Unmarshal([]byte(raw), spec); err != nil {
		return fmt.Errorf("invalid recorded request: %w", err)
	}
	request, target, err := networkDesired(r.Kind, saved)
	if err != nil {
		return fmt.Errorf("invalid recorded request: %w", err)
	}
	if r.Kind == "EVPNPeer" || r.Kind == "EVPN" {
		// Preserve the originally resolved mapping snapshot. Recovery must not
		// silently replace it with today's dependency state or drop it by
		// unmarshalling the internal payload into the public API type.
		var recorded map[string]json.RawMessage
		if err := json.Unmarshal([]byte(raw), &recorded); err != nil {
			return err
		}
		if mappings, ok := recorded["mappings"]; ok {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(request.Spec, &fields); err != nil {
				return err
			}
			fields["mappings"] = mappings
			request.Spec, err = json.Marshal(fields)
			if err != nil {
				return err
			}
		}
	}
	// Only immutable selectors must agree. Mutable fields may be invalid or new.
	currentSpec, _, _ := networkFields(obj)
	currentRaw, err := json.Marshal(currentSpec)
	if err != nil {
		return err
	}
	var currentFields, savedFields map[string]any
	if err := json.Unmarshal(currentRaw, &currentFields); err != nil {
		return err
	}
	if err := json.Unmarshal(request.Spec, &savedFields); err != nil {
		return err
	}
	// FRR mode is mutable intent, not a target selector. Always recover the
	// saved mode and approval before considering a transition in either direction.
	for _, field := range []string{"switchRef", "name", "vrf", "prefix", "address", "vlanID", "policy", "type", "interfaceName", "domainID", "peerSwitchRef", "tunnel"} {
		current, previous := currentFields[field], savedFields[field]
		if field == "address" && r.Kind == "EVPNPeer" {
			canonical := func(value any) any {
				if s, ok := value.(string); ok {
					if ip, err := netip.ParseAddr(s); err == nil {
						return ip.String()
					}
				}
				return value
			}
			current, previous = canonical(current), canonical(previous)
		}
		if field == "vrf" {
			if current == nil || current == "" {
				current = "default"
			}
			if previous == nil || previous == "" {
				previous = "default"
			}
		}
		if !reflect.DeepEqual(current, previous) {
			return fmt.Errorf("recorded network target selector %s changed; retaining finalizer", field)
		}
	}
	if r.Kind == "EVPNPeer" {
		role := func(v any) any {
			if v == nil || v == "" {
				return "Leaf"
			}
			return v
		}
		if role(currentFields["role"]) != role(savedFields["role"]) {
			return fmt.Errorf("EVPN peer role changed during recovery")
		}
	}
	sw := &api.Switch{}
	if err := r.APIReader.Get(ctx, client.ObjectKey{Name: savedCommon.SwitchRef.Name}, sw); err != nil {
		return err
	}
	binding := obj.GetAnnotations()[networkTargetAnnotation]
	if binding == "" || sw.UID == "" || !sw.DeletionTimestamp.IsZero() || networkBinding(obj, sw, r.Kind, target) != binding {
		return fmt.Errorf("recorded Switch identity or endpoint changed; retaining finalizer")
	}
	checkCurrent := func() error {
		latest, _, _ := networkObjects(r.Kind)
		if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(obj), latest); err != nil {
			return err
		}
		if latest.GetUID() != obj.GetUID() || latest.GetResourceVersion() != obj.GetResourceVersion() {
			return fmt.Errorf("network claim changed during recovery; retaining finalizer")
		}
		current := &api.Switch{}
		if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(sw), current); err != nil {
			return err
		}
		if !current.DeletionTimestamp.IsZero() || networkBinding(obj, current, r.Kind, target) != binding {
			return fmt.Errorf("Switch changed during recovery; retaining finalizer")
		}
		return nil
	}
	factory := r.NewAgentClient
	if factory == nil {
		factory = switchutil.NewAgentClientFromSwitchRef
	}
	a, err := factory(ctx, networkBoundReader{Reader: r.APIReader, target: sw}, &corev1.LocalObjectReference{Name: sw.Name}, "")
	if err != nil {
		return err
	}
	if a == nil || (reflect.ValueOf(a).Kind() == reflect.Pointer && reflect.ValueOf(a).IsNil()) {
		return fmt.Errorf("nil network recovery client")
	}
	defer func() { retErr = errors.Join(retErr, closeAgentClient(a)) }()
	nc, ok := a.(agentclient.NetworkRecoveryClient)
	if !ok {
		return fmt.Errorf("agent client does not support network recovery")
	}
	if err := checkCurrent(); err != nil {
		return err
	}
	recoveryCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	result, err := nc.RecoverNetworkResource(recoveryCtx, request)
	cancel()
	if err != nil {
		return fmt.Errorf("recover recorded network operation: %w", err)
	}
	// Recover's successful outcome guarantees pending persistence was completed
	// or no pending operation exists. A no-record/no-pending result deliberately
	// has empty verification flags: it is not an observation of desired state.
	if result == nil {
		return fmt.Errorf("network recovery returned no completion result; retaining finalizer")
	}
	if err := observeNetwork(&api.NetworkResourceStatus{}, result); err != nil {
		return err
	}
	return checkCurrent()
}

func (r *NetworkReconciler) networkRecoveryFailed(ctx context.Context, obj client.Object, cause error) error {
	before := obj.DeepCopyObject().(client.Object)
	_, status, _ := networkFields(obj)
	status.ObservedGeneration = obj.GetGeneration()
	status.Exists, status.ConfigurationVerified, status.RuntimeVerified, status.PersistenceVerified = false, false, false, false
	status.Observed.Raw = nil
	status.Observed.Object = nil
	for _, name := range []string{"Ready", "Synced", "ConfigurationReady", "RuntimeReady", "PersistenceReady"} {
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{Type: name, Status: metav1.ConditionUnknown, Reason: "RecoveryBlocked", Message: cause.Error(), ObservedGeneration: obj.GetGeneration()})
	}
	return errors.Join(cause, r.Status().Patch(ctx, obj, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})))
}
