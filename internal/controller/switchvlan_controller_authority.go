// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"strconv"
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
)

const (
	vlanAuthorityFinalizer        = "sonic.networking.metal.ironcore.dev/vlan-authority"
	vlanAuthorityTargetAnnotation = "sonic.networking.metal.ironcore.dev/vlan-authority-target"
)

var vlanAuthorityDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func (r *SwitchVLANReconciler) reconcileVLANAuthority(ctx context.Context, req ctrl.Request) (result ctrl.Result, retErr error) {
	if r.APIReader == nil {
		return ctrl.Result{}, fmt.Errorf("authoritative VLANs require an uncached APIReader")
	}
	v := &api.SwitchVLAN{}
	if err := r.APIReader.Get(ctx, req.NamespacedName, v); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	deleting := !v.DeletionTimestamp.IsZero()
	if deleting && !controllerutil.ContainsFinalizer(v, vlanAuthorityFinalizer) {
		return ctrl.Result{}, nil
	}
	original := v.DeepCopy()
	removed, synced := false, false
	reason, message := "AuthorityBlocked", "Authoritative VLAN configuration is not confirmed"
	v.Status.ObservedGeneration = v.Generation
	v.Status.Exists, v.Status.Members = nil, nil
	v.Status.AdoptionDigest = ""
	v.Status.RuntimeVerified, v.Status.PersistenceVerified = false, false
	defer func() {
		if removed {
			return
		}
		state := metav1.ConditionFalse
		if retErr != nil {
			message = retErr.Error()
		} else if synced {
			state = metav1.ConditionTrue
		}
		for _, name := range []string{"Ready", "Synced"} {
			meta.SetStatusCondition(&v.Status.Conditions, metav1.Condition{Type: name, Status: state, Reason: reason, Message: message, ObservedGeneration: v.Generation})
		}
		if !reflect.DeepEqual(original.Status, v.Status) {
			if err := r.Status().Patch(ctx, v, client.MergeFromWithOptions(original, client.MergeFromWithOptimisticLock{})); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("update SwitchVLAN authority status: %w", err))
			}
		}
	}()
	result.RequeueAfter = 60 * time.Second
	if v.UID == "" || v.Spec.SwitchRef.Name == "" || v.Spec.VLANID < 1 || v.Spec.VLANID > 4094 {
		return result, fmt.Errorf("valid CR UID, switch reference and VLAN ID are required")
	}
	if v.Spec.ReconcilePolicy != api.VLANReconcilePolicyAuthoritative {
		return result, fmt.Errorf("cannot downshift an owned or finalized VLAN to Additive; restore Authoritative and use Orphan deletion to release ownership")
	}
	if v.Spec.ManagementPolicy != "" && v.Spec.ManagementPolicy != api.VLANManagementPolicyObserve && v.Spec.ManagementPolicy != api.VLANManagementPolicyManage {
		return result, fmt.Errorf("invalid management policy")
	}
	if v.Spec.DeletionPolicy != "" && v.Spec.DeletionPolicy != api.VLANDeletionPolicyOrphan && v.Spec.DeletionPolicy != api.VLANDeletionPolicyDelete {
		return result, fmt.Errorf("invalid deletion policy")
	}
	if v.Spec.AdoptionDigest != "" && !vlanAuthorityDigest.MatchString(v.Spec.AdoptionDigest) {
		return result, fmt.Errorf("adoptionDigest must be a lowercase SHA256 digest")
	}
	desired := &agent.VLAN{ID: v.Spec.VLANID}
	seen := map[string]bool{}
	for _, m := range v.Spec.Members {
		if seen[m.InterfaceName] || !vlanEthernetName.MatchString(m.InterfaceName) || (m.TaggingMode != "tagged" && m.TaggingMode != "untagged") {
			return result, fmt.Errorf("invalid or duplicate desired member %q", m.InterfaceName)
		}
		seen[m.InterfaceName] = true
		desired.Members = append(desired.Members, agent.VLANMember{InterfaceName: m.InterfaceName, TaggingMode: m.TaggingMode})
	}
	s := &api.Switch{}
	if err := r.APIReader.Get(ctx, client.ObjectKey{Name: v.Spec.SwitchRef.Name}, s); err != nil {
		return result, err
	}
	port, portErr := strconv.Atoi(s.Spec.Management.Port)
	if s.UID == "" || !s.DeletionTimestamp.IsZero() || s.Spec.Management.Host == "" || portErr != nil || port < 1 || port > 65535 {
		return result, fmt.Errorf("a live Switch UID and explicit valid agent host/port are required; implicit localhost is unsafe")
	}
	identity := vlanAuthorityTargetIdentity(v, s)
	binding := v.Annotations[vlanAuthorityTargetAnnotation]
	if controllerutil.ContainsFinalizer(v, vlanAuthorityFinalizer) && binding == "" {
		return result, fmt.Errorf("finalized VLAN lost its target binding; restore the binding before any ownership or cleanup operation")
	}
	if (binding != "" && binding != identity) || (v.Status.TargetIdentity != "" && v.Status.TargetIdentity != identity) {
		return result, fmt.Errorf("switch identity or endpoint changed; restore the original target before reconciling or releasing ownership")
	}
	if err := r.checkVLANAuthorityCurrent(ctx, v, s); err != nil {
		return result, err
	}
	factory := r.NewAgentClient
	if factory == nil {
		factory = switchUtil.NewAgentClientFromSwitchRef
	}
	// Pin the actual dial target to the Switch snapshot checked above, rather
	// than letting a second factory lookup select a newly changed endpoint.
	a, err := factory(ctx, vlanAuthorityReader{Reader: r.APIReader, target: s}, &corev1.LocalObjectReference{Name: s.Name}, "")
	if err != nil {
		return result, err
	}
	if a == nil {
		return result, fmt.Errorf("agent client is nil")
	}
	defer func() { retErr = errors.Join(retErr, closeAgentClient(a)) }()
	vc, ok := a.(agentclient.VLANAuthorityClient)
	if !ok {
		return result, fmt.Errorf("agent client does not support VLAN authority")
	}
	snapshot, err := vc.GetVLANAuthority(ctx, v.Spec.VLANID)
	if err != nil {
		return result, fmt.Errorf("observe VLAN authority: %w", err)
	}
	match, err := observeVLANAuthority(v, snapshot)
	if err != nil {
		return result, err
	}
	owner := string(v.UID)
	if snapshot.OwnerID != "" && snapshot.OwnerID != owner {
		return result, fmt.Errorf("VLAN is owned by another UID %q; ownership cannot transfer", snapshot.OwnerID)
	}
	if snapshot.OwnerID == owner && binding == "" {
		return result, fmt.Errorf("agent ownership exists without a persisted target binding; manual recovery required")
	}
	if deleting {
		// A successful authority read is required even for a never-owned claim.
		// An absent VLAN alone is not proof that a pending save is complete.
		if snapshot.OwnerID != "" {
			if err := r.vlanAuthorityWriteGuard(v); err != nil {
				return result, err
			}
			if err := r.checkVLANAuthorityCurrent(ctx, v, s); err != nil {
				return result, err
			}
			if v.Spec.DeletionPolicy == api.VLANDeletionPolicyDelete {
				response, err := vc.ReconcileVLANAuthority(ctx, &agent.VLANAuthorityRequest{OwnerID: owner, VLAN: &agent.VLAN{ID: v.Spec.VLANID}, Delete: true})
				v.Status.Exists, v.Status.Members = nil, nil
				v.Status.RuntimeVerified, v.Status.PersistenceVerified = false, false
				if err != nil {
					return result, fmt.Errorf("delete authoritative VLAN: %w", err)
				}
				if _, err := observeVLANAuthority(v, response); err != nil {
					return result, err
				}
				if response.OwnerID != owner || response.VLAN != nil || !response.RuntimeVerified || !response.PersistenceVerified {
					return result, fmt.Errorf("agent did not confirm owned VLAN deletion and persistence")
				}
			}
			// Delete retains ownership until its save is confirmed; Orphan reaches
			// only this call and never changes VLAN configuration or saves it.
			if err := r.checkVLANAuthorityCurrent(ctx, v, s); err != nil {
				return result, err
			}
			if err := vc.ReleaseVLANAuthority(ctx, v.Spec.VLANID, owner); err != nil {
				return result, fmt.Errorf("release VLAN authority (pending persistence must be recovered first): %w", err)
			}
			after, err := vc.GetVLANAuthority(ctx, v.Spec.VLANID)
			if err != nil {
				return result, fmt.Errorf("confirm authority release: %w", err)
			}
			if _, err := observeVLANAuthority(v, after); err != nil {
				return result, err
			}
			if after.OwnerID != "" {
				return result, fmt.Errorf("agent still reports an owner after release")
			}
		}
		if err := r.checkVLANAuthorityCurrent(ctx, v, s); err != nil {
			return result, err
		}
		patch := client.MergeFromWithOptions(v.DeepCopy(), client.MergeFromWithOptimisticLock{})
		controllerutil.RemoveFinalizer(v, vlanAuthorityFinalizer)
		if err := r.Patch(ctx, v, patch); err != nil {
			return result, err
		}
		removed = true
		return ctrl.Result{}, nil
	}
	if original.Status.OwnerID != "" && snapshot.OwnerID == "" {
		return result, fmt.Errorf("previously confirmed ownership disappeared; manual recovery required, refusing automatic re-adoption")
	}
	v.Status.OwnerID = snapshot.OwnerID
	if snapshot.OwnerID == "" && snapshot.VLAN != nil && v.Spec.AdoptionDigest != snapshot.Digest {
		reason, message = "AdoptionRequired", "Review status.members and status.adoptionDigest, then explicitly set spec.adoptionDigest to approve entire-VLAN takeover"
		return result, nil
	}
	if err := r.vlanAuthorityWriteGuard(v); err != nil {
		reason, message = "WritesDisabled", err.Error()
		// Observation confirms configuration only; it does not claim ownership.
		synced = match
		return result, nil
	}
	if !controllerutil.ContainsFinalizer(v, vlanAuthorityFinalizer) || binding == "" {
		if err := r.checkVLANAuthorityCurrent(ctx, v, s); err != nil {
			return result, err
		}
		patch := client.MergeFromWithOptions(v.DeepCopy(), client.MergeFromWithOptimisticLock{})
		controllerutil.AddFinalizer(v, vlanAuthorityFinalizer)
		if v.Annotations == nil {
			v.Annotations = map[string]string{}
		}
		v.Annotations[vlanAuthorityTargetAnnotation] = identity
		if err := r.Patch(ctx, v, patch); err != nil {
			return result, err
		}
		// Metadata is durable before the first agent mutation, even if the
		// subsequent status patch fails or the controller crashes.
		original = v.DeepCopy()
		v.Status.TargetIdentity = identity
		reason, message = "AuthorityPrepared", "Target binding and finalizer persisted; requeue before the first write"
		return ctrl.Result{RequeueAfter: time.Second}, nil
	}
	v.Status.TargetIdentity = identity
	if err := r.checkVLANAuthorityCurrent(ctx, v, s); err != nil {
		return result, err
	}
	response, err := vc.ReconcileVLANAuthority(ctx, &agent.VLANAuthorityRequest{OwnerID: owner, VLAN: desired, AdoptionDigest: v.Spec.AdoptionDigest})
	v.Status.Exists, v.Status.Members = nil, nil
	v.Status.RuntimeVerified, v.Status.PersistenceVerified = false, false
	if err != nil {
		return result, fmt.Errorf("reconcile VLAN authority: %w", err)
	}
	match, err = observeVLANAuthority(v, response)
	if err != nil {
		return result, err
	}
	if response.OwnerID != owner || !match || !response.RuntimeVerified || !response.PersistenceVerified {
		return result, fmt.Errorf("agent did not confirm ownership, entire desired membership and persistence")
	}
	v.Status.OwnerID = owner
	synced = true
	reason, message = "AuthorityConfirmed", "Entire VLAN membership and persistence confirmed; CONFIG_DB verification is not forwarding health"
	return result, nil
}

func (r *SwitchVLANReconciler) vlanAuthorityWriteGuard(v *api.SwitchVLAN) error {
	if r.ObserveOnly || !r.AllowAuthoritativeVLANs || v.Spec.ManagementPolicy != api.VLANManagementPolicyManage {
		return fmt.Errorf("authority writes/release require managementPolicy=Manage, observe-only=false and allow-authoritative-vlans=true; agent read-only and authority gates must also permit writes")
	}
	return nil
}

func observeVLANAuthority(v *api.SwitchVLAN, snapshot *agent.VLANAuthorityResult) (bool, error) {
	if snapshot == nil || !vlanAuthorityDigest.MatchString(snapshot.Digest) {
		return false, fmt.Errorf("agent returned missing/invalid authority snapshot digest")
	}
	if snapshot.VLAN == nil {
		v.Status.Exists, v.Status.Members = new(false), nil
	} else {
		// Reuse observation validation but not additive mode-conflict semantics.
		copy := v.DeepCopy()
		copy.Spec.Members = nil
		if _, err := observeVLAN(copy, snapshot.VLAN); err != nil {
			return false, err
		}
		v.Status.Exists, v.Status.Members = copy.Status.Exists, copy.Status.Members
	}
	v.Status.AdoptionDigest = snapshot.Digest
	v.Status.RuntimeVerified, v.Status.PersistenceVerified = snapshot.RuntimeVerified, snapshot.PersistenceVerified
	// A missing journal can still provide configuration preview, but an empty
	// OwnerID is not proof of release. Check every read/write confirmation here
	// before any caller uses ownership, including finalizer removal.
	if !snapshot.OwnershipKnown {
		return false, fmt.Errorf("VLAN ownership is unknown; configure or restore the agent's persistent authority journal before adoption, writes or finalizer cleanup")
	}
	if snapshot.VLAN == nil || len(snapshot.VLAN.Members) != len(v.Spec.Members) {
		return false, nil
	}
	observed := map[string]string{}
	for _, m := range snapshot.VLAN.Members {
		observed[m.InterfaceName] = m.TaggingMode
	}
	for _, m := range v.Spec.Members {
		if observed[m.InterfaceName] != m.TaggingMode {
			return false, nil
		}
	}
	return true, nil
}

func vlanAuthorityTargetIdentity(v *api.SwitchVLAN, s *api.Switch) string {
	data, _ := json.Marshal([]any{v.UID, v.Spec.SwitchRef.Name, v.Spec.VLANID, s.UID, s.Spec.Management, s.Spec.MacAddress})
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func (r *SwitchVLANReconciler) checkVLANAuthorityCurrent(ctx context.Context, v *api.SwitchVLAN, s *api.Switch) error {
	latest := &api.SwitchVLAN{}
	if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(v), latest); err != nil {
		return err
	}
	if latest.UID != v.UID || latest.Generation != v.Generation || !reflect.DeepEqual(latest.Spec, v.Spec) || !reflect.DeepEqual(latest.Finalizers, v.Finalizers) || !reflect.DeepEqual(latest.DeletionTimestamp, v.DeletionTimestamp) || latest.Annotations[vlanAuthorityTargetAnnotation] != v.Annotations[vlanAuthorityTargetAnnotation] {
		return fmt.Errorf("VLAN claim changed or deletion started; retry without writing")
	}
	sw := &api.Switch{}
	if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(s), sw); err != nil {
		return err
	}
	if !sw.DeletionTimestamp.IsZero() || vlanAuthorityTargetIdentity(v, sw) != vlanAuthorityTargetIdentity(v, s) {
		return fmt.Errorf("switch identity or endpoint changed; no authority operations allowed")
	}
	// Duplicate Switch objects pointing at one endpoint are also ambiguous.
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
	claims := &api.SwitchVLANList{}
	if err := r.APIReader.List(ctx, claims); err != nil {
		return err
	}
	for _, other := range claims.Items {
		if other.Name != v.Name && aliases[other.Spec.SwitchRef.Name] && other.Spec.VLANID == v.Spec.VLANID {
			return fmt.Errorf("SwitchVLAN %q also claims this VLAN endpoint; no authority operations allowed", other.Name)
		}
	}
	return nil
}

type vlanAuthorityReader struct {
	client.Reader
	target *api.Switch
}

func (r vlanAuthorityReader) Get(ctx context.Context, key client.ObjectKey, object client.Object, opts ...client.GetOption) error {
	if s, ok := object.(*api.Switch); ok && key == client.ObjectKeyFromObject(r.target) {
		r.target.DeepCopyInto(s)
		return nil
	}
	return r.Reader.Get(ctx, key, object, opts...)
}
