// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"strings"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func (r *NetworkReconciler) networkWritesDisabled(common *api.NetworkResourceSpec) bool {
	return r.ObserveOnly || !r.AllowNetworkConfig || common.ManagementPolicy != api.NetworkManagementPolicyManage ||
		(r.Kind == "FRRMigration" && !r.AllowFRRMigration) || (isTrafficKind(r.Kind) && !r.AllowTrafficPolicy) || (isRedundancyKind(r.Kind) && !r.AllowRedundancy)
}

// Check the fresh Get result, never the previously published Kubernetes status.
// Recovery deliberately bypasses this check and resumes only the original journal.
func approveNetworkFRRMigration(obj *api.SwitchFRRMigration, sw *api.Switch, result *agent.NetworkResult) error {
	spec := obj.Spec
	var observed struct {
		PreflightEligible bool   `json:"preflightEligible"`
		AdoptionDigest    string `json:"adoptionDigest"`
		Mode              string `json:"mode"`
		Classification    string `json:"classification"`
	}
	if result == nil || json.Unmarshal(result.Observed, &observed) != nil || observed.Mode != spec.Mode {
		return fmt.Errorf("FRR migration requires an eligible observed preflight")
	}
	// A completed migration can lose full-DB save proof after unrelated changes.
	// The backend's migration-complete evidence is owner- and mode-specific;
	// refreshing persistence is not a new transition or an empty-routing preflight.
	// Require the existing local ownership/recovery chain as well, so an unbound
	// claim cannot use terminal observation to bypass its initial approval.
	if observed.Classification == "migration-complete" && result.Exists && result.ConfigurationVerified && result.RuntimeVerified && !result.PersistenceVerified &&
		obj.UID != "" && sw.UID != "" && controllerutil.ContainsFinalizer(obj, networkRecoveryFinalizer) &&
		obj.Annotations[networkTargetAnnotation] == networkBinding(obj, sw, "FRRMigration", "unified") {
		saved := &api.SwitchFRRMigration{}
		saved.UID = obj.UID
		if json.Unmarshal([]byte(obj.Annotations[networkRequestAnnotation]), &saved.Spec) == nil &&
			saved.Spec.Mode == spec.Mode && saved.Spec.SwitchRef == spec.SwitchRef && saved.Spec.ManagementPolicy == api.NetworkManagementPolicyManage {
			if _, _, err := networkDesired("FRRMigration", saved); err == nil {
				return nil
			}
		}
	}
	if !observed.PreflightEligible {
		return fmt.Errorf("FRR migration requires an eligible observed preflight")
	}
	if !networkDigest.MatchString(spec.ApprovedDigest) || spec.ApprovedDigest != observed.AdoptionDigest {
		return fmt.Errorf("FRR migration approvedDigest must match the current observed adoptionDigest")
	}
	return nil
}

func networkBinding(obj client.Object, sw *api.Switch, kind, target string) string {
	raw, _ := json.Marshal([]any{obj.GetUID(), sw.Name, sw.UID, sw.Spec.Management, sw.Spec.MacAddress, kind, target})
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

func (r *NetworkReconciler) checkNetworkCurrent(ctx context.Context, obj client.Object, sw *api.Switch, target string) error {
	latest, _, _ := networkObjects(r.Kind)
	if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(obj), latest); err != nil {
		return err
	}
	want, _, _ := networkFields(obj)
	got, _, _ := networkFields(latest)
	if latest.GetUID() != obj.GetUID() || latest.GetGeneration() != obj.GetGeneration() || !latest.GetDeletionTimestamp().IsZero() || !reflect.DeepEqual(want, got) || latest.GetAnnotations()[networkTargetAnnotation] != obj.GetAnnotations()[networkTargetAnnotation] || latest.GetAnnotations()[networkRequestAnnotation] != obj.GetAnnotations()[networkRequestAnnotation] || !reflect.DeepEqual(latest.GetFinalizers(), obj.GetFinalizers()) {
		return fmt.Errorf("network claim changed or deletion started; retry without writing")
	}
	current := &api.Switch{}
	if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(sw), current); err != nil {
		return err
	}
	if !current.DeletionTimestamp.IsZero() || networkBinding(obj, current, r.Kind, target) != networkBinding(obj, sw, r.Kind, target) {
		return fmt.Errorf("Switch identity or endpoint changed; retry without writing")
	}
	return nil
}

func (r *NetworkReconciler) checkNetworkClaims(ctx context.Context, obj client.Object, sw *api.Switch, target string) error {
	switches := &api.SwitchList{}
	if err := r.APIReader.List(ctx, switches); err != nil {
		return err
	}
	aliases := map[string]bool{sw.Name: true}
	for _, other := range switches.Items {
		if networkEndpoint(&other) == networkEndpoint(sw) {
			aliases[other.Name] = true
		}
	}
	if err := r.checkEVPNNeighborClaims(ctx, obj, aliases); err != nil {
		return err
	}
	_, list, _ := networkObjects(r.Kind)
	if err := r.APIReader.List(ctx, list); err != nil {
		return err
	}
	return meta.EachListItem(list, func(item runtime.Object) error {
		other := item.(client.Object)
		if other.GetUID() == obj.GetUID() {
			return nil
		}
		if port, ok := other.(*api.SwitchInterface); ok && port.Spec.Speed == nil && port.Spec.MTU == nil && port.Spec.FEC == "" && !controllerutil.ContainsFinalizer(port, networkRecoveryFinalizer) {
			return nil // inventory alone does not claim speed/MTU/FEC
		}
		_, _, common := networkFields(other)
		if !aliases[common.SwitchRef.Name] {
			return nil
		}
		// Invalid claims cannot prove disjoint ownership. Deleting claims still
		// reserve their target until gone; Orphan leaves durable device ownership.
		_, otherTarget, err := networkDesired(r.Kind, other)
		if err != nil {
			return fmt.Errorf("cannot establish target of competing %s %q: %w", r.Kind, other.GetName(), err)
		}
		if otherTarget == target {
			return fmt.Errorf("%s %q also claims target %q on this switch", r.Kind, other.GetName(), target)
		}
		if mapping, ok := obj.(*api.SwitchVLANVNI); ok && vlanVNIOverlap(mapping, other.(*api.SwitchVLANVNI)) {
			return fmt.Errorf("VLANVNI %q overlaps VLAN, VNI, RD or route-target isolation", other.GetName())
		}
		return nil
	})
}

func networkEndpoint(sw *api.Switch) string {
	host := strings.ToLower(strings.TrimSuffix(sw.Spec.Management.Host, "."))
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.Unmap().String()
	}
	port := sw.Spec.Management.Port
	if n, err := strconv.Atoi(port); err == nil {
		port = strconv.Itoa(n)
	}
	return net.JoinHostPort(host, port)
}

// Freeze the selected Switch while the factory resolves its endpoint. All other
// reads, including credentials, still use the uncached API reader.
type networkBoundReader struct {
	client.Reader
	target *api.Switch
}

func (r networkBoundReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if sw, ok := obj.(*api.Switch); ok && key.Name == r.target.Name && key.Namespace == "" {
		r.target.DeepCopyInto(sw)
		return nil
	}
	return r.Reader.Get(ctx, key, obj, opts...)
}
