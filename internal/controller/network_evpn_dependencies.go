// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (r *NetworkReconciler) resolveEVPNMappings(ctx context.Context, sw *api.Switch, refs []api.NetworkSwitchReference) ([]agent.EVPNMappingSnapshot, func() error, error) {
	if r.APIReader == nil || len(refs) == 0 || len(refs) > 64 {
		return nil, nil, fmt.Errorf("EVPN requires an API reader and 1..64 mapping references")
	}
	seen := map[string]bool{}
	originals := make([]*api.SwitchVLANVNI, 0, len(refs))
	result := make([]agent.EVPNMappingSnapshot, 0, len(refs))
	for _, ref := range refs {
		if seen[ref.Name] || len(validation.IsDNS1123Subdomain(ref.Name)) != 0 {
			return nil, nil, fmt.Errorf("invalid or duplicate EVPN mapping reference")
		}
		seen[ref.Name] = true
		m := &api.SwitchVLANVNI{}
		if err := r.APIReader.Get(ctx, client.ObjectKey{Name: ref.Name}, m); err != nil {
			return nil, nil, err
		}
		if m.UID == "" || m.Generation < 1 || !m.DeletionTimestamp.IsZero() || m.Spec.SwitchRef.Name != sw.Name || m.Spec.ManagementPolicy != api.NetworkManagementPolicyManage {
			return nil, nil, fmt.Errorf("EVPN requires live Manage mappings on the same switch")
		}
		if _, _, err := networkDesired("VLANVNI", m); err != nil {
			return nil, nil, err
		}
		stringsOf := func(values []api.RouteIdentifier) []string {
			out := make([]string, len(values))
			for i, v := range values {
				out[i] = string(v)
			}
			return out
		}
		result = append(result, agent.EVPNMappingSnapshot{Name: m.Name, UID: string(m.UID), Generation: m.Generation, Tunnel: string(m.Spec.Tunnel), VLANID: m.Spec.VLANID, VNI: m.Spec.VNI, RouteDistinguisher: string(m.Spec.RouteDistinguisher), ImportRouteTargets: stringsOf(m.Spec.ImportRouteTargets), ExportRouteTargets: stringsOf(m.Spec.ExportRouteTargets)})
		originals = append(originals, m.DeepCopy())
	}
	switchBefore := sw.DeepCopy()
	fresh := func() error {
		current := &api.Switch{}
		if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(switchBefore), current); err != nil {
			return err
		}
		if current.UID != switchBefore.UID || !current.DeletionTimestamp.IsZero() || !reflect.DeepEqual(current.Spec.Management, switchBefore.Spec.Management) {
			return fmt.Errorf("EVPN switch identity or endpoint changed")
		}
		for _, before := range originals {
			after := &api.SwitchVLANVNI{}
			if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(before), after); err != nil {
				return err
			}
			if after.UID != before.UID || after.Generation != before.Generation || !after.DeletionTimestamp.IsZero() || !reflect.DeepEqual(after.Spec, before.Spec) {
				return fmt.Errorf("referenced EVPN mapping changed")
			}
		}
		return nil
	}
	return result, fresh, nil
}

func (r *NetworkReconciler) resolveEVPNRequest(ctx context.Context, obj client.Object, sw *api.Switch, request *agent.NetworkRequest) (func() error, error) {
	var refs []api.NetworkSwitchReference
	switch o := obj.(type) {
	case *api.SwitchEVPNPeer:
		refs = o.Spec.MappingRefs
	case *api.SwitchEVPN:
		refs = o.Spec.MappingRefs
	}
	if len(refs) == 0 {
		return func() error { return nil }, nil
	}
	mappings, fresh, err := r.resolveEVPNMappings(ctx, sw, refs)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(request.Spec, &fields); err != nil {
		return nil, err
	}
	fields["mappings"], err = json.Marshal(mappings)
	if err != nil {
		return nil, err
	}
	request.Spec, err = json.Marshal(fields)
	return fresh, err
}
