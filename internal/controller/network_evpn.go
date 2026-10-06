// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	agentclient "github.com/ironcore-dev/sonic-operator/internal/agent/agent_client/client"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func vlanVNIOverlap(a, b *api.SwitchVLANVNI) bool {
	if a.Spec.VLANID == b.Spec.VLANID || a.Spec.VNI == b.Spec.VNI || a.Spec.RouteDistinguisher == b.Spec.RouteDistinguisher {
		return true
	}
	for _, targets := range [][]api.RouteIdentifier{a.Spec.ImportRouteTargets, a.Spec.ExportRouteTargets} {
		for _, rt := range targets {
			if slices.Contains(b.Spec.ImportRouteTargets, rt) || slices.Contains(b.Spec.ExportRouteTargets, rt) {
				return true
			}
		}
	}
	return false
}

// Shared neighbor identity is independent of address-family ownership. Both
// reconcilers check the other API, including endpoint aliases and deleting claims.
func (r *NetworkReconciler) checkEVPNNeighborClaims(ctx context.Context, obj client.Object, aliases map[string]bool) error {
	var bgps []api.SwitchBGPPeer
	var evpns []api.SwitchEVPNPeer
	switch o := obj.(type) {
	case *api.SwitchBGPPeer:
		bgps = []api.SwitchBGPPeer{*o}
		list := &api.SwitchEVPNPeerList{}
		if err := r.APIReader.List(ctx, list); err != nil {
			return err
		}
		evpns = list.Items
	case *api.SwitchEVPNPeer:
		evpns = []api.SwitchEVPNPeer{*o}
		list := &api.SwitchBGPPeerList{}
		if err := r.APIReader.List(ctx, list); err != nil {
			return err
		}
		bgps = list.Items
	default:
		return nil
	}
	for i := range bgps {
		bgp := &bgps[i]
		if !aliases[bgp.Spec.SwitchRef.Name] {
			continue
		}
		breq, _, err := networkDesired("BGPPeer", bgp)
		if err != nil {
			return fmt.Errorf("cannot validate shared BGP claim: %w", err)
		}
		var b api.SwitchBGPPeerSpec
		if err := json.Unmarshal(breq.Spec, &b); err != nil {
			return err
		}
		for j := range evpns {
			evpn := &evpns[j]
			if !aliases[evpn.Spec.SwitchRef.Name] {
				continue
			}
			ereq, _, err := networkDesired("EVPNPeer", evpn)
			if err != nil {
				return fmt.Errorf("cannot validate shared EVPN claim: %w", err)
			}
			var e api.SwitchEVPNPeerSpec
			if err := json.Unmarshal(ereq.Spec, &e); err != nil {
				return err
			}
			address, _ := redundancyIP(string(b.Address), false)
			if b.VRF != e.VRF || address.String() != string(e.Address) {
				continue
			}
			local, err := redundancyIP(string(b.LocalAddress), false)
			if err != nil || local.String() != string(e.LocalAddress) || b.RemoteASN != e.RemoteASN {
				return fmt.Errorf("BGP and EVPN claims disagree on shared neighbor ASN/localAddress")
			}
			// Up is not safe merely because the AF is staged. Native per-peer
			// export restrictions and activation ownership are not yet supported.
			if b.AdminState != api.AdminStateDown && ((len(e.MappingRefs) == 0 && e.Role != "Transit") || evpn.Spec.ManagementPolicy != api.NetworkManagementPolicyManage) {
				return fmt.Errorf("shared BGP neighbor requires managed explicit EVPN policy before activation")
			}
		}
	}
	return nil
}

// checkEVPNStaged reads actual shared-neighbor state; Kubernetes status alone
// cannot prove the neighbor is configured, persisted, or still staged Down.
func (r *NetworkReconciler) checkEVPNStaged(ctx context.Context, obj *api.SwitchEVPNPeer, sw *api.Switch, nc agentclient.NetworkClient) (func() error, error) {
	request, _, err := networkDesired("EVPNPeer", obj)
	if err != nil {
		return nil, err
	}
	var desired api.SwitchEVPNPeerSpec
	if err := json.Unmarshal(request.Spec, &desired); err != nil {
		return nil, err
	}
	list := &api.SwitchBGPPeerList{}
	if err := r.APIReader.List(ctx, list); err != nil {
		return nil, err
	}
	var shared *api.SwitchBGPPeer
	for i := range list.Items {
		peer := &list.Items[i]
		if peer.Spec.SwitchRef.Name != sw.Name {
			continue
		}
		address, err := redundancyIP(string(peer.Spec.Address), false)
		if err != nil || address.String() != string(desired.Address) || (peer.Spec.VRF != "" && peer.Spec.VRF != "default") {
			continue
		}
		if shared != nil {
			return nil, fmt.Errorf("multiple shared BGP neighbor claims")
		}
		shared = peer
	}
	if shared == nil || shared.UID == "" || !shared.DeletionTimestamp.IsZero() || shared.Spec.ManagementPolicy != api.NetworkManagementPolicyManage {
		return nil, fmt.Errorf("EVPN requires a live Manage SwitchBGPPeer on the same Switch")
	}
	sharedRequest, sharedTarget, err := networkDesired("BGPPeer", shared)
	if err != nil {
		return nil, err
	}
	peerReconciler := *r
	peerReconciler.Kind = "BGPPeer"
	fresh := func() error {
		if err := peerReconciler.checkNetworkCurrent(ctx, shared, sw, sharedTarget); err != nil {
			return err
		}
		return peerReconciler.checkNetworkClaims(ctx, shared, sw, sharedTarget)
	}
	if err := fresh(); err != nil {
		return nil, err
	}
	if saved := shared.Annotations[networkTargetAnnotation]; saved != "" && saved != networkBinding(shared, sw, "BGPPeer", sharedTarget) {
		return nil, fmt.Errorf("shared BGP target changed")
	}
	readCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	result, err := nc.GetNetworkResource(readCtx, sharedRequest)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("observe shared BGP neighbor: %w", err)
	}
	if result == nil || !result.Exists || !result.ConfigurationVerified || !result.PersistenceVerified {
		return nil, fmt.Errorf("shared BGP neighbor must be configured and persisted Down before EVPN staging")
	}
	return fresh, fresh()
}
