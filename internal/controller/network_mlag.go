// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"time"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	agentclient "github.com/ironcore-dev/sonic-operator/internal/agent/agent_client/client"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	switchutil "github.com/ironcore-dev/sonic-operator/internal/switch_util"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// checkMLAGPeer checks reciprocal intent and fresh device preflight. It never
// requires full peer ConfigurationReady: either side must be able to stage first.
// It returns a freshness check to repeat immediately before local Ensure.
func (r *NetworkReconciler) checkMLAGPeer(ctx context.Context, obj *api.SwitchMLAG, sw *api.Switch, local *agent.NetworkResult, manage bool) (fresh func() error, retErr error) {
	request, target, err := networkDesired("MLAG", obj)
	if err != nil {
		return nil, err
	}
	var desired api.SwitchMLAGSpec
	if err := json.Unmarshal(request.Spec, &desired); err != nil {
		return nil, err
	}
	peerSwitch := &api.Switch{}
	if err := r.APIReader.Get(ctx, client.ObjectKey{Name: desired.PeerSwitchRef.Name}, peerSwitch); err != nil {
		return nil, fmt.Errorf("MLAG peer switch: %w", err)
	}
	port, err := strconv.Atoi(peerSwitch.Spec.Management.Port)
	if peerSwitch.UID == "" || peerSwitch.UID == sw.UID || !peerSwitch.DeletionTimestamp.IsZero() || peerSwitch.Spec.Management.Host == "" || err != nil || port < 1 || port > 65535 || networkEndpoint(peerSwitch) == networkEndpoint(sw) {
		return nil, fmt.Errorf("MLAG requires live, distinct peer Switch UID and agent endpoint")
	}
	list := &api.SwitchMLAGList{}
	if err := r.APIReader.List(ctx, list); err != nil {
		return nil, err
	}
	var peer *api.SwitchMLAG
	for i := range list.Items {
		candidate := &list.Items[i]
		if candidate.Spec.SwitchRef.Name == peerSwitch.Name && candidate.Spec.DomainID == desired.DomainID {
			if peer != nil {
				return nil, fmt.Errorf("multiple MLAG peer claims")
			}
			peer = candidate
		}
	}
	if peer == nil || peer.UID == "" || !peer.DeletionTimestamp.IsZero() {
		return nil, fmt.Errorf("live reciprocal MLAG peer CR required")
	}
	peerRequest, peerTarget, err := networkDesired("MLAG", peer)
	if err != nil {
		return nil, fmt.Errorf("MLAG peer configuration: %w", err)
	}
	var remote api.SwitchMLAGSpec
	if err := json.Unmarshal(peerRequest.Spec, &remote); err != nil {
		return nil, err
	}
	if remote.PeerSwitchRef.Name != sw.Name || remote.LocalAddress != desired.PeerAddress || remote.PeerAddress != desired.LocalAddress || remote.KeepaliveInterval != desired.KeepaliveInterval || remote.SessionTimeout != desired.SessionTimeout {
		return nil, fmt.Errorf("MLAG peer must have reciprocal switches, addresses, domain and timers")
	}
	if manage && (desired.ManagementPolicy != api.NetworkManagementPolicyManage || remote.ManagementPolicy != api.NetworkManagementPolicyManage) {
		return nil, fmt.Errorf("both reciprocal MLAG configurations must be Manage")
	}
	if saved := peer.Annotations[networkTargetAnnotation]; saved != "" && saved != networkBinding(peer, peerSwitch, "MLAG", peerTarget) {
		return nil, fmt.Errorf("MLAG peer binding changed")
	}
	if err := r.checkNetworkClaims(ctx, peer, peerSwitch, peerTarget); err != nil {
		return nil, err
	}
	factory := r.NewAgentClient
	if factory == nil {
		factory = switchutil.NewAgentClientFromSwitchRef
	}
	a, err := factory(ctx, networkBoundReader{Reader: r.APIReader, target: peerSwitch}, &corev1.LocalObjectReference{Name: peerSwitch.Name}, "")
	if err != nil {
		return nil, err
	}
	if a == nil || (reflect.ValueOf(a).Kind() == reflect.Pointer && reflect.ValueOf(a).IsNil()) {
		return nil, fmt.Errorf("nil MLAG peer agent")
	}
	defer func() { retErr = errors.Join(retErr, closeAgentClient(a)) }()
	nc, ok := a.(agentclient.NetworkClient)
	if !ok {
		return nil, fmt.Errorf("MLAG peer agent lacks network capability")
	}
	readCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	remoteResult, err := nc.GetNetworkResource(readCtx, peerRequest)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("MLAG peer preflight: %w", err)
	}
	for _, result := range []*agent.NetworkResult{local, remoteResult} {
		var preflight struct {
			Eligible bool `json:"preflightEligible"`
		}
		if result == nil || json.Unmarshal(result.Observed, &preflight) != nil || !preflight.Eligible {
			return nil, fmt.Errorf("MLAG requires explicit local and peer preflightEligible capability, LAG and reachability evidence")
		}
	}
	fresh = func() error {
		if err := r.checkNetworkCurrent(ctx, peer, peerSwitch, peerTarget); err != nil {
			return fmt.Errorf("MLAG peer changed: %w", err)
		}
		if err := r.checkNetworkClaims(ctx, peer, peerSwitch, peerTarget); err != nil {
			return err
		}
		return r.checkNetworkCurrent(ctx, obj, sw, target)
	}
	return fresh, fresh()
}
