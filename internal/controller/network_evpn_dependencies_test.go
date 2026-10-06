// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"encoding/json"
	"testing"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestEVPNMappingReferencesFreshness(t *testing.T) {
	_, sw, _, c, r := networkFixture(t, "EVPNPeer", redundancyTestSpecs[3].spec)
	m := &api.SwitchVLANVNI{ObjectMeta: metav1.ObjectMeta{Name: "mapping", UID: "mapping-uid", Generation: 1}, Spec: api.SwitchVLANVNISpec{NetworkResourceSpec: api.NetworkResourceSpec{SwitchRef: api.NetworkSwitchReference{Name: sw.Name}, ManagementPolicy: api.NetworkManagementPolicyManage}, Tunnel: "vtep1", VLANID: 10, VNI: 100, RouteDistinguisher: "65001:100", ImportRouteTargets: []api.RouteIdentifier{"65001:100"}, ExportRouteTargets: []api.RouteIdentifier{"65001:100"}}}
	if err := c.Create(t.Context(), m); err != nil {
		t.Fatal(err)
	}
	refs := []api.NetworkSwitchReference{{Name: "mapping"}}
	snapshots, fresh, err := r.resolveEVPNMappings(t.Context(), sw, refs)
	if err != nil || len(snapshots) != 1 || snapshots[0].UID != "mapping-uid" {
		t.Fatalf("snapshots=%v err=%v", snapshots, err)
	}
	if err := fresh(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.resolveEVPNMappings(t.Context(), sw, append(refs, refs...)); err == nil {
		t.Fatal("duplicate reference accepted")
	}
	m.Spec.VNI++
	if err := c.Update(t.Context(), m); err != nil {
		t.Fatal(err)
	}
	if err := fresh(); err == nil {
		t.Fatal("changed mapping accepted")
	}
	m.Spec.SwitchRef.Name = "other"
	if err := c.Update(t.Context(), m); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.resolveEVPNMappings(t.Context(), sw, refs); err == nil {
		t.Fatal("cross-switch mapping accepted")
	}
	if err := c.Delete(t.Context(), m); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.resolveEVPNMappings(t.Context(), sw, refs); err == nil {
		t.Fatal("absent mapping accepted")
	}
}

func TestEVPNRecoveryKeepsResolvedSnapshot(t *testing.T) {
	obj, sw, a, c, r := networkFixture(t, "EVPNPeer", redundancyTestSpecs[3].spec)
	r.AllowRedundancy = true
	request, target, err := networkDesired("EVPNPeer", obj)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(request.Spec, &fields); err != nil {
		t.Fatal(err)
	}
	snapshot := []agent.EVPNMappingSnapshot{{Name: "original", UID: "original-uid", Generation: 7}}
	fields["mappings"], err = json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	obj.SetAnnotations(map[string]string{networkRequestAnnotation: string(raw), networkTargetAnnotation: networkBinding(obj, sw, "EVPNPeer", target)})
	if err := c.Update(t.Context(), obj); err != nil {
		t.Fatal(err)
	}
	if err := r.recoverNetwork(t.Context(), obj); err != nil {
		t.Fatal(err)
	}
	if len(a.recoveries) != 1 {
		t.Fatal("missing recovery")
	}
	var saved struct {
		Mappings []agent.EVPNMappingSnapshot `json:"mappings"`
	}
	if err := json.Unmarshal(a.recoveries[0].Spec, &saved); err != nil {
		t.Fatal(err)
	}
	if len(saved.Mappings) != 1 || saved.Mappings[0].UID != "original-uid" || saved.Mappings[0].Generation != 7 {
		t.Fatal("recovery lost original dependency snapshot")
	}
}
