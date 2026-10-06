// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"testing"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	agentclient "github.com/ironcore-dev/sonic-operator/internal/agent/agent_client/client"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var redundancyTestSpecs = []struct{ kind, spec, target string }{
	{"MLAG", `{"domainID":1,"peerSwitchRef":{"name":"peer"},"localAddress":"192.0.2.1","peerAddress":"192.0.2.2","peerLink":"PortChannel10","members":["PortChannel20"]}`, "1"},
	{"VXLANTunnel", `{"name":"vtep","sourceAddress":"192.0.2.1","evpnNVO":"nvo"}`, "vtep"},
	{"VLANVNI", `{"tunnel":"vtep","vlanID":10,"vni":10010,"routeDistinguisher":"65000:10","importRouteTargets":["65000:10"],"exportRouteTargets":["65000:10"]}`, "vtep|10"},
	{"EVPNPeer", `{"address":"2001:0db8::2","remoteASN":65002,"localAddress":"2001:db8::1"}`, "default|2001:db8::2"},
	{"EVPN", `{"tunnel":"vtep","adminState":"Down"}`, "default"},
}

type redundancyReadAgent struct {
	*networkTestAgent
	reads []agent.NetworkRequest
}

func (a *redundancyReadAgent) GetNetworkResource(ctx context.Context, req *agent.NetworkRequest) (*agent.NetworkResult, error) {
	a.reads = append(a.reads, *req)
	return a.networkTestAgent.GetNetworkResource(ctx, req)
}

func mlagFixture(t *testing.T) (*api.SwitchMLAG, *api.SwitchMLAG, *api.Switch, *networkTestAgent, *redundancyReadAgent, client.WithWatch, *NetworkReconciler) {
	t.Helper()
	obj, _, a, c, r := networkFixture(t, "MLAG", redundancyTestSpecs[0].spec)
	peer := obj.(*api.SwitchMLAG).DeepCopy()
	peer.Name, peer.UID, peer.ResourceVersion = "peer-claim", "peer-claim-uid", ""
	peer.Spec.SwitchRef.Name, peer.Spec.PeerSwitchRef.Name = "peer", "leaf"
	peer.Spec.LocalAddress, peer.Spec.PeerAddress = peer.Spec.PeerAddress, peer.Spec.LocalAddress
	sw := &api.Switch{ObjectMeta: metav1.ObjectMeta{Name: "peer", UID: "peer-switch-uid"}, Spec: api.SwitchSpec{Management: api.Management{Host: "192.0.2.11", Port: "50051"}}}
	for _, o := range []client.Object{peer, sw} {
		if err := c.Create(t.Context(), o); err != nil {
			t.Fatal(err)
		}
	}
	pa := &redundancyReadAgent{networkTestAgent: &networkTestAgent{current: &agent.NetworkResult{Observed: json.RawMessage(`{"preflightEligible":true}`)}}}
	a.current.Observed = json.RawMessage(`{"preflightEligible":true}`)
	r.AllowRedundancy = true
	r.NewAgentClient = func(_ context.Context, _ client.Reader, ref *corev1.LocalObjectReference, _ string) (agentclient.SwitchAgentClient, error) {
		if ref.Name == "peer" {
			return pa, nil
		}
		return a, nil
	}
	return obj.(*api.SwitchMLAG), peer, sw, a, pa, c, r
}

func TestMLAGReciprocalStaging(t *testing.T) {
	for _, mode := range []string{"staged", "missing", "observe peer", "asymmetric address", "asymmetric domain", "asymmetric timers", "nonreciprocal", "same UID", "endpoint alias", "deleted peer", "deleted switch", "unsupported", "unreachable", "nil peer result", "stale peer", "stale endpoint"} {
		t.Run(mode, func(t *testing.T) {
			obj, peer, sw, a, pa, c, r := mlagFixture(t)
			switch mode {
			case "missing":
				if err := c.Delete(t.Context(), peer); err != nil {
					t.Fatal(err)
				}
			case "observe peer":
				peer.Spec.ManagementPolicy = api.NetworkManagementPolicyObserve
			case "asymmetric address":
				peer.Spec.PeerAddress = "192.0.2.3"
			case "asymmetric domain":
				peer.Spec.DomainID = 2
			case "asymmetric timers":
				peer.Spec.SessionTimeout = 31
			case "nonreciprocal":
				peer.Spec.PeerSwitchRef.Name = "other"
			case "same UID":
				sw.UID = "switch-uid"
			case "endpoint alias":
				sw.Spec.Management.Host = "::ffff:192.0.2.10"
				sw.Spec.Management.Port = "050051"
			case "deleted peer":
				peer.Finalizers = []string{"test/hold"}
			case "deleted switch":
				sw.Finalizers = []string{"test/hold"}
			case "unsupported":
				pa.current.Observed = json.RawMessage(`{}`)
			case "unreachable":
				pa.readErr = errors.New("underlay unreachable")
			case "nil peer result":
				pa.current = nil
			case "stale peer":
				pa.onRead = func() {
					peer.Spec.ManagementPolicy = api.NetworkManagementPolicyObserve
					if err := c.Update(t.Context(), peer); err != nil {
						t.Fatal(err)
					}
				}
			case "stale endpoint":
				pa.onRead = func() {
					sw.Spec.Management.Host = "192.0.2.12"
					if err := c.Update(t.Context(), sw); err != nil {
						t.Fatal(err)
					}
				}
			}
			if mode != "missing" {
				if err := c.Update(t.Context(), peer); err != nil {
					t.Fatal(err)
				}
			}
			if err := c.Update(t.Context(), sw); err != nil {
				t.Fatal(err)
			}
			if mode == "deleted peer" {
				if err := c.Delete(t.Context(), peer); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "deleted switch" {
				if err := c.Delete(t.Context(), sw); err != nil {
					t.Fatal(err)
				}
			}
			req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}
			_, err := r.Reconcile(t.Context(), req)
			if mode == "staged" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := r.Reconcile(t.Context(), req); err != nil {
					t.Fatal(err)
				}
				if len(a.requests) != 1 {
					t.Fatal("reciprocal preflight must permit initial staging without either configuration ready")
				}
				if len(pa.reads) == 0 || pa.reads[0].OwnerID != string(peer.UID) {
					t.Fatal("peer not freshly probed with its own identity")
				}
			} else {
				if err == nil {
					t.Fatal("unsafe pair accepted")
				}
				if len(a.requests) != 0 {
					t.Fatal("unsafe pair wrote")
				}
			}
			if len(pa.requests) != 0 || len(pa.recoveries) != 0 {
				t.Fatal("local reconcile wrote peer")
			}
		})
	}
}

func TestRedundancyRecoveryGatesAndSelectors(t *testing.T) {
	for _, tc := range redundancyTestSpecs {
		for _, mode := range []string{"gate", "selector", "orphan"} {
			t.Run(tc.kind+"/"+mode, func(t *testing.T) {
				obj, sw, a, c, r := networkFixture(t, tc.kind, tc.spec)
				r.AllowRedundancy = true
				request, target, err := networkDesired(tc.kind, obj)
				if err != nil {
					t.Fatal(err)
				}
				obj.SetAnnotations(map[string]string{networkRequestAnnotation: string(request.Spec), networkTargetAnnotation: networkBinding(obj, sw, tc.kind, target)})
				obj.SetFinalizers([]string{networkRecoveryFinalizer})
				if mode == "gate" {
					r.AllowRedundancy = false
				}
				if mode == "selector" {
					spec, _, _ := networkFields(obj)
					changes := map[string]string{"MLAG": `{"domainID":2}`, "VXLANTunnel": `{"name":"other"}`, "VLANVNI": `{"tunnel":"other"}`, "EVPNPeer": `{"address":"2001:db8::3"}`, "EVPN": `{"tunnel":"other"}`}
					if err := json.Unmarshal([]byte(changes[tc.kind]), spec); err != nil {
						t.Fatal(err)
					}
				}
				if err := c.Update(t.Context(), obj); err != nil {
					t.Fatal(err)
				}
				if err := c.Delete(t.Context(), obj); err != nil {
					t.Fatal(err)
				}
				_, err = r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)})
				if mode == "orphan" {
					if err != nil || len(a.recoveries) != 1 {
						t.Fatalf("orphan recovery failed: %v", err)
					}
				} else {
					if err == nil || len(a.recoveries) != 0 {
						t.Fatalf("blocked recovery allowed: %v", err)
					}
					if err := c.Get(t.Context(), client.ObjectKeyFromObject(obj), obj); err != nil {
						t.Fatal(err)
					}
					if !slices.Contains(obj.GetFinalizers(), networkRecoveryFinalizer) {
						t.Fatal("lost blocked finalizer")
					}
				}
				if len(a.requests) != 0 {
					t.Fatal("deletion applied configuration")
				}
			})
		}
	}
}

func TestRedundancyContracts(t *testing.T) {
	for _, tc := range redundancyTestSpecs {
		t.Run(tc.kind, func(t *testing.T) {
			obj, _, a, _, r := networkFixture(t, tc.kind, tc.spec)
			before := obj.DeepCopyObject()
			req, target, err := networkDesired(tc.kind, obj)
			if err != nil || target != tc.target {
				t.Fatalf("target=%s err=%v", target, err)
			}
			if !reflect.DeepEqual(before, obj) {
				t.Fatal("defaulting mutated source")
			}
			var spec map[string]any
			if err := json.Unmarshal(req.Spec, &spec); err != nil {
				t.Fatal(err)
			}
			if tc.kind == "MLAG" && (spec["keepaliveInterval"] != float64(1) || spec["sessionTimeout"] != float64(30)) {
				t.Fatal("missing MLAG defaults")
			}
			if tc.kind == "EVPNPeer" && (spec["adminState"] != "Down" || spec["vrf"] != "default" || spec["address"] != "2001:db8::2") {
				t.Fatal("missing EVPN normalization")
			}
			if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}); err != nil {
				t.Fatal(err)
			}
			if len(a.requests) != 0 || len(a.recoveries) != 0 {
				t.Fatal("default redundancy gate permitted writes")
			}
		})
	}
}

var redundancyInvalidFields = map[string][]string{
	"EVPN":        {`{"tunnel":"bad|tunnel"}`, `{"adminState":"Up"}`, `{"adminState":"invalid"}`, `{"mappingRefs":[{"name":"a"},{"name":"a"}]}`},
	"MLAG":        {`{"domainID":0}`, `{"domainID":4096}`, `{"peerSwitchRef":{"name":"leaf"}}`, `{"localAddress":"2001:db8::1"}`, `{"peerAddress":"192.0.2.1"}`, `{"peerLink":"eth0"}`, `{"members":[]}`, `{"members":["PortChannel10"]}`, `{"members":["PortChannel20","PortChannel20"]}`, `{"sessionTimeout":1}`, `{"keepaliveInterval":61}`, `{"sessionTimeout":2}`, `{"localAddress":"0.0.0.0"}`, `{"peerAddress":"224.0.0.1"}`},
	"VXLANTunnel": {`{"name":"vtep|evil"}`, `{"sourceAddress":"2001:db8::1"}`, `{"evpnNVO":""}`},
	"VLANVNI":     {`{"vlanID":4095}`, `{"vni":0}`, `{"vni":16777216}`, `{"routeDistinguisher":"bad"}`, `{"routeDistinguisher":"4294967295:65536"}`, `{"importRouteTargets":[]}`, `{"exportRouteTargets":["65000:10","65000:10"]}`, `{"importRouteTargets":["192.0.2.1:65536"]}`},
	"EVPNPeer":    {`{"vrf":"VrfBlue"}`, `{"remoteASN":0}`, `{"address":"::ffff:192.0.2.2"}`, `{"localAddress":"192.0.2.1"}`, `{"adminState":"Enabled"}`},
}

func TestMLAGObserveReportsMissingPeer(t *testing.T) {
	obj, _, a, c, r := networkFixture(t, "MLAG", redundancyTestSpecs[0].spec)
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(obj), obj); err != nil {
		t.Fatal(err)
	}
	_, status, _ := networkFields(obj)
	if len(a.requests) != 0 || string(status.Observed.Raw) != string(a.current.Observed) {
		t.Fatal("missing peer prevented local observation or wrote")
	}
	if len(status.Conditions) == 0 || status.Conditions[0].Reason != "PeerNotReady" {
		t.Fatal("missing peer not reported")
	}
}

func TestMLAGPeerRevokedAfterBinding(t *testing.T) {
	obj, peer, _, a, _, c, r := mlagFixture(t)
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}
	if _, err := r.Reconcile(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	peer.Spec.ManagementPolicy = api.NetworkManagementPolicyObserve
	if err := c.Update(t.Context(), peer); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(t.Context(), req); err == nil {
		t.Fatal("revoked peer allowed Ensure")
	}
	if len(a.requests) != 0 {
		t.Fatal("revoked peer wrote")
	}
}

func TestRedundancyRejectInvalidSpecs(t *testing.T) {
	for _, tc := range redundancyTestSpecs {
		for _, bad := range redundancyInvalidFields[tc.kind] {
			t.Run(tc.kind+bad, func(t *testing.T) {
				obj, _, _, _, _ := networkFixture(t, tc.kind, tc.spec)
				spec, _, _ := networkFields(obj)
				if err := json.Unmarshal([]byte(bad), spec); err != nil {
					t.Fatal(err)
				}
				if _, _, err := networkDesired(tc.kind, obj); err == nil {
					t.Fatal("invalid redundancy spec accepted")
				}
			})
		}
	}
}

func TestEVPNSharedNeighborOwnership(t *testing.T) {
	for _, mode := range []string{"staged", "missing", "ASN conflict", "local conflict", "observe BGP", "not staged", "already up", "reverse conflict", "reverse activation"} {
		t.Run(mode, func(t *testing.T) {
			obj, _, a, c, r := networkFixture(t, "EVPNPeer", redundancyTestSpecs[3].spec)
			r.AllowRedundancy = true
			bgp := &api.SwitchBGPPeer{ObjectMeta: metav1.ObjectMeta{Name: "shared", UID: "shared-uid"}, Spec: api.SwitchBGPPeerSpec{NetworkResourceSpec: api.NetworkResourceSpec{SwitchRef: api.NetworkSwitchReference{Name: "leaf"}, ManagementPolicy: api.NetworkManagementPolicyManage}, Address: "2001:db8::2", LocalAddress: "2001:db8::1", RemoteASN: 65002, AddressFamilies: []string{"ipv6Unicast"}, AdminState: api.AdminStateDown}}
			switch mode {
			case "ASN conflict", "reverse conflict":
				bgp.Spec.RemoteASN++
			case "local conflict":
				bgp.Spec.LocalAddress = "2001:db8::3"
			case "observe BGP":
				bgp.Spec.ManagementPolicy = api.NetworkManagementPolicyObserve
			case "already up", "reverse activation":
				bgp.Spec.AdminState = api.AdminStateUp
			}
			if mode != "missing" {
				if err := c.Create(t.Context(), bgp); err != nil {
					t.Fatal(err)
				}
			}
			shared := &redundancyReadAgent{networkTestAgent: &networkTestAgent{current: &agent.NetworkResult{Exists: true, ConfigurationVerified: true, PersistenceVerified: true}}}
			if mode == "not staged" {
				shared.current.ConfigurationVerified = false
			}
			a.onRead = nil
			// Each connection can read both kinds; route requests by kind.
			r.NewAgentClient = func(context.Context, client.Reader, *corev1.LocalObjectReference, string) (agentclient.SwitchAgentClient, error) {
				return &evpnTestAgent{networkTestAgent: a, shared: shared}, nil
			}
			if mode == "reverse conflict" || mode == "reverse activation" {
				// Check the inverse claim guard directly; fixture registers only
				// the EVPN status subresource, not BGP reconciliation status.
				r.Kind = "BGPPeer"
				if err := r.checkEVPNNeighborClaims(t.Context(), bgp, map[string]bool{"leaf": true}); err == nil {
					t.Fatal("reverse shared-field conflict accepted")
				}
				return
			}
			req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}
			_, err := r.Reconcile(t.Context(), req)
			if mode == "staged" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := r.Reconcile(t.Context(), req); err != nil {
					t.Fatal(err)
				}
				if len(a.requests) != 1 || len(shared.reads) == 0 {
					t.Fatal("EVPN did not stage against freshly verified shared neighbor")
				}
			} else if err == nil || len(a.requests) != 0 {
				t.Fatalf("unsafe shared neighbor accepted: %v", err)
			}
		})
	}
}

type evpnTestAgent struct {
	*networkTestAgent
	shared *redundancyReadAgent
}

func (a *evpnTestAgent) GetNetworkResource(ctx context.Context, req *agent.NetworkRequest) (*agent.NetworkResult, error) {
	if req.Kind == "BGPPeer" {
		return a.shared.GetNetworkResource(ctx, req)
	}
	return a.networkTestAgent.GetNetworkResource(ctx, req)
}

func TestVLANVNIIsolationClaims(t *testing.T) {
	for _, mode := range []string{"vlan", "vni", "RD", "RT", "disjoint"} {
		t.Run(mode, func(t *testing.T) {
			obj, sw, _, c, r := networkFixture(t, "VLANVNI", redundancyTestSpecs[2].spec)
			other := obj.(*api.SwitchVLANVNI).DeepCopy()
			other.Name, other.UID, other.ResourceVersion = "other", "other-uid", ""
			other.Spec.Tunnel, other.Spec.VLANID, other.Spec.VNI, other.Spec.RouteDistinguisher = "other", 11, 10011, "65000:11"
			other.Spec.ImportRouteTargets, other.Spec.ExportRouteTargets = []api.RouteIdentifier{"65000:11"}, []api.RouteIdentifier{"65000:11"}
			switch mode {
			case "vlan":
				other.Spec.VLANID = 10
			case "vni":
				other.Spec.VNI = 10010
			case "RD":
				other.Spec.RouteDistinguisher = "65000:10"
			case "RT":
				other.Spec.ExportRouteTargets = []api.RouteIdentifier{"65000:10"}
			}
			if err := c.Create(t.Context(), other); err != nil {
				t.Fatal(err)
			}
			_, target, err := networkDesired("VLANVNI", obj)
			if err != nil {
				t.Fatal(err)
			}
			err = r.checkNetworkClaims(t.Context(), obj, sw, target)
			if (err == nil) != (mode == "disjoint") {
				t.Fatalf("isolation claim %s: %v", mode, err)
			}
		})
	}
}
