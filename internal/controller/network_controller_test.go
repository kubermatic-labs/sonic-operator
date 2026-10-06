// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	agentclient "github.com/ironcore-dev/sonic-operator/internal/agent/agent_client/client"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var networkTestSpecs = []struct{ kind, spec string }{
	{"PortChannel", `{"name":"PortChannel10","members":["Ethernet0","Ethernet4"]}`},
	{"VRF", `{"name":"VrfBlue"}`},
	{"L3Interface", `{"name":"Vlan10","addresses":["192.0.2.1/24","2001:db8::1/64"]}`},
	{"StaticRoute", `{"prefix":"203.0.113.0/24","nextHops":[{"address":"192.0.2.2"}]}`},
	{"BGP", `{"localASN":65001,"routerID":"192.0.2.1"}`},
	{"BGPPeer", `{"address":"192.0.2.2","remoteASN":65002,"addressFamilies":["ipv4Unicast"]}`},
	{"DHCPRelay", `{"vlanID":10,"ipv4Servers":["192.0.2.10"],"ipv6Servers":["2001:db8::10"]}`},
	{"FRRMigration", `{"mode":"Unified","approvedDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`},
	{"ACLPolicy", `{"name":"edge","family":"IPv4","defaultAction":"Drop","rules":[{"name":"web","priority":100,"action":"Permit","protocol":6,"destinationPort":443}]}`},
	{"ACLBinding", `{"policy":"edge","interfaces":["Ethernet0","PortChannel10"]}`},
	{"QoSMap", `{"name":"dscp","type":"DSCPToTC","entries":[{"from":0,"to":0},{"from":46,"to":5}]}`},
	{"Scheduler", `{"name":"weighted","algorithm":"DWRR","weight":10}`},
	{"QoSBinding", `{"interfaceName":"Ethernet0","dscpToTC":"dscp","queues":[{"index":0,"scheduler":"weighted"}]}`},
}

type networkTestAgent struct {
	agentclient.SwitchAgentClient
	current           *agent.NetworkResult
	readErr, writeErr error
	requests          []agent.NetworkRequest
	onRead            func()
	nilEnsure         bool
	recoveries        []agent.NetworkRequest
	recovery          *agent.NetworkResult
	recoverErr        error
	onRecover         func()
	nilRecovery       bool
}

type networkUnsupportedAgent struct{ agentclient.SwitchAgentClient }

func (a *networkTestAgent) GetNetworkResource(context.Context, *agent.NetworkRequest) (*agent.NetworkResult, error) {
	if a.onRead != nil {
		a.onRead()
	}
	return a.current, a.readErr
}

func (a *networkTestAgent) EnsureNetworkResource(_ context.Context, req *agent.NetworkRequest) (*agent.NetworkResult, error) {
	a.requests = append(a.requests, *req)
	if a.nilEnsure {
		return nil, nil
	}
	if a.writeErr != nil {
		return nil, a.writeErr
	}
	a.current = &agent.NetworkResult{Exists: true, ConfigurationVerified: true, RuntimeVerified: true, PersistenceVerified: true, Observed: json.RawMessage(`{"configured":true}`)}
	return a.current, nil
}

func networkFixture(t *testing.T, kind, spec string) (client.Object, *api.Switch, *networkTestAgent, client.WithWatch, *NetworkReconciler) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := api.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	obj, _, err := networkObjects(kind)
	if err != nil {
		t.Fatal(err)
	}
	payload := `{"metadata":{"name":"claim","uid":"claim-uid","generation":1},"spec":{"switchRef":{"name":"leaf"},"managementPolicy":"Manage",` + strings.TrimPrefix(spec, "{") + `}`
	if err := json.Unmarshal([]byte(payload), obj); err != nil {
		t.Fatal(err)
	}
	sw := &api.Switch{ObjectMeta: metav1.ObjectMeta{Name: "leaf", UID: "switch-uid"}, Spec: api.SwitchSpec{Management: api.Management{Host: "192.0.2.10", Port: "50051"}}}
	a := &networkTestAgent{current: &agent.NetworkResult{Observed: json.RawMessage(`{"present":false}`)}}
	if kind == "FRRMigration" {
		a.current.Observed = json.RawMessage(`{"preflightEligible":true,"adoptionDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","mode":"Unified"}`)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(obj).WithObjects(obj, sw).Build()
	r := &NetworkReconciler{Client: c, APIReader: c, Kind: kind, AllowNetworkConfig: true, NewAgentClient: func(context.Context, client.Reader, *corev1.LocalObjectReference, string) (agentclient.SwitchAgentClient, error) {
		return a, nil
	}}
	r.AllowFRRMigration = kind == "FRRMigration"
	r.AllowTrafficPolicy = isTrafficKind(kind)
	return obj, sw, a, c, r
}

func TestNetworkGatesAndIdempotency(t *testing.T) {
	t.Parallel()
	for _, resource := range networkTestSpecs {
		for _, mode := range []string{"default", "observe", "global observe", "gate disabled", "manage", "duplicate", "deletion", "nil response", "read failure", "malformed observation", "unsupported client", "nil client", "typed nil client", "missing reader"} {
			t.Run(resource.kind+"/"+mode, func(t *testing.T) {
				t.Parallel()
				obj, _, a, c, r := networkFixture(t, resource.kind, resource.spec)
				spec, _, _ := networkFields(obj)
				wantErr := false
				switch mode {
				case "default", "observe":
					b, _ := json.Marshal(spec)
					var fields map[string]any
					_ = json.Unmarshal(b, &fields)
					fields["managementPolicy"] = "Observe"
					if mode == "default" {
						fields["managementPolicy"] = ""
					}
					b, _ = json.Marshal(map[string]any{"spec": fields})
					if err := json.Unmarshal(b, obj); err != nil {
						t.Fatal(err)
					}
					if err := c.Update(t.Context(), obj); err != nil {
						t.Fatal(err)
					}
				case "global observe":
					r.ObserveOnly = true
				case "gate disabled":
					r.AllowNetworkConfig = false
				case "duplicate":
					other := obj.DeepCopyObject().(client.Object)
					other.SetName("other")
					other.SetUID("other-uid")
					other.SetResourceVersion("")
					if err := c.Create(t.Context(), other); err != nil {
						t.Fatal(err)
					}
					wantErr = true
				case "deletion":
					obj.SetFinalizers([]string{"test/hold"})
					if err := c.Update(t.Context(), obj); err != nil {
						t.Fatal(err)
					}
					if err := c.Delete(t.Context(), obj); err != nil {
						t.Fatal(err)
					}
				case "nil response":
					a.current = nil
					wantErr = true
				case "read failure":
					a.readErr = errors.New("offline")
					wantErr = true
				case "malformed observation":
					a.current.Observed = json.RawMessage(`[]`)
					wantErr = true
				case "unsupported client":
					r.NewAgentClient = func(context.Context, client.Reader, *corev1.LocalObjectReference, string) (agentclient.SwitchAgentClient, error) {
						return &networkUnsupportedAgent{}, nil
					}
					wantErr = true
				case "nil client":
					r.NewAgentClient = func(context.Context, client.Reader, *corev1.LocalObjectReference, string) (agentclient.SwitchAgentClient, error) {
						return nil, nil
					}
					wantErr = true
				case "typed nil client":
					r.NewAgentClient = func(context.Context, client.Reader, *corev1.LocalObjectReference, string) (agentclient.SwitchAgentClient, error) {
						return (*networkTestAgent)(nil), nil
					}
					wantErr = true
				case "missing reader":
					r.APIReader = nil
					wantErr = true
				}
				for i := 0; i < 3; i++ {
					_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)})
					if (err != nil) != wantErr {
						t.Fatalf("reconcile %d: %v, wantErr=%v", i, err, wantErr)
					}
				}
				wantWrites := 0
				if mode == "manage" {
					wantWrites = 1
				}
				if len(a.requests) != wantWrites {
					t.Fatalf("writes=%d, want %d", len(a.requests), wantWrites)
				}
				if wantWrites > 0 && (a.requests[0].Kind != resource.kind || a.requests[0].OwnerID != string(obj.GetUID())) {
					t.Fatalf("wrong request: %+v", a.requests[0])
				}
				if mode == "read failure" || mode == "nil response" || mode == "malformed observation" {
					if err := c.Get(t.Context(), client.ObjectKeyFromObject(obj), obj); err != nil {
						t.Fatal(err)
					}
					_, status, _ := networkFields(obj)
					if condition := meta.FindStatusCondition(status.Conditions, "Ready"); condition == nil || condition.Status != metav1.ConditionUnknown {
						t.Fatalf("observation failure must be Unknown: %+v", status)
					}
				}
			})
		}
	}
}

func TestNetworkFreshness(t *testing.T) {
	t.Parallel()
	for _, resource := range networkTestSpecs {
		for _, change := range []string{"endpoint", "spec", "deletion", "duplicate"} {
			t.Run(resource.kind+"/"+change, func(t *testing.T) {
				t.Parallel()
				obj, sw, a, c, r := networkFixture(t, resource.kind, resource.spec)
				a.onRead = func() {
					switch change {
					case "endpoint":
						sw.Spec.Management.Host = "192.0.2.99"
						if err := c.Update(t.Context(), sw); err != nil {
							t.Fatal(err)
						}
					case "spec":
						if err := c.Get(t.Context(), client.ObjectKeyFromObject(obj), obj); err != nil {
							t.Fatal(err)
						}
						if err := json.Unmarshal([]byte(`{"spec":{"managementPolicy":"Observe"}}`), obj); err != nil {
							t.Fatal(err)
						}
						if err := c.Update(t.Context(), obj); err != nil {
							t.Fatal(err)
						}
					case "deletion":
						if err := c.Delete(t.Context(), obj); err != nil {
							t.Fatal(err)
						}
					case "duplicate":
						other := obj.DeepCopyObject().(client.Object)
						other.SetName("new-claim")
						other.SetUID("new-uid")
						other.SetResourceVersion("")
						if err := c.Create(t.Context(), other); err != nil {
							t.Fatal(err)
						}
					}
				}
				_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)})
				if err == nil || len(a.requests) != 0 {
					t.Fatalf("stale reconcile err=%v writes=%d", err, len(a.requests))
				}
			})
		}
	}
}

func TestNetworkIndependentConditions(t *testing.T) {
	t.Parallel()
	for _, resource := range networkTestSpecs {
		t.Run(resource.kind, func(t *testing.T) {
			t.Parallel()
			obj, _, a, c, r := networkFixture(t, resource.kind, resource.spec)
			r.ObserveOnly = true
			a.current = &agent.NetworkResult{Exists: true, ConfigurationVerified: true, PersistenceVerified: true, Observed: json.RawMessage(`{"peer":{"state":"Idle"}}`)}
			if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}); err != nil {
				t.Fatal(err)
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(obj), obj); err != nil {
				t.Fatal(err)
			}
			_, status, _ := networkFields(obj)
			for _, name := range []string{"ConfigurationReady", "PersistenceReady"} {
				if !meta.IsStatusConditionTrue(status.Conditions, name) {
					t.Fatalf("%s: %+v", name, status.Conditions)
				}
			}
			if !meta.IsStatusConditionFalse(status.Conditions, "RuntimeReady") || !meta.IsStatusConditionFalse(status.Conditions, "Ready") {
				t.Fatalf("runtime must stay unverified: %+v", status)
			}
			if string(status.Observed.Raw) != string(a.current.Observed) {
				t.Fatalf("observation lost: %s", status.Observed.Raw)
			}
		})
	}
}

func TestNetworkInvalidSpecNeverWrites(t *testing.T) {
	t.Parallel()
	for _, resource := range networkTestSpecs {
		for _, bad := range []string{"reference", "policy", "value", "duplicate"} {
			t.Run(resource.kind+"/"+bad, func(t *testing.T) {
				t.Parallel()
				obj, _, a, c, r := networkFixture(t, resource.kind, resource.spec)
				fields := map[string]any{}
				switch bad {
				case "reference":
					fields["switchRef"] = map[string]any{"name": ""}
				case "policy":
					fields["managementPolicy"] = "manage"
				case "value":
					if isTrafficKind(resource.kind) {
						fields = trafficInvalidFields(resource.kind, false)
					}
					switch resource.kind {
					case "PortChannel":
						fields["lacpMode"] = "static"
					case "VRF":
						fields["name"] = "mgmt"
					case "L3Interface":
						fields["addresses"] = []string{"192.0.2.1/99"}
					case "StaticRoute":
						fields["prefix"] = "192.0.2.1/24"
					case "BGP":
						fields["localASN"] = 0
					case "BGPPeer":
						fields["address"] = "2001:db8::bad::1"
					case "DHCPRelay":
						fields["ipv6Servers"] = []string{"192.0.2.1"}
					case "FRRMigration":
						fields["mode"] = "split"
					}
				case "duplicate":
					if isTrafficKind(resource.kind) {
						fields = trafficInvalidFields(resource.kind, true)
					}
					switch resource.kind {
					case "PortChannel":
						fields["members"] = []string{"Ethernet0", "Ethernet0"}
					case "VRF":
						fields["name"] = "default"
					case "L3Interface":
						fields["addresses"] = []string{"2001:db8::1/64", "2001:0db8::1/64"}
					case "StaticRoute":
						fields["nextHops"] = []any{map[string]any{"address": "192.0.2.2"}, map[string]any{"address": "192.0.2.2"}}
					case "BGP":
						fields["prefixes"] = []string{"192.0.2.0/24", "192.0.2.0/24"}
					case "BGPPeer":
						fields["addressFamilies"] = []string{"ipv4Unicast", "ipv4Unicast"}
					case "DHCPRelay":
						fields["ipv6Servers"] = []string{"2001:db8::1", "2001:0db8::1"}
					case "FRRMigration":
						fields["approvedDigest"] = strings.Repeat("A", 64)
					}
				}
				raw, err := json.Marshal(map[string]any{"spec": fields})
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(raw, obj); err != nil {
					t.Fatal(err)
				}
				if err := c.Update(t.Context(), obj); err != nil {
					t.Fatal(err)
				}
				if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}); err == nil {
					t.Fatal("invalid spec accepted")
				}
				if len(a.requests) != 0 {
					t.Fatal("invalid spec caused writes")
				}
			})
		}
	}
}

func TestNetworkBindingAndEndpointAliases(t *testing.T) {
	t.Parallel()
	for _, resource := range networkTestSpecs {
		for _, scenario := range []string{"endpoint after binding", "UID after binding", "alias claim", "runtime unverified", "write error", "nil ensure"} {
			t.Run(resource.kind+"/"+scenario, func(t *testing.T) {
				t.Parallel()
				obj, sw, a, c, r := networkFixture(t, resource.kind, resource.spec)
				key := client.ObjectKeyFromObject(obj)
				if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key}); err != nil {
					t.Fatal(err)
				}
				if len(a.requests) != 0 {
					t.Fatal("first write preceded durable binding")
				}
				if err := c.Get(t.Context(), key, obj); err != nil {
					t.Fatal(err)
				}
				if obj.GetAnnotations()[networkTargetAnnotation] == "" {
					t.Fatal("target was not bound")
				}
				wantErr := true
				switch scenario {
				case "endpoint after binding":
					sw.Spec.Management.Host = "192.0.2.99"
					if err := c.Update(t.Context(), sw); err != nil {
						t.Fatal(err)
					}
				case "UID after binding":
					sw.UID = "replaced"
					if err := c.Update(t.Context(), sw); err != nil {
						t.Fatal(err)
					}
				case "alias claim":
					alias := sw.DeepCopy()
					alias.Name = "alias"
					alias.UID = "alias-uid"
					alias.ResourceVersion = ""
					alias.Spec.Management.Port = "050051"
					if err := c.Create(t.Context(), alias); err != nil {
						t.Fatal(err)
					}
					other := obj.DeepCopyObject().(client.Object)
					other.SetName("alias-claim")
					other.SetUID("alias-claim-uid")
					other.SetResourceVersion("")
					_, _, common := networkFields(other)
					common.SwitchRef.Name = "alias"
					if err := c.Create(t.Context(), other); err != nil {
						t.Fatal(err)
					}
				case "runtime unverified":
					a.current.Exists = true
					a.current.ConfigurationVerified = true
					a.current.PersistenceVerified = true
					wantErr = false
				case "write error":
					a.writeErr = errors.New("save outcome unknown")
				case "nil ensure":
					a.nilEnsure = true
				}
				_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: key})
				if (err != nil) != wantErr {
					t.Fatalf("err=%v, wantErr=%v", err, wantErr)
				}
				wantWrites := 0
				if scenario == "write error" || scenario == "nil ensure" {
					wantWrites = 1
				}
				if len(a.requests) != wantWrites {
					t.Fatalf("writes=%d want=%d", len(a.requests), wantWrites)
				}
			})
		}
	}
}

func TestNetworkRequestDefaults(t *testing.T) {
	t.Parallel()
	for _, resource := range networkTestSpecs {
		t.Run(resource.kind, func(t *testing.T) {
			t.Parallel()
			obj, _, _, _, _ := networkFixture(t, resource.kind, resource.spec)
			req, target, err := networkDesired(resource.kind, obj)
			if err != nil {
				t.Fatal(err)
			}
			var spec map[string]any
			if err := json.Unmarshal(req.Spec, &spec); err != nil {
				t.Fatal(err)
			}
			if spec["switchRef"].(map[string]any)["name"] != "leaf" || spec["managementPolicy"] != "Manage" {
				t.Fatalf("missing common fields: %s", req.Spec)
			}
			switch resource.kind {
			case "FRRMigration":
				if req.Kind+"|"+target != "FRRMigration|unified" || spec["mode"] != "Unified" || spec["approvedDigest"] != strings.Repeat("a", 64) {
					t.Fatalf("migration identity or approval lost: target=%s spec=%s", target, req.Spec)
				}
			case "PortChannel":
				if spec["minLinks"] != float64(1) || spec["mtu"] != float64(9100) || spec["lacpMode"] != "active" || spec["adminState"] != "Up" {
					t.Fatalf("bad defaults: %s", req.Spec)
				}
			case "BGPPeer":
				if spec["adminState"] != "Down" || spec["maxPrefixes"] != float64(1000) {
					t.Fatalf("unsafe defaults: %s", req.Spec)
				}
			case "BGP":
				if prefixes, ok := spec["prefixes"]; ok && len(prefixes.([]any)) != 0 {
					t.Fatal("default advertises prefixes")
				}
			case "L3Interface":
				if spec["addresses"].([]any)[0] != "192.0.2.1/24" {
					t.Fatal("host bits lost")
				}
			case "StaticRoute":
				if spec["nextHops"].([]any)[0].(map[string]any)["distance"] != float64(1) {
					t.Fatal("distance default lost")
				}
			}
		})
	}
}

func TestNetworkPartialObservationError(t *testing.T) {
	t.Parallel()
	for _, resource := range networkTestSpecs {
		t.Run(resource.kind, func(t *testing.T) {
			t.Parallel()
			obj, _, a, c, r := networkFixture(t, resource.kind, resource.spec)
			a.current = &agent.NetworkResult{Exists: true, ConfigurationVerified: true, PersistenceVerified: true, Observed: json.RawMessage(`{"runtimeError":"unavailable"}`)}
			a.readErr = errors.New("runtime probe unavailable")
			if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}); err == nil {
				t.Fatal("probe error lost")
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(obj), obj); err != nil {
				t.Fatal(err)
			}
			_, status, _ := networkFields(obj)
			if !meta.IsStatusConditionTrue(status.Conditions, "ConfigurationReady") || !meta.IsStatusConditionTrue(status.Conditions, "PersistenceReady") {
				t.Fatalf("independent proof lost: %+v", status)
			}
			if got := meta.FindStatusCondition(status.Conditions, "Ready"); got == nil || got.Status != metav1.ConditionUnknown {
				t.Fatalf("readiness on failed probe: %+v", got)
			}
			if len(a.requests) != 0 {
				t.Fatal("observation error caused writes")
			}
		})
	}
}
