// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type networkNoRecoveryClient struct {
	agentclient.SwitchAgentClient
	agentclient.NetworkClient
}

func TestNetworkRequiresRecoveryCapabilityBeforeEnsure(t *testing.T) {
	t.Parallel()
	obj, _, a, _, r := networkFixture(t, "BGP", networkTestSpecs[4].spec)
	r.NewAgentClient = func(context.Context, client.Reader, *corev1.LocalObjectReference, string) (agentclient.SwitchAgentClient, error) {
		return &networkNoRecoveryClient{NetworkClient: a}, nil
	}
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}); err == nil {
		t.Fatal("missing recovery capability accepted for management")
	}
	if len(a.requests) != 0 {
		t.Fatal("Ensure issued without recovery capability")
	}
}

func (a *networkTestAgent) RecoverNetworkResource(_ context.Context, req *agent.NetworkRequest) (*agent.NetworkResult, error) {
	a.recoveries = append(a.recoveries, *req)
	if a.onRecover != nil {
		a.onRecover()
	}
	if a.recoverErr != nil {
		return nil, a.recoverErr
	}
	if a.nilRecovery {
		return nil, nil
	}
	if a.recovery != nil {
		return a.recovery, nil
	}
	return &agent.NetworkResult{Message: "no pending network operation; configuration orphaned unchanged"}, nil
}

func TestNetworkRecoveryDeletion(t *testing.T) {
	t.Parallel()
	for _, resource := range networkTestSpecs {
		for _, scenario := range []string{"success", "new invalid spec", "save failed", "no pending", "nil result", "pending", "global observe", "gate disabled", "policy observe", "agent gate disabled", "recovery unsupported", "endpoint changed", "endpoint changes during recovery", "claim changes during recovery"} {
			t.Run(resource.kind+"/"+scenario, func(t *testing.T) {
				t.Parallel()
				obj, sw, a, c, r := networkFixture(t, resource.kind, resource.spec)
				key := client.ObjectKeyFromObject(obj)
				request := ctrl.Request{NamespacedName: key}
				if _, err := r.Reconcile(t.Context(), request); err != nil {
					t.Fatal(err)
				}
				if err := c.Get(t.Context(), key, obj); err != nil {
					t.Fatal(err)
				}
				if !slices.Contains(obj.GetFinalizers(), "sonic.networking.metal.ironcore.dev/network-recovery") {
					t.Fatal("missing pre-Ensure finalizer")
				}
				if len(a.requests) != 0 {
					t.Fatal("Ensure preceded finalizer persistence")
				}
				a.writeErr = errors.New("save pending")
				if _, err := r.Reconcile(t.Context(), request); err == nil {
					t.Fatal("expected uncertain write")
				}
				if len(a.requests) != 1 {
					t.Fatalf("writes=%d", len(a.requests))
				}
				original := a.requests[0]
				if err := c.Get(t.Context(), key, obj); err != nil {
					t.Fatal(err)
				}
				wantHold := scenario != "success" && scenario != "new invalid spec" && scenario != "no pending"
				wantRecovery := true
				switch scenario {
				case "new invalid spec":
					// Recovery must use the recorded request, not validate/apply new intent.
					switch o := obj.(type) {
					case *api.SwitchPortChannel:
						o.Spec.Members = nil
					case *api.SwitchVRF: /* no mutable fields */
					case *api.SwitchL3Interface:
						o.Spec.Addresses = nil
					case *api.SwitchStaticRoute:
						o.Spec.NextHops = nil
					case *api.SwitchBGP:
						o.Spec.LocalASN = 0
					case *api.SwitchBGPPeer:
						o.Spec.RemoteASN = 0
					case *api.SwitchDHCPRelay:
						o.Spec.IPv4Servers = nil
						o.Spec.IPv6Servers = nil
					case *api.SwitchFRRMigration:
						o.Spec.ApprovedDigest = "invalid-new-approval"
						o.Spec.Mode = "Traditional"
					case *api.SwitchACLPolicy:
						o.Spec.DefaultAction = "invalid"
					case *api.SwitchACLBinding:
						o.Spec.Interfaces = nil
					case *api.SwitchQoSMap:
						o.Spec.Entries = nil
					case *api.SwitchScheduler:
						o.Spec.Algorithm = "invalid"
					case *api.SwitchQoSBinding:
						o.Spec.Queues = nil
						o.Spec.DSCPToTC = ""
					}
					if err := c.Update(t.Context(), obj); err != nil {
						t.Fatal(err)
					}
				case "save failed":
					a.recoverErr = errors.New("save failed")
				case "no pending":
					a.recovery = &agent.NetworkResult{}
				case "nil result":
					a.nilRecovery = true
				case "pending":
					a.recoverErr = errors.New("pending operation could not be saved")
				case "global observe":
					r.ObserveOnly = true
					wantRecovery = false
				case "gate disabled":
					r.AllowNetworkConfig = false
					wantRecovery = false
				case "agent gate disabled":
					a.recoverErr = errors.New("agent network writes disabled")
				case "recovery unsupported":
					r.NewAgentClient = func(context.Context, client.Reader, *corev1.LocalObjectReference, string) (agentclient.SwitchAgentClient, error) {
						return &networkNoRecoveryClient{NetworkClient: a}, nil
					}
					wantRecovery = false
				case "policy observe":
					_, _, common := networkFields(obj)
					common.ManagementPolicy = api.NetworkManagementPolicyObserve
					if err := c.Update(t.Context(), obj); err != nil {
						t.Fatal(err)
					}
					wantRecovery = false
				case "endpoint changed":
					sw.Spec.Management.Host = "192.0.2.99"
					if err := c.Update(t.Context(), sw); err != nil {
						t.Fatal(err)
					}
					wantRecovery = false
				case "endpoint changes during recovery":
					a.onRecover = func() {
						sw.Spec.Management.Host = "192.0.2.99"
						if err := c.Update(t.Context(), sw); err != nil {
							t.Fatal(err)
						}
					}
				case "claim changes during recovery":
					a.onRecover = func() {
						if err := c.Get(t.Context(), key, obj); err != nil {
							t.Fatal(err)
						}
						annotations := obj.GetAnnotations()
						annotations["sonic.networking.metal.ironcore.dev/network-request"] = "{}"
						obj.SetAnnotations(annotations)
						if err := c.Update(t.Context(), obj); err != nil {
							t.Fatal(err)
						}
					}
				}
				if err := c.Delete(t.Context(), obj); err != nil {
					t.Fatal(err)
				}
				a.recoveries = nil
				_, err := r.Reconcile(t.Context(), request)
				if (err != nil) != wantHold {
					t.Fatalf("err=%v hold=%v", err, wantHold)
				}
				getErr := c.Get(t.Context(), key, obj)
				if wantHold {
					if getErr != nil || !slices.Contains(obj.GetFinalizers(), "sonic.networking.metal.ironcore.dev/network-recovery") {
						t.Fatalf("uncertain recovery lost finalizer: %v", getErr)
					}
					_, status, _ := networkFields(obj)
					if meta.IsStatusConditionTrue(status.Conditions, "Ready") {
						t.Fatal("uncertain deletion reported ready")
					}
				} else if !apierrors.IsNotFound(getErr) {
					t.Fatalf("saved orphan not released: %v", getErr)
				}
				if len(a.requests) != 1 {
					t.Fatal("deletion submitted desired writes")
				}
				if (len(a.recoveries) == 1) != wantRecovery {
					t.Fatalf("recovery count=%d want=%v", len(a.recoveries), wantRecovery)
				}
				if wantRecovery && !reflect.DeepEqual(a.recoveries[0], original) {
					t.Fatalf("recovery changed saved request: %+v", a.recoveries[0])
				}
			})
		}
	}
}

func TestNetworkRecoverBeforeNewIntent(t *testing.T) {
	t.Parallel()
	obj, _, a, c, r := networkFixture(t, "BGP", networkTestSpecs[4].spec)
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}
	if _, err := r.Reconcile(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	a.writeErr = errors.New("uncertain save")
	if _, err := r.Reconcile(t.Context(), req); err == nil {
		t.Fatal("expected save error")
	}
	original := a.requests[0]
	if err := c.Get(t.Context(), req.NamespacedName, obj); err != nil {
		t.Fatal(err)
	}
	obj.(*api.SwitchBGP).Spec.Prefixes = []api.NetworkPrefix{"203.0.113.0/24"}
	if err := c.Update(t.Context(), obj); err != nil {
		t.Fatal(err)
	}
	a.recoverErr = errors.New("pending still unsaved")
	if _, err := r.Reconcile(t.Context(), req); err == nil {
		t.Fatal("expected recovery error")
	}
	if !reflect.DeepEqual(a.recoveries[len(a.recoveries)-1], original) || len(a.requests) != 1 {
		t.Fatal("new intent bypassed original recovery")
	}
	a.recoverErr = nil
	a.writeErr = nil
	for i := 0; i < 3; i++ {
		if _, err := r.Reconcile(t.Context(), req); err != nil {
			t.Fatal(err)
		}
	}
	if len(a.requests) != 2 {
		t.Fatalf("new intent writes=%d", len(a.requests))
	}
	var spec api.SwitchBGPSpec
	if err := json.Unmarshal(a.requests[1].Spec, &spec); err != nil {
		t.Fatal(err)
	}
	if len(spec.Prefixes) != 1 {
		t.Fatal("new intent not reconciled after recovery")
	}
}

func TestNetworkForeignOwnerNeverReady(t *testing.T) {
	t.Parallel()
	for _, resource := range networkTestSpecs {
		t.Run(resource.kind, func(t *testing.T) {
			t.Parallel()
			obj, _, a, c, r := networkFixture(t, resource.kind, resource.spec)
			a.current = &agent.NetworkResult{Exists: true, ConfigurationVerified: true, RuntimeVerified: true, PersistenceVerified: true}
			a.readErr = errors.New("foreign owner")
			if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}); err == nil {
				t.Fatal("foreign owner accepted")
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(obj), obj); err != nil {
				t.Fatal(err)
			}
			_, status, _ := networkFields(obj)
			if meta.IsStatusConditionTrue(status.Conditions, "Ready") || len(a.requests) > 0 {
				t.Fatal("foreign owner became healthy or caused writes")
			}
		})
	}
}

func TestNetworkUnsupportedConfiguration(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, kind, spec string }{
		{"passive LACP", "PortChannel", `{"name":"PortChannel10","members":["Ethernet0"],"lacpMode":"passive"}`},
		{"empty DHCP Manage", "DHCPRelay", `{"vlanID":10}`},
		{"empty DHCP Observe", "DHCPRelay", `{"vlanID":10,"managementPolicy":"Observe"}`},
		{"missing migration mode", "FRRMigration", `{"managementPolicy":"Observe"}`},
		{"split migration mode", "FRRMigration", `{"mode":"split"}`},
		{"split-unified migration mode", "FRRMigration", `{"mode":"split-unified"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			obj, _, a, _, r := networkFixture(t, tc.kind, tc.spec)
			if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}); err == nil {
				t.Fatal("unsupported configuration accepted")
			}
			if len(a.requests) > 0 {
				t.Fatal("unsupported config caused writes")
			}
		})
	}
}
