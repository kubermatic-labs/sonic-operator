//go:build integration

// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	agentclient "github.com/ironcore-dev/sonic-operator/internal/agent/agent_client/client"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/ironcore-dev/sonic-operator/internal/controller"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// The real reconciler and SonicAgent are connected here; only transport and the
// explicitly synthetic independent producer instrumentation are substituted.
type bufferControllerAgent struct {
	agentclient.SwitchAgentClient
	backend          *SonicAgent
	ensures          int
	readFailure      bool
	stripEligibility bool
}

func bufferControllerResult(out *agent.NetworkResult, st *agent.Status) (*agent.NetworkResult, error) {
	if st != nil && st.Code != 0 {
		return out, fmt.Errorf("%s", st.Message)
	}
	return out, nil
}
func (a *bufferControllerAgent) GetNetworkResource(ctx context.Context, r *agent.NetworkRequest) (*agent.NetworkResult, error) {
	out, st := a.backend.GetNetworkResource(ctx, r)
	if a.readFailure {
		return out, fmt.Errorf("injected transport failure")
	}
	if out != nil && a.stripEligibility {
		out.BufferRepairEligible = false
	}
	return bufferControllerResult(out, st)
}
func (a *bufferControllerAgent) EnsureNetworkResource(ctx context.Context, r *agent.NetworkRequest) (*agent.NetworkResult, error) {
	a.ensures++
	out, st := a.backend.EnsureNetworkResource(ctx, r)
	return bufferControllerResult(out, st)
}
func (a *bufferControllerAgent) RecoverNetworkResource(ctx context.Context, r *agent.NetworkRequest) (*agent.NetworkResult, error) {
	out, st := a.backend.RecoverNetworkResource(ctx, r)
	return bufferControllerResult(out, st)
}

func TestNetworkBufferControllerReachesQualifiedRepair(t *testing.T) {
	for _, mode := range []string{"configuration", "runtime", "runtime without flag", "unsupported PG", "transport failure"} {
		t.Run(mode, func(t *testing.T) {
			backend, capture, saves := bufferCapturedEngine(t, "core-01")
			key, kind := "BUFFER_PROFILE|PORT3_INGRESS_PROFILE", "BufferProfile"
			var obj client.Object = &api.SwitchBufferProfile{}
			if mode == "unsupported PG" {
				key, kind = "BUFFER_PG|Ethernet11|7", "BufferPG"
				obj = &api.SwitchBufferPG{}
			}
			req := bufferCapturedRequest(t, key, capture["CONFIG_DB"][key])
			raw := []byte(`{"metadata":{"name":"buffer","uid":"buffer-owner","generation":1},"spec":` + string(req.Spec) + `}`)
			if err := json.Unmarshal(raw, obj); err != nil {
				t.Fatal(err)
			}
			switch o := obj.(type) {
			case *api.SwitchBufferProfile:
				o.Spec.SwitchRef.Name = "leaf"
				o.Spec.ManagementPolicy = api.NetworkManagementPolicyManage
			case *api.SwitchBufferPG:
				o.Spec.SwitchRef.Name = "leaf"
				o.Spec.ManagementPolicy = api.NetworkManagementPolicyManage
			}
			scheme := runtime.NewScheme()
			if err := api.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			sw := &api.Switch{ObjectMeta: metav1.ObjectMeta{Name: "leaf", UID: "switch-uid"}, Spec: api.SwitchSpec{Management: api.Management{Host: "192.0.2.10", Port: "50051"}}}
			c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(obj).WithObjects(obj, sw).Build()
			a := &bufferControllerAgent{backend: backend}
			r := &controller.NetworkReconciler{Client: c, APIReader: c, Kind: kind, AllowNetworkConfig: true, AllowTrafficPolicy: true, NewAgentClient: func(context.Context, client.Reader, *corev1.LocalObjectReference, string) (agentclient.SwitchAgentClient, error) {
				return a, nil
			}}
			reconcile := func() error {
				_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)})
				return err
			}
			if err := reconcile(); err != nil {
				t.Fatal("bind", err)
			}
			if err := reconcile(); err != nil {
				t.Fatal("conditional adoption", err)
			}
			if a.ensures != 1 || *saves != 1 {
				t.Fatalf("adoption did not reach real agent: calls=%d saves=%d", a.ensures, *saves)
			}
			switch mode {
			case "configuration", "transport failure":
				if err := backend.clientPool["CONFIG_DB"].HSet(t.Context(), key, "dynamic_th", "2").Err(); err != nil {
					t.Fatal(err)
				}
				a.readFailure = mode == "transport failure"
			case "runtime", "runtime without flag":
				a.stripEligibility = mode == "runtime without flag"
				if err := backend.clientPool["ASIC_DB"].HSet(t.Context(), "ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_PROFILE:"+bufferProfileOID, "SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH", "2").Err(); err != nil {
					t.Fatal(err)
				}
			case "unsupported PG":
				if err := backend.clientPool["ASIC_DB"].HSet(t.Context(), "ASIC_STATE:SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP:"+bufferPGOID, "SAI_INGRESS_PRIORITY_GROUP_ATTR_BUFFER_PROFILE", "oid:0x999").Err(); err != nil {
					t.Fatal(err)
				}
			}
			err := reconcile()
			if mode == "unsupported PG" || mode == "transport failure" {
				if err == nil || a.ensures != 1 || *saves != 1 {
					t.Fatalf("failed/unsupported observation caused writes: err=%v calls=%d saves=%d", err, a.ensures, *saves)
				}
			} else if mode == "runtime without flag" {
				if err != nil || a.ensures != 1 || *saves != 1 {
					t.Fatalf("ordinary runtime nonconvergence caused writes: %v calls=%d", err, a.ensures)
				}
			} else {
				if err != nil || a.ensures != 2 || *saves != 2 {
					t.Fatalf("controller never repaired qualified drift: err=%v calls=%d saves=%d", err, a.ensures, *saves)
				}
				if backend.clientPool["CONFIG_DB"].HGet(t.Context(), key, "dynamic_th").Val() != "3" {
					t.Fatal("controller failed to enforce original value")
				}
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(obj), obj); err != nil {
				t.Fatal(err)
			}
			if mode == "unsupported PG" {
				s := obj.(*api.SwitchBufferPG).Status
				if !s.PersistenceVerified || !s.ConfigurationVerified || s.RuntimeVerified {
					t.Fatalf("lost independent evidence: %+v", s)
				}
			}
			if mode == "runtime" {
				s := obj.(*api.SwitchBufferProfile).Status
				if !s.PersistenceVerified || !s.ConfigurationVerified || s.RuntimeVerified {
					t.Fatalf("inferred runtime convergence: %+v", s)
				}
			}
		})
	}
}
