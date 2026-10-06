//go:build integration

// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

// Exercise field ownership and recovery with real Redis independently of native
// capability fixtures, which are covered by the traffic planners' tests.
func TestNetworkTrafficSharedTableOwnership(t *testing.T) {
	m, db, req, saves := networkEngineFixture(t)
	policy := vlanChangeDB{
		"ACL_TABLE|Edge":        {"type": "L3", "stage": "ingress", "policy_desc": "Edge"},
		"ACL_RULE|Edge|Default": {"PRIORITY": "1", "PACKET_ACTION": "DROP"},
	}
	binding := vlanChangeDB{"ACL_TABLE|Edge": {"ports@": "Ethernet0"}}
	preflights := 0
	applied := false
	m.planNetwork = func(_ vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
		identity, err := networkIdentity(r)
		if err != nil {
			return nil, err
		}
		desired := policy
		if r.Kind == "ACLBinding" {
			desired = binding
		}
		return &networkPlan{Identity: identity, Desired: desired,
			Runtime: func(context.Context, *SonicAgent) (bool, json.RawMessage, error) { return applied, nil, nil },
			Preflight: func(context.Context, *SonicAgent) error {
				preflights++
				if r.Kind == "ACLBinding" && !applied {
					return errors.New("policy not applied")
				}
				return nil
			}}, nil
	}
	req.Kind, req.Spec = "ACLPolicy", json.RawMessage(`{"name":"Edge"}`)
	if out, st := m.GetNetworkResource(t.Context(), req); st != nil || out.Exists || preflights != 0 || *saves != 0 {
		t.Fatalf("read ran preflight/write: %+v %v preflights=%d", out, st, preflights)
	}
	if out, st := m.EnsureNetworkResource(t.Context(), req); st != nil || !out.PersistenceVerified {
		t.Fatalf("policy stage: %+v %v", out, st)
	}
	if db.HExists(t.Context(), "ACL_TABLE|Edge", "ports@").Val() {
		t.Fatal("policy owns binding field")
	}
	bindReq := &agent.NetworkRequest{Kind: "ACLBinding", OwnerID: "binding-uid", Spec: json.RawMessage(`{"policy":"Edge"}`)}
	before, _, err := m.vlanChangeSnapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, st := m.EnsureNetworkResource(t.Context(), bindReq); st == nil || *saves != 1 {
		t.Fatal("binding written without applied proof")
	}
	after, _, err := m.vlanChangeSnapshot(t.Context())
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("preflight failure changed config: %v", err)
	}
	applied = true
	if out, st := m.EnsureNetworkResource(t.Context(), bindReq); st != nil || !out.PersistenceVerified {
		t.Fatalf("independent binding owner: %+v %v", out, st)
	}
	j, err := m.lockNetworkJournal(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	state, err := loadNetworkJournal(j)
	j.close()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(state.Records["ACLPolicy|Edge"].Owned, policy) || !reflect.DeepEqual(state.Records["ACLBinding|Edge"].Owned, binding) {
		t.Fatalf("overlapping ownership: %+v", state.Records)
	}
	priorPreflights := preflights
	if out, st := m.EnsureNetworkResource(t.Context(), req); st != nil || !out.PersistenceVerified || *saves != 2 || preflights != priorPreflights {
		t.Fatalf("policy no-op after binding: %+v %v saves=%d", out, st, *saves)
	}
	// Additive ownership forbids replacing even an owned traffic policy or binding.
	policy["ACL_RULE|Edge|Default"]["PACKET_ACTION"] = "FORWARD"
	if _, st := m.EnsureNetworkResource(t.Context(), req); st == nil || db.HGet(t.Context(), "ACL_RULE|Edge|Default", "PACKET_ACTION").Val() != "DROP" {
		t.Fatal("existing policy replaced")
	}
	binding["ACL_TABLE|Edge"]["ports@"] = "Ethernet4"
	if _, st := m.EnsureNetworkResource(t.Context(), bindReq); st == nil || db.HGet(t.Context(), "ACL_TABLE|Edge", "ports@").Val() != "Ethernet0" {
		t.Fatal("existing binding replaced")
	}
}

func TestNetworkTrafficBindingRecovery(t *testing.T) {
	for _, tc := range []struct {
		name, kind, spec string
		desired          vlanChangeDB
	}{
		{"acl", "ACLBinding", `{"policy":"Edge"}`, vlanChangeDB{"ACL_TABLE|Edge": {"ports@": "Ethernet0"}}},
		{"qos", "QoSBinding", `{"interfaceName":"Ethernet0"}`, vlanChangeDB{"PORT_QOS_MAP|Ethernet0": {"dscp_to_tc_map": "Map1"}, "QUEUE|Ethernet0|0": {"scheduler": "Weighted"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, db, req, _ := networkEngineFixture(t)
			req.Kind, req.Spec = tc.kind, json.RawMessage(tc.spec)
			preflights := 0
			ready := true
			m.planNetwork = func(_ vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
				id, err := networkIdentity(r)
				return &networkPlan{Identity: id, Desired: tc.desired, Preflight: func(context.Context, *SonicAgent) error {
					preflights++
					if !ready {
						return errors.New("capability unavailable")
					}
					return nil
				}}, err
			}
			// Interrupt before CAS, then make capability proof unavailable.
			syncs := 0
			m.journalSync = func(*os.File) error {
				syncs++
				if syncs == 2 {
					return errors.New("journal sync failed")
				}
				return nil
			}
			if _, st := m.EnsureNetworkResource(t.Context(), req); st == nil {
				t.Fatal("expected interrupted journal")
			}
			m.journalSync = nil
			ready = false
			if _, st := m.RecoverNetworkResource(t.Context(), req); st == nil {
				t.Fatal("recovery bypassed preflight")
			}
			for key := range tc.desired {
				if db.Exists(t.Context(), key).Val() != 0 {
					t.Fatal("recovery wrote before capability proof")
				}
			}
			ready = true
			m.saveConfig = func(context.Context) *agent.Status { return &agent.Status{Code: 500, Message: "save failed"} }
			if out, st := m.RecoverNetworkResource(t.Context(), req); st == nil || !out.ConfigurationVerified || out.PersistenceVerified {
				t.Fatalf("save interruption: %+v %v", out, st)
			}
			priorPreflights := preflights
			m.saveConfig = func(context.Context) *agent.Status { return nil }
			// Recovery uses the durable spec, not unrelated mutable fields in the caller.
			if tc.kind == "ACLBinding" {
				req.Spec = json.RawMessage(`{"policy":"Edge","interfaces":null}`)
			}
			out, st := m.RecoverNetworkResource(t.Context(), req)
			if st != nil || !out.PersistenceVerified || preflights != priorPreflights {
				t.Fatalf("post-state recovery: %+v %v preflights=%d", out, st, preflights)
			}
		})
	}
}
