//go:build integration

// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

// The generic engine enforces immutable fields independently of planner checks.
func TestNetworkRedundancyImmutableFields(t *testing.T) {
	for _, tc := range []struct{ name, kind, spec, key, field, value, replacement string }{
		{"mlag", "MLAG", `{"domainID":1}`, "MCLAG_DOMAIN|1", "peer_ip", "192.0.2.2", "192.0.2.3"},
		{"tunnel", "VXLANTunnel", `{"name":"vtep1"}`, "VXLAN_TUNNEL|vtep1", "src_ip", "192.0.2.1", "192.0.2.3"},
		{"mapping", "VLANVNI", `{"tunnel":"vtep1","vlanID":10}`, "VXLAN_TUNNEL_MAP|vtep1|map_100_Vlan10", "vni", "100", "200"},
		{"route distinguisher", "VLANVNI", `{"tunnel":"vtep1","vlanID":10}`, "BGP_GLOBALS_EVPN_VNI|default|l2vpn_evpn|100", "route-distinguisher", "65001:100", "65001:200"},
		{"route target direction", "VLANVNI", `{"tunnel":"vtep1","vlanID":10}`, "BGP_GLOBALS_EVPN_VNI_RT|default|l2vpn_evpn|100|65001:100", "route-target-type", "import", "both"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, db, req, saves := networkEngineFixture(t)
			req.Kind, req.Spec = tc.kind, json.RawMessage(tc.spec)
			value := tc.value
			m.planNetwork = func(_ vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
				id, err := networkIdentity(r)
				return &networkPlan{Identity: id, Desired: vlanChangeDB{tc.key: {tc.field: value}}}, err
			}
			if out, st := m.EnsureNetworkResource(t.Context(), req); st != nil || !out.PersistenceVerified {
				t.Fatalf("stage: %+v %v", out, st)
			}
			value = tc.replacement
			if _, st := m.EnsureNetworkResource(t.Context(), req); st == nil || *saves != 1 || db.HGet(t.Context(), tc.key, tc.field).Val() != tc.value {
				t.Fatal("owned redundancy field replaced")
			}
		})
	}
}

func TestNetworkRedundancyRejectsUnknownFields(t *testing.T) {
	for _, tc := range []struct{ kind, spec, key string }{
		{"MLAG", `{"domainID":1}`, "MCLAG_DOMAIN|1"},
		{"VXLANTunnel", `{"name":"vtep1"}`, "VXLAN_TUNNEL|vtep1"},
		{"VLANVNI", `{"tunnel":"vtep1","vlanID":10}`, "VXLAN_TUNNEL_MAP|vtep1|map_100_Vlan10"},
		{"EVPNPeer", `{"address":"192.0.2.2"}`, "BGP_NEIGHBOR_AF|default|192.0.2.2|l2vpn_evpn"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			m, db, req, saves := networkEngineFixture(t)
			req.Kind, req.Spec = tc.kind, json.RawMessage(tc.spec)
			preflights := 0
			m.planNetwork = func(_ vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
				id, err := networkIdentity(r)
				return &networkPlan{Identity: id, Desired: vlanChangeDB{tc.key: {"arbitraryTables": "PORT", "admin_status": "down"}},
					Preflight: func(context.Context, *SonicAgent) error { preflights++; return nil }}, err
			}
			if _, st := m.EnsureNetworkResource(t.Context(), req); st == nil || *saves != 0 || preflights != 0 || db.Exists(t.Context(), tc.key).Val() != 0 {
				t.Fatal("unknown planner field reached mutation path")
			}
		})
	}
}

func TestNetworkEVPNOwnedAFUpdate(t *testing.T) {
	for _, tc := range []struct {
		name                                                     string
		foreign, drift, missingPreflight, missingRuntime, unsafe bool
	}{
		{name: "owned safe"},
		{name: "foreign", foreign: true},
		{name: "owned drift", drift: true},
		{name: "missing preflight", missingPreflight: true},
		{name: "missing runtime", missingRuntime: true},
		{name: "unsafe export", unsafe: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, db, req, saves := networkEngineFixture(t)
			const key = "BGP_NEIGHBOR_AF|default|192.0.2.2|l2vpn_evpn"
			const neighbor = "BGP_NEIGHBOR|default|192.0.2.2"
			if err := db.HSet(t.Context(), neighbor, "admin_status", "down", "asn", "65002").Err(); err != nil {
				t.Fatal(err)
			}
			if tc.foreign {
				if err := db.HSet(t.Context(), key, "admin_status", "down").Err(); err != nil {
					t.Fatal(err)
				}
			}
			req.Kind, req.Spec = "EVPNPeer", json.RawMessage(`{"address":"192.0.2.2","adminState":"Down"}`)
			preflights := 0
			m.planNetwork = func(_ vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
				id, err := networkIdentity(r)
				var spec struct {
					AdminState string `json:"adminState"`
				}
				if err := json.Unmarshal(r.Spec, &spec); err != nil {
					return nil, err
				}
				admin := "down"
				if spec.AdminState == "Up" {
					admin = "up"
				}
				p := &networkPlan{Identity: id, Desired: vlanChangeDB{key: {"admin_status": admin}},
					Runtime: func(context.Context, *SonicAgent) (bool, json.RawMessage, error) { return false, nil, nil },
					Preflight: func(context.Context, *SonicAgent) error {
						preflights++
						if admin == "up" && tc.unsafe {
							return errors.New("export isolation not verified")
						}
						return nil
					},
				}
				if admin == "up" && tc.missingPreflight {
					p.Preflight = nil
				}
				if admin == "up" && tc.missingRuntime {
					p.Runtime = nil
				}
				return p, err
			}
			if out, st := m.EnsureNetworkResource(t.Context(), req); st != nil || !out.PersistenceVerified {
				t.Fatalf("stage: %+v %v", out, st)
			}
			old := "down"
			if tc.drift {
				old = "foreign"
				if err := db.HSet(t.Context(), key, "admin_status", old).Err(); err != nil {
					t.Fatal(err)
				}
			}
			req.Spec = json.RawMessage(`{"address":"192.0.2.2","adminState":"Up"}`)
			before := preflights
			out, st := m.EnsureNetworkResource(t.Context(), req)
			if tc.foreign || tc.drift || tc.missingPreflight || tc.missingRuntime || tc.unsafe {
				if st == nil || *saves != 1 || db.HGet(t.Context(), key, "admin_status").Val() != old {
					t.Fatalf("unsafe Up: %+v %v", out, st)
				}
			} else {
				if st != nil || !out.PersistenceVerified || out.RuntimeVerified || preflights <= before || db.HGet(t.Context(), key, "admin_status").Val() != "up" {
					t.Fatalf("owned Up: %+v %v", out, st)
				}
				req.Spec = json.RawMessage(`{"address":"192.0.2.2","adminState":"Down"}`)
				if _, st := m.EnsureNetworkResource(t.Context(), req); st != nil || db.HGet(t.Context(), key, "admin_status").Val() != "down" {
					t.Fatalf("owned Down: %v", st)
				}
			}
			if db.HGet(t.Context(), neighbor, "admin_status").Val() != "down" || db.HGet(t.Context(), neighbor, "asn").Val() != "65002" {
				t.Fatal("shared neighbor modified")
			}
		})
	}
}

func TestNetworkEVPNRecoveryRechecksSafety(t *testing.T) {
	m, db, req, saves := networkEngineFixture(t)
	const key = "BGP_NEIGHBOR_AF|default|192.0.2.2|l2vpn_evpn"
	req.Kind, req.Spec = "EVPNPeer", json.RawMessage(`{"address":"192.0.2.2","adminState":"Up"}`)
	ready := true
	m.planNetwork = func(_ vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
		id, err := networkIdentity(r)
		return &networkPlan{Identity: id, Desired: vlanChangeDB{key: {"admin_status": "up"}},
			Runtime: func(context.Context, *SonicAgent) (bool, json.RawMessage, error) { return false, nil, nil },
			Preflight: func(context.Context, *SonicAgent) error {
				if !ready {
					return errors.New("underlay no longer reachable")
				}
				return nil
			}}, err
	}
	syncs := 0
	m.journalSync = func(*os.File) error {
		syncs++
		if syncs == 2 {
			return errors.New("interrupted before CAS")
		}
		return nil
	}
	if _, st := m.EnsureNetworkResource(t.Context(), req); st == nil {
		t.Fatal("expected interruption")
	}
	m.journalSync, ready = nil, false
	if _, st := m.RecoverNetworkResource(t.Context(), req); st == nil || db.Exists(t.Context(), key).Val() != 0 || *saves != 0 {
		t.Fatal("recovery bypassed safety")
	}
	ready = true
	if out, st := m.RecoverNetworkResource(t.Context(), req); st != nil || !out.PersistenceVerified || out.RuntimeVerified {
		t.Fatalf("recovery: %+v %v", out, st)
	}
}
