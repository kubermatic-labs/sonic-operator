//go:build integration

// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"os/exec"
	"reflect"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

func TestNetworkQoSNumericNamesRedis(t *testing.T) {
	m, config, saves := qosRedisFixture(t)
	f := qosRuntimeFixture()
	// Use actual capability/SAI reads and the production planners and engine.
	delete(f.db, "CONFIG_DB")
	qosSeedRedis(t, m, f)
	for _, tc := range []struct{ name, kind, spec, key string }{
		{"dscp", "QoSMap", `{"name":"1","type":"DSCPToTC","entries":[{"from":63,"to":9}]}`, "DSCP_TO_TC_MAP|1"},
		{"dot1p", "QoSMap", `{"name":"1-default","type":"Dot1pToTC","entries":[{"from":7,"to":0}]}`, "DOT1P_TO_TC_MAP|1-default"},
		{"tc", "QoSMap", `{"name":"1","type":"TCToQueue","entries":[{"from":0,"to":0}]}`, "TC_TO_QUEUE_MAP|1"},
		{"scheduler", "Scheduler", `{"name":"1-default","algorithm":"DWRR","weight":5,"committedRate":1000,"peakRate":2000,"committedBurst":100,"peakBurst":200}`, "SCHEDULER|1-default"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Replace only the read-only host consumer probe; the name validation,
			// planner, Redis transaction, runtime reads and journal remain real.
			ctx := context.WithValue(t.Context(), qosStageRunnerKey{}, qosStageRunner(func(*exec.Cmd) ([]byte, error) {
				return []byte(`{"running":true,"tokens":["SCHEDULER","DWRR","bytes","type","weight","meter_type","cir","pir","cbs","pbs"]}`), nil
			}))
			r := &agent.NetworkRequest{Kind: tc.kind, OwnerID: "uid-" + tc.name, Spec: json.RawMessage(tc.spec)}
			if out, st := m.GetNetworkResource(ctx, r); st != nil || out.Exists {
				t.Fatalf("absent: %+v %v", out, st)
			}
			// Force recovery to validate the numeric identity and target in the journal.
			m.saveConfig = func(context.Context) *agent.Status { return &agent.Status{Code: 500, Message: "interrupted save"} }
			if out, st := m.EnsureNetworkResource(ctx, r); st == nil || out == nil || !out.ConfigurationVerified || out.PersistenceVerified {
				t.Fatalf("pending: %+v %v", out, st)
			}
			m.saveConfig = func(context.Context) *agent.Status { *saves++; return nil }
			if out, st := m.RecoverNetworkResource(ctx, r); st != nil || !out.ConfigurationVerified || !out.PersistenceVerified {
				t.Fatalf("recovery: %+v %v", out, st)
			}
			if config.Exists(t.Context(), tc.key).Val() != 1 {
				t.Fatal("missing numeric named target")
			}
			beforeSaves := *saves
			if out, st := m.EnsureNetworkResource(ctx, r); st != nil || !out.PersistenceVerified || *saves != beforeSaves {
				t.Fatalf("idempotence: %+v %v", out, st)
			}
		})
	}
	before, _, err := m.vlanChangeSnapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	beforeSaves := *saves
	for _, kind := range []string{"QoSMap", "Scheduler"} {
		t.Run("invalid "+kind, func(t *testing.T) {
			for _, name := range []string{"1|escape", "1/default", "-1"} {
				spec := map[string]any{"name": name}
				if kind == "QoSMap" {
					spec["type"] = "DSCPToTC"
					spec["entries"] = []map[string]uint32{{"from": 0, "to": 0}}
				} else {
					spec["algorithm"] = "STRICT"
				}
				raw, err := json.Marshal(spec)
				if err != nil {
					t.Fatal(err)
				}
				r := &agent.NetworkRequest{Kind: kind, OwnerID: "invalid", Spec: raw}
				for _, call := range []func(context.Context, *agent.NetworkRequest) (*agent.NetworkResult, *agent.Status){m.GetNetworkResource, m.EnsureNetworkResource, m.RecoverNetworkResource} {
					if _, st := call(t.Context(), r); st == nil {
						t.Fatalf("accepted invalid name %q", name)
					}
				}
			}
		})
	}
	after, _, err := m.vlanChangeSnapshot(t.Context())
	if err != nil || !reflect.DeepEqual(before, after) || *saves != beforeSaves {
		t.Fatalf("invalid name changed configuration: %v", err)
	}
}
