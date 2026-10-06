//go:build integration

// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/redis/go-redis/v9"
)

func mlagTestStateDB(t *testing.T, m *SonicAgent, config *redis.Client) *redis.Client {
	t.Helper()
	options := *config.Options()
	options.DB = 6
	state := redis.NewClient(&options)
	t.Cleanup(func() { _ = state.Close() })
	m.clientPool["STATE_DB"] = state
	return state
}

func TestNetworkMLAGObservedPreflightEligibility(t *testing.T) {
	for _, tc := range []struct {
		name          string
		consumerProof string
		missingDaemon bool
		missingLAG    bool
		missingSource bool
		unreachable   bool
		eligible      bool
		consumerReady bool
	}{
		{name: "future audited successful fixture", eligible: true, consumerReady: true},
		{name: "unaudited running consumers", consumerProof: `{"supported":false,"iccpd":true,"mclagsyncd":true}`},
		{name: "missing container", missingDaemon: true},
		{name: "missing daemon", consumerProof: `{"supported":true,"iccpd":false,"mclagsyncd":true}`},
		{name: "malformed consumer proof", consumerProof: `{"supported":false,"supported":true,"iccpd":true,"mclagsyncd":true}`},
		{name: "missing LAG", missingLAG: true, consumerReady: true},
		{name: "missing source", missingSource: true, consumerReady: true},
		{name: "unreachable peer", unreachable: true, consumerReady: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, db, _, saves := networkEngineFixture(t)
			m.planNetwork = nil
			state := mlagTestStateDB(t, m, db)
			seed := mlagTestDB()
			if tc.missingLAG {
				delete(seed, "PORTCHANNEL|PortChannel10")
			}
			if tc.missingSource {
				delete(seed, "PORTCHANNEL_INTERFACE|PortChannel100|192.0.2.1/30")
			}
			for key, fields := range seed {
				if err := db.HSet(t.Context(), key, fields).Err(); err != nil {
					t.Fatal(err)
				}
			}
			// An up state must neither bypass preflight nor imply verified pair health.
			if err := state.HSet(t.Context(), "MCLAG_TABLE|1", "oper_status", "up").Err(); err != nil {
				t.Fatal(err)
			}
			ctx := context.WithValue(t.Context(), mlagRunnerKey{}, mlagRunner(func(cmd *exec.Cmd) ([]byte, error) {
				if cmd.Args[0] == "docker" {
					if tc.missingDaemon {
						return nil, errors.New("iccpd container unavailable")
					}
					if tc.consumerProof != "" {
						return []byte(tc.consumerProof), nil
					}
				}
				if tc.unreachable && cmd.Args[0] == "ip" && cmd.Args[3] == "route" {
					return nil, errors.New("peer unreachable")
				}
				return mlagTestRunner(cmd)
			}))
			request := mlagTestRequest()
			plan, err := planNetworkMLAG(seed, request)
			if err != nil {
				t.Fatal(err)
			}
			preflightErr := plan.Preflight(ctx, m)
			out, st := m.GetNetworkResource(ctx, request)
			if st != nil || out.RuntimeVerified {
				t.Fatalf("observation=%+v status=%v", out, st)
			}
			var observed map[string]any
			if err := json.Unmarshal(out.Observed, &observed); err != nil {
				t.Fatal(err)
			}
			// Map lookup checks presence and JSON boolean type, including false.
			if observed["preflightEligible"] != tc.eligible || observed["preflightEligible"] != (preflightErr == nil) || observed["consumerReady"] != tc.consumerReady {
				t.Fatalf("observed=%v preflight=%v", observed, preflightErr)
			}
			if preflightErr != nil && observed["reason"] != preflightErr.Error() {
				t.Fatalf("preflight failure reason lost: %v", observed)
			}
			if tc.eligible && !strings.Contains(observed["reason"].(string), "pair health unverified") {
				t.Fatalf("eligibility implies pair health: %v", observed)
			}
			after, _, err := m.vlanChangeSnapshot(ctx)
			if err != nil || !reflect.DeepEqual(seed, after) || *saves != 0 {
				t.Fatalf("read-only eligibility mutated config: %v", err)
			}
		})
	}
}

// Uses the production planner dispatch, journal, CAS and observation loop with
// real Redis. Only the native read-only command transport and config save are
// replaced. A successful save never implies that a redundant pair is healthy.
func TestNetworkMLAGEngine(t *testing.T) {
	m, db, _, saves := networkEngineFixture(t)
	m.planNetwork = nil
	state := mlagTestStateDB(t, m, db)
	ctx := context.WithValue(t.Context(), mlagRunnerKey{}, mlagRunner(mlagTestRunner))
	for key, fields := range mlagTestDB() {
		if err := db.HSet(ctx, key, fields).Err(); err != nil {
			t.Fatal(err)
		}
	}
	r := mlagTestRequest()
	before, _, err := m.vlanChangeSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out, st := m.GetNetworkResource(ctx, r); st != nil || out.Exists || out.RuntimeVerified || *saves != 0 {
		t.Fatalf("observe=%+v %v", out, st)
	}
	missing := context.WithValue(t.Context(), mlagRunnerKey{}, mlagRunner(func(*exec.Cmd) ([]byte, error) { return nil, errors.New("no iccpd") }))
	if _, st := m.EnsureNetworkResource(missing, r); st == nil {
		t.Fatal("absent daemon allowed writes")
	}
	after, _, err := m.vlanChangeSnapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) || *saves != 0 {
		t.Fatalf("failed preflight wrote config: %v", err)
	}
	// Stage domain alone, then add member fields under the same durable identity.
	r.Spec = json.RawMessage(strings.Replace(mlagTestSpec, `["PortChannel10"]`, `[]`, 1))
	if out, st := m.EnsureNetworkResource(ctx, r); st != nil || !out.PersistenceVerified || out.RuntimeVerified {
		t.Fatalf("domain stage=%+v %v", out, st)
	}
	if db.Exists(ctx, "MCLAG_INTERFACE|1|PortChannel10").Val() != 0 {
		t.Fatal("domain stage added members")
	}
	r = mlagTestRequest()
	if out, st := m.EnsureNetworkResource(ctx, r); st != nil || !out.ConfigurationVerified || !out.PersistenceVerified || out.RuntimeVerified {
		t.Fatalf("member stage=%+v %v", out, st)
	}
	if *saves != 2 {
		t.Fatalf("saves=%d", *saves)
	}
	if out, st := m.EnsureNetworkResource(ctx, r); st != nil || !out.PersistenceVerified || *saves != 2 {
		t.Fatalf("no-op=%+v %v", out, st)
	}
	// Even a plausible up/active state is not exact peer/timer/sync proof.
	if err := state.HSet(ctx, "MCLAG_TABLE|1", map[string]string{"oper_status": "up", "role": "active", "system_mac": "02:00:00:00:00:01", "peer_mac": "02:00:00:00:00:02", "info_sync_done": "true"}).Err(); err != nil {
		t.Fatal(err)
	}
	out, st := m.GetNetworkResource(ctx, r)
	if st != nil || out.RuntimeVerified || !strings.Contains(string(out.Observed), `"oper_status":"up"`) || strings.Contains(string(out.Observed), "info_sync_done") {
		t.Fatalf("invented runtime=%+v %v", out, st)
	}
	// Another domain's state cannot appear in this domain's observation.
	if err := state.Del(ctx, "MCLAG_TABLE|1").Err(); err != nil {
		t.Fatal(err)
	}
	if err := state.HSet(ctx, "MCLAG_TABLE|2", "oper_status", "up").Err(); err != nil {
		t.Fatal(err)
	}
	out, st = m.GetNetworkResource(ctx, r)
	if st != nil || out.RuntimeVerified || strings.Contains(string(out.Observed), "MCLAG_TABLE|2") {
		t.Fatalf("wrong domain observation=%+v %v", out, st)
	}
	other := *r
	other.OwnerID = "other-uid"
	if _, st := m.EnsureNetworkResource(ctx, &other); st == nil {
		t.Fatal("ownership transferred")
	}
	r.Spec = json.RawMessage(strings.Replace(mlagTestSpec, `192.0.2.2`, `192.0.2.3`, 1))
	if _, st := m.EnsureNetworkResource(ctx, r); st == nil || db.HGet(ctx, "MCLAG_DOMAIN|1", "peer_ip").Val() != "192.0.2.2" {
		t.Fatal("peer reconfigured")
	}
	r.Spec = json.RawMessage(strings.Replace(mlagTestSpec, `["PortChannel10"]`, `[]`, 1))
	if _, st := m.EnsureNetworkResource(ctx, r); st == nil {
		t.Fatal("member removed")
	}
	if err := state.Set(ctx, "MCLAG_TABLE|1", "wrong-type", 0).Err(); err != nil {
		t.Fatal(err)
	}
	out, st = m.GetNetworkResource(ctx, mlagTestRequest())
	if st == nil || out.RuntimeVerified || !out.ConfigurationVerified || !out.PersistenceVerified {
		t.Fatalf("runtime transport/type error concealed: %+v %v", out, st)
	}
}

func TestNetworkMLAGEngineRecovery(t *testing.T) {
	m, db, _, _ := networkEngineFixture(t)
	m.planNetwork = nil
	mlagTestStateDB(t, m, db)
	ctx := context.WithValue(t.Context(), mlagRunnerKey{}, mlagRunner(mlagTestRunner))
	for key, fields := range mlagTestDB() {
		if err := db.HSet(ctx, key, fields).Err(); err != nil {
			t.Fatal(err)
		}
	}
	r := mlagTestRequest()
	// Interrupt journal preparation before CAS, then verify recovery repeats
	// daemon and live dependency checks against the durable original spec.
	syncs := 0
	m.journalSync = func(*os.File) error {
		syncs++
		if syncs == 2 {
			return errors.New("sync interrupted")
		}
		return nil
	}
	if _, st := m.EnsureNetworkResource(ctx, r); st == nil {
		t.Fatal("expected interruption")
	}
	m.journalSync = nil
	missing := context.WithValue(t.Context(), mlagRunnerKey{}, mlagRunner(func(*exec.Cmd) ([]byte, error) { return nil, errors.New("daemon gone") }))
	if _, st := m.RecoverNetworkResource(missing, r); st == nil || db.Exists(ctx, "MCLAG_DOMAIN|1").Val() != 0 {
		t.Fatal("recovery bypassed daemon preflight")
	}
	if err := db.Del(ctx, "PORTCHANNEL|PortChannel10").Err(); err != nil {
		t.Fatal(err)
	}
	if _, st := m.RecoverNetworkResource(ctx, r); st == nil || db.Exists(ctx, "MCLAG_DOMAIN|1").Val() != 0 {
		t.Fatal("recovery bypassed dependency guard")
	}
	if err := db.HSet(ctx, "PORTCHANNEL|PortChannel10", mlagTestDB()["PORTCHANNEL|PortChannel10"]).Err(); err != nil {
		t.Fatal(err)
	}
	m.saveConfig = func(context.Context) *agent.Status { return &agent.Status{Code: 500, Message: "save interrupted"} }
	out, st := m.RecoverNetworkResource(ctx, r)
	if st == nil || !out.ConfigurationVerified || out.PersistenceVerified || out.RuntimeVerified {
		t.Fatalf("save interruption=%+v %v", out, st)
	}
	m.saveConfig = func(context.Context) *agent.Status { return nil }
	r.Spec = json.RawMessage(`{"domainID":1,"members":null}`)
	out, st = m.RecoverNetworkResource(ctx, r)
	if st != nil || !out.PersistenceVerified || out.RuntimeVerified {
		t.Fatalf("recovery=%+v %v", out, st)
	}
}

func TestNetworkMLAGEnginePreflightNoWrites(t *testing.T) {
	for _, tc := range []struct {
		name      string
		edit      func(vlanChangeDB)
		failRoute bool
	}{
		{"missing local peerlink", func(db vlanChangeDB) { delete(db, "PORTCHANNEL|PortChannel100") }, false},
		{"missing local source", func(db vlanChangeDB) { delete(db, "PORTCHANNEL_INTERFACE|PortChannel100|192.0.2.1/30") }, false},
		{"unreachable peer", func(vlanChangeDB) {}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, db, _, saves := networkEngineFixture(t)
			m.planNetwork = nil
			mlagTestStateDB(t, m, db)
			seed := mlagTestDB()
			tc.edit(seed)
			for key, fields := range seed {
				if err := db.HSet(t.Context(), key, fields).Err(); err != nil {
					t.Fatal(err)
				}
			}
			ctx := context.WithValue(t.Context(), mlagRunnerKey{}, mlagRunner(func(cmd *exec.Cmd) ([]byte, error) {
				if tc.failRoute && cmd.Args[0] == "ip" && cmd.Args[3] == "route" {
					return nil, errors.New("unreachable")
				}
				return mlagTestRunner(cmd)
			}))
			if _, st := m.EnsureNetworkResource(ctx, mlagTestRequest()); st == nil {
				t.Fatal("preflight unexpectedly passed")
			}
			got, _, err := m.vlanChangeSnapshot(ctx)
			if err != nil || !reflect.DeepEqual(seed, got) || *saves != 0 {
				t.Fatalf("preflight mutated config: %v", err)
			}
		})
	}
}

func TestNetworkMLAGEngineNativeRuntime(t *testing.T) {
	m, db, _, saves := networkEngineFixture(t)
	m.planNetwork = nil
	state := mlagTestStateDB(t, m, db)
	ctx := context.WithValue(t.Context(), mlagRunnerKey{}, mlagRunner(mlagStatusRunner))
	seed := mlagTestDB()
	plan, err := planNetworkMLAG(seed, mlagTestRequest())
	if err != nil {
		t.Fatal(err)
	}
	for key, fields := range seed {
		if err := db.HSet(ctx, key, fields).Err(); err != nil {
			t.Fatal(err)
		}
	}
	// Bootstrap eligibility is independent of the native domain/session. Both
	// agents can stage their first domain while runtime remains unverified.
	absent := context.WithValue(t.Context(), mlagRunnerKey{}, mlagRunner(mlagTestRunner))
	out, st := m.GetNetworkResource(absent, mlagTestRequest())
	if st != nil || out.Exists || out.RuntimeVerified || !strings.Contains(string(out.Observed), `"preflightEligible":true`) {
		t.Fatalf("bootstrap=%+v %v", out, st)
	}
	for key, fields := range plan.Desired {
		if err := db.HSet(ctx, key, fields).Err(); err != nil {
			t.Fatal(err)
		}
	}
	_, _, stateRows := mlagStatusFixture(t)
	for key, fields := range stateRows {
		if err := state.HSet(ctx, key, fields).Err(); err != nil {
			t.Fatal(err)
		}
	}
	out, st = m.GetNetworkResource(ctx, mlagTestRequest())
	if st != nil || !out.RuntimeVerified || !out.ConfigurationVerified || *saves != 0 {
		t.Fatalf("native convergence=%+v %v", out, st)
	}
	if err := state.HSet(ctx, "MCLAG_REMOTE_INTF_TABLE|1|PortChannel10", "oper_status", "down").Err(); err != nil {
		t.Fatal(err)
	}
	out, st = m.GetNetworkResource(ctx, mlagTestRequest())
	if st != nil || out.RuntimeVerified || !out.ConfigurationVerified || *saves != 0 {
		t.Fatalf("lost peer member=%+v %v", out, st)
	}
}
