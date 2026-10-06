//go:build integration

// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/redis/go-redis/v9"
)

func TestNetworkRecoveryOriginalRequest(t *testing.T) {
	for _, operation := range []string{"ensure", "recover"} {
		t.Run(operation, func(t *testing.T) {
			m, db, req, _ := networkEngineFixture(t)
			req.Spec = json.RawMessage(`{"name":"VrfTest","value":"original"}`)
			m.planNetwork = func(_ vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
				var spec struct {
					Value string `json:"value"`
				}
				if err := json.Unmarshal(r.Spec, &spec); err != nil {
					return nil, err
				}
				if spec.Value == "invalid-new" {
					t.Fatal("planned caller's new desired during recovery")
				}
				return &networkPlan{Identity: "VRF|VrfTest", Desired: vlanChangeDB{"VRF|VrfTest": {"NULL": spec.Value}}}, nil
			}
			m.saveConfig = func(context.Context) *agent.Status { return &agent.Status{Code: 500} }
			if _, st := m.EnsureNetworkResource(t.Context(), req); st == nil {
				t.Fatal("save should fail")
			}
			m.saveConfig = func(context.Context) *agent.Status { return nil }
			newRequest := *req
			newRequest.Spec = json.RawMessage(`{"name":"VrfTest","value":"invalid-new"}`)
			out, st := m.networkResource(t.Context(), &newRequest, operation)
			if out == nil || !out.PersistenceVerified || (operation == "ensure" && st == nil) || (operation == "recover" && st != nil) {
				t.Fatalf("recovery: %+v %v", out, st)
			}
			if db.HGet(t.Context(), "VRF|VrfTest", "NULL").Val() != "original" {
				t.Fatal("new desired applied")
			}
			// Recovery remains a no-op once no pending work exists, even with invalid desired fields.
			if _, st := m.RecoverNetworkResource(t.Context(), &newRequest); st != nil {
				t.Fatal(st)
			}
		})
	}
}

func TestNetworkRecoveryAbsentAndForeign(t *testing.T) {
	m, db, req, saves := networkEngineFixture(t)
	if _, st := m.RecoverNetworkResource(t.Context(), req); st != nil || *saves != 0 || db.DBSize(t.Context()).Val() != 0 {
		t.Fatal("recovery created new desired")
	}
	m.saveConfig = func(context.Context) *agent.Status { return &agent.Status{Code: 500} }
	if _, st := m.EnsureNetworkResource(t.Context(), req); st == nil {
		t.Fatal("save should fail")
	}
	foreign := *req
	foreign.OwnerID = "other"
	if _, st := m.RecoverNetworkResource(t.Context(), &foreign); st == nil {
		t.Fatal("foreign owner recovered")
	}
	other := *req
	other.Spec = json.RawMessage(`{"name":"VrfOther"}`)
	if _, st := m.RecoverNetworkResource(t.Context(), &other); st != nil {
		t.Fatal(st)
	}
	if unlock, err := m.guardNetworkWrites(t.Context()); err == nil {
		unlock()
		t.Fatal("wrong identity cleared pending")
	}
}

func TestNetworkActivationRecovery(t *testing.T) {
	for _, scenario := range []string{"success", "already active", "prepared fsync", "lost reply", "unverified reply", "dispatch fsync", "verified fsync"} {
		t.Run(scenario, func(t *testing.T) {
			m, db, req, saves := networkEngineFixture(t)
			activated := scenario == "already active"
			calls := 0
			failRuntime := false
			planner := m.planNetwork
			m.planNetwork = func(db vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
				p, err := planner(db, r)
				p.Preflight = func(context.Context, *SonicAgent) error {
					if db["VRF|VrfTest"] == nil && calls > 0 {
						t.Fatal("preflight used stale state")
					}
					return nil
				}
				p.Activate = func(ctx context.Context, _ *SonicAgent) error {
					calls++
					if !networkSubset(db, p.Desired) {
						// First plan captures pre-state; check actual Redis at dispatch.
						if m.clientPool["CONFIG_DB"].HGet(ctx, "VRF|VrfTest", "NULL").Val() != "NULL" {
							t.Fatal("activation before CAS")
						}
					}
					activated = scenario != "unverified reply"
					if scenario == "lost reply" {
						return errors.New("reply lost")
					}
					return nil
				}
				p.Runtime = func(context.Context, *SonicAgent) (bool, json.RawMessage, error) {
					if failRuntime {
						return false, nil, errors.New("probe failed")
					}
					return activated, nil, nil
				}
				return p, err
			}
			syncs := 0
			m.journalSync = func(*os.File) error {
				syncs++
				if (scenario == "prepared fsync" && syncs == 2) || (scenario == "dispatch fsync" && syncs == 3) || (scenario == "verified fsync" && syncs == 4) {
					return errors.New("fsync failed")
				}
				return nil
			}
			out, st := m.EnsureNetworkResource(t.Context(), req)
			if scenario == "success" || scenario == "already active" {
				wantCalls := 1
				if scenario == "already active" {
					wantCalls = 0
				}
				if st != nil || !out.PersistenceVerified || calls != wantCalls || *saves != 1 {
					t.Fatalf("success: %+v %v calls=%d saves=%d", out, st, calls, *saves)
				}
			} else {
				if st == nil || out.PersistenceVerified || *saves != 0 {
					t.Fatalf("failure: %+v %v saves=%d", out, st, *saves)
				}
			}
			beforeCalls := calls
			restarted := &SonicAgent{networkJournalDir: m.networkJournalDir, clientPool: map[string]*redis.Client{"CONFIG_DB": db}, planNetwork: m.planNetwork, saveConfig: func(context.Context) *agent.Status { *saves++; return nil }}
			if scenario == "unverified reply" || scenario == "dispatch fsync" {
				if _, st := restarted.RecoverNetworkResource(t.Context(), req); st == nil {
					t.Fatal("unverified activation completed")
				}
				failRuntime = true
				if _, st := restarted.RecoverNetworkResource(t.Context(), req); st == nil {
					t.Fatal("probe failure completed activation")
				}
				failRuntime = false
				activated = true // external evidence resolves uncertain dispatch
			}
			if _, st := restarted.RecoverNetworkResource(t.Context(), req); st != nil {
				t.Fatal(st)
			}
			if scenario == "prepared fsync" {
				beforeCalls++
			}
			if calls != beforeCalls {
				t.Fatal("activation replayed after durable dispatch")
			}
		})
	}
}

func TestNetworkPreflightFailureNoWrites(t *testing.T) {
	m, db, req, saves := networkEngineFixture(t)
	planner := m.planNetwork
	m.planNetwork = func(db vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
		p, err := planner(db, r)
		p.Preflight = func(context.Context, *SonicAgent) error { return errors.New("unsupported daemon") }
		return p, err
	}
	if _, st := m.EnsureNetworkResource(t.Context(), req); st == nil || *saves != 0 || db.DBSize(t.Context()).Val() != 0 {
		t.Fatal("preflight did not block writes")
	}
	if unlock, err := m.guardNetworkWrites(t.Context()); err != nil {
		t.Fatal(err)
	} else {
		unlock()
	}
}

func TestNetworkCASUncertainRetainsPending(t *testing.T) {
	m, db, req, _ := networkEngineFixture(t)
	db.AddHook(networkUncertainHook{})
	if _, st := m.EnsureNetworkResource(t.Context(), req); st == nil {
		t.Fatal("lost CAS reply accepted")
	}
	if unlock, err := m.guardNetworkWrites(t.Context()); err == nil {
		unlock()
		t.Fatal("uncertain CAS cleared pending")
	}
	other := redis.NewClient(db.Options())
	t.Cleanup(func() { _ = other.Close() })
	restarted := &SonicAgent{networkJournalDir: m.networkJournalDir, clientPool: map[string]*redis.Client{"CONFIG_DB": other}, planNetwork: m.planNetwork, saveConfig: func(context.Context) *agent.Status { return nil }}
	if out, st := restarted.RecoverNetworkResource(t.Context(), req); st != nil || !out.PersistenceVerified {
		t.Fatalf("uncertain recovery: %+v %v", out, st)
	}
}

func TestNetworkCASRejectedRetainsConfirmedOwner(t *testing.T) {
	m, db, req, _ := networkEngineFixture(t)
	if _, st := m.EnsureNetworkResource(t.Context(), req); st != nil {
		t.Fatal(st)
	}
	planner := m.planNetwork
	m.planNetwork = func(db vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
		p, err := planner(db, r)
		p.Desired["VRF|VrfAdditional"] = map[string]string{"NULL": "NULL"}
		return p, err
	}
	other := redis.NewClient(db.Options())
	t.Cleanup(func() { _ = other.Close() })
	db.AddHook(&networkCASHook{before: func(ctx context.Context) {
		if err := other.HSet(ctx, "OTHER|x", "value", "changed").Err(); err != nil {
			t.Fatal(err)
		}
	}})
	if _, st := m.EnsureNetworkResource(t.Context(), req); st == nil {
		t.Fatal("CAS should reject")
	}
	if unlock, err := m.guardNetworkWrites(t.Context()); err != nil {
		t.Fatal(err)
	} else {
		unlock()
	}
	m.planNetwork = planner
	foreign := *req
	foreign.OwnerID = "foreign"
	if _, st := m.GetNetworkResource(t.Context(), &foreign); st == nil {
		t.Fatal("confirmed ownership lost on CAS rejection")
	}
	if db.HGet(t.Context(), "VRF|VrfTest", "NULL").Val() != "NULL" || db.Exists(t.Context(), "VRF|VrfAdditional").Val() != 0 {
		t.Fatal("CAS rejection changed targets")
	}
}

func TestNetworkRuntimeNonconvergenceAndErrors(t *testing.T) {
	for _, operation := range []string{"get", "ensure"} {
		t.Run(operation, func(t *testing.T) {
			m, _, req, _ := networkEngineFixture(t)
			probeError := error(nil)
			planner := m.planNetwork
			m.planNetwork = func(db vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
				p, err := planner(db, r)
				p.Runtime = func(context.Context, *SonicAgent) (bool, json.RawMessage, error) {
					return false, json.RawMessage(`{"state":"pending"}`), probeError
				}
				return p, err
			}
			if out, st := m.networkResource(t.Context(), req, operation); st != nil || out.RuntimeVerified {
				t.Fatalf("nonconvergence is not an error: %+v %v", out, st)
			}
			probeError = errors.New("runtime command failed")
			if out, st := m.networkResource(t.Context(), req, operation); st == nil || out == nil || out.RuntimeVerified {
				t.Fatalf("runtime error not propagated: %+v %v", out, st)
			}
		})
	}
}

type networkUncertainHook struct{}

func (networkUncertainHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (networkUncertainHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

// Production planner, callback dispatch, receipt files, Redis CAS and journal
// recovery all run unchanged. Only SONiC command execution is injected: these
// tests cannot restart a host service or contact a switch.
func TestNetworkProductionRelayRecovery(t *testing.T) {
	for _, lostReply := range []bool{false, true} {
		t.Run(fmt.Sprintf("lost-restart-reply=%v", lostReply), func(t *testing.T) {
			m, db, _, _ := networkEngineFixture(t)
			m.planNetwork = nil
			m.networkJournalDir = filepath.Join(t.TempDir(), "network")
			if err := os.Mkdir(m.networkJournalDir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(m.networkJournalDir, ".lock"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			for key, fields := range (vlanChangeDB{
				"VLAN|Vlan100":                          {"vlanid": "100", "unknown": "keep"},
				"VLAN_INTERFACE|Vlan100":                {"NULL": "NULL"},
				"VLAN_INTERFACE|Vlan100|2001:db8::1/64": {"NULL": "NULL"},
			}) {
				if err := db.HSet(t.Context(), key, fields).Err(); err != nil {
					t.Fatal(err)
				}
			}
			restarts := 0
			runner := routingCommandRunner(func(cmd *exec.Cmd) ([]byte, error) {
				args := strings.Join(cmd.Args, " ")
				if args == "systemctl restart dhcp_relay.service" {
					if db.HGet(t.Context(), "DHCP_RELAY|Vlan100", "dhcpv6_servers@").Val() != "2001:db8::2" {
						t.Fatal("restart before CAS")
					}
					restarts++
					if lostReply {
						return nil, errors.New("restart reply lost")
					}
					return nil, nil
				}
				switch {
				case strings.HasPrefix(args, "docker inspect "):
					return []byte(fmt.Sprintf(`[{"Id":"relay","State":{"Running":true,"StartedAt":"start-%d"}}]`, restarts)), nil
				case strings.Contains(args, " cat /etc/supervisor/"), strings.Contains(args, " sonic-cfggen "):
					return []byte("[program:dhcp6relay]\ncommand=/usr/sbin/dhcp6relay\n"), nil
				case strings.Contains(args, " python3 -c "):
					return []byte(fmt.Sprintf(`[{"pid":"42","start":"%d","argv":["/usr/sbin/dhcp6relay"]}]`, 100+restarts)), nil
				default:
					t.Fatalf("unexpected command: %s", args)
					return nil, nil
				}
			})
			ctx := context.WithValue(t.Context(), routingCommandRunnerKey{}, runner)
			req := &agent.NetworkRequest{Kind: "DHCPRelay", OwnerID: "relay-uid", Spec: json.RawMessage(`{"vlanID":100,"ipv6Servers":["2001:db8::2"]}`)}
			// Get must neither invoke Activate nor create its sibling runtime directory.
			if _, st := m.GetNetworkResource(ctx, req); st != nil {
				t.Fatal(st)
			}
			if restarts != 0 {
				t.Fatal("Get restarted service")
			}
			if _, err := os.Stat(m.networkJournalDir + "-relay-runtime"); !os.IsNotExist(err) {
				t.Fatalf("Get created receipt directory: %v", err)
			}
			m.saveConfig = func(context.Context) *agent.Status { return &agent.Status{Code: 500} }
			out, st := m.EnsureNetworkResource(ctx, req)
			if st == nil || out == nil || !out.ConfigurationVerified || out.PersistenceVerified || restarts != 1 {
				t.Fatalf("pending relay: %+v %v restarts=%d", out, st, restarts)
			}
			restarted := &SonicAgent{networkJournalDir: m.networkJournalDir, clientPool: map[string]*redis.Client{"CONFIG_DB": db}, saveConfig: func(context.Context) *agent.Status { return nil }}
			// Latest desired is intentionally different. Recovery only completes old target.
			deleting := *req
			deleting.Spec = json.RawMessage(`{"vlanID":100,"ipv6Servers":["2001:db8::3"]}`)
			out, st = restarted.RecoverNetworkResource(ctx, &deleting)
			if st != nil || !out.ConfigurationVerified || !out.RuntimeVerified || !out.PersistenceVerified || restarts != 1 {
				t.Fatalf("production recovery: %+v %v restarts=%d", out, st, restarts)
			}
			if db.HGet(ctx, "DHCP_RELAY|Vlan100", "dhcpv6_servers@").Val() != "2001:db8::2" || db.HGet(ctx, "VLAN|Vlan100", "unknown").Val() != "keep" {
				t.Fatal("recovery changed new desired/unmanaged fields")
			}
		})
	}
}
func (networkUncertainHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		err := next(ctx, cmd)
		if err == nil && cmd.Name() == "eval" && cmd.Args()[1] == vlanChangeCASScript {
			return errors.New("CAS reply lost")
		}
		return err
	}
}
