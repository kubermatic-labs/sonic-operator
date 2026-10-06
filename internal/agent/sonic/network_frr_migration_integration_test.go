//go:build integration

// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"github.com/redis/go-redis/v9"
)

func frrMigrationEngine(t *testing.T, explicit bool) (*SonicAgent, *redis.Client, *agent.NetworkRequest, *frrMigrationFixture, *int) {
	t.Helper()
	m, db, _, saves := networkEngineFixture(t)
	m.planNetwork = nil
	config := frrMigrationTestDB()
	if explicit {
		config["DEVICE_METADATA|localhost"]["frr_mgmt_framework_config"] = "false"
		config["DEVICE_METADATA|localhost"]["docker_routing_config_mode"] = "separated"
	}
	config["SNMP|LOCATION"] = map[string]string{"Location": "secret-sensitive-output"}
	for key, fields := range config {
		if err := db.HSet(t.Context(), key, fields).Err(); err != nil {
			t.Fatal(err)
		}
	}
	req := &agent.NetworkRequest{Kind: "FRRMigration", OwnerID: "migration-owner", Spec: json.RawMessage(`{"mode":"Unified"}`)}
	return m, db, req, newFRRMigrationFixture(), saves
}

func frrMigrationApprove(t *testing.T, m *SonicAgent, req *agent.NetworkRequest, f *frrMigrationFixture) string {
	t.Helper()
	out, st := m.GetNetworkResource(f.ctx(t), req)
	if st != nil {
		t.Fatal(st)
	}
	var observed struct {
		AdoptionDigest    string `json:"adoptionDigest"`
		PreflightEligible bool   `json:"preflightEligible"`
	}
	if json.Unmarshal(out.Observed, &observed) != nil || !observed.PreflightEligible || !vlanAuthorityDigestValid(observed.AdoptionDigest) {
		t.Fatalf("preflight %+v", out)
	}
	var spec frrMigrationSpec
	if err := json.Unmarshal(req.Spec, &spec); err != nil {
		t.Fatal(err)
	}
	req.Spec = json.RawMessage(`{"mode":"` + spec.Mode + `","approvedDigest":"` + observed.AdoptionDigest + `"}`)
	return observed.AdoptionDigest
}

func TestFRRMigrationRealEngine(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(fmt.Sprint("explicit-", explicit), func(t *testing.T) {
			m, db, req, f, saves := frrMigrationEngine(t, explicit)
			before, _, _ := m.vlanChangeSnapshot(t.Context())
			frrMigrationApprove(t, m, req, f)
			entries, err := os.ReadDir(m.networkJournalDir)
			if err != nil || len(entries) != 1 {
				t.Fatal("Get created migration evidence", err)
			}
			if out, st := m.EnsureNetworkResource(f.ctx(t), req); st != nil || !out.ConfigurationVerified || !out.RuntimeVerified || !out.PersistenceVerified || f.restarts != 1 || *saves != 1 {
				t.Fatalf("ensure %+v %v restarts=%d", out, st, f.restarts)
			}
			after, _, _ := m.vlanChangeSnapshot(t.Context())
			if !reflect.DeepEqual(after, frrMigrationPost(before)) {
				t.Fatal("migration changed non-mode fields")
			}
			receipt, err := frrMigrationReceiptFile(m.networkJournalDir, nil)
			if err != nil || !reflect.DeepEqual(receipt.Before, networkTarget(before, frrMigrationDesired())) {
				t.Fatal("missing durable before values", err)
			}
			for _, name := range []string{"network.json", "frr-migration/launch.json"} {
				data, err := os.ReadFile(filepath.Join(m.networkJournalDir, name))
				if err != nil || strings.Contains(string(data), "secret-sensitive-output") || strings.Contains(string(data), "password") {
					t.Fatal("secret escaped private backup", err)
				}
			}
			backup, err := os.ReadFile(filepath.Join(m.networkJournalDir, "frr-migration/backup.json"))
			if err != nil || !strings.Contains(string(backup), "password zebra") {
				t.Fatal("startup/running config not backed up", err)
			}
			// A fresh process and a cleared approval must remain idempotent.
			m = &SonicAgent{networkJournalDir: m.networkJournalDir, clientPool: map[string]*redis.Client{"CONFIG_DB": db}, saveConfig: func(context.Context) *agent.Status { (*saves)++; return nil }}
			req.Spec = json.RawMessage(`{"mode":"Unified"}`)
			if out, st := m.EnsureNetworkResource(f.ctx(t), req); st != nil || !out.RuntimeVerified || f.restarts != 1 || *saves != 1 {
				t.Fatalf("no-op %+v %v", out, st)
			}
			// Later BGP is allowed. Force a full-DB persistence refresh and ensure the
			// terminal migration's Prepared callback skips restart/empty preflight.
			if err := db.HSet(t.Context(), "BGP_GLOBALS|default", "local_asn", "65000").Err(); err != nil {
				t.Fatal(err)
			}
			f.config += "router bgp 65000\n"
			f.summary = `{"default":{"ipv4Unicast":{"asn":65000}}}`
			if out, st := m.EnsureNetworkResource(f.ctx(t), req); st != nil || !out.RuntimeVerified || !out.PersistenceVerified || f.restarts != 1 || *saves != 2 {
				t.Fatalf("subsequent BGP %+v %v restarts=%d", out, st, f.restarts)
			}
		})
	}
}

func TestFRRMigrationRecovery(t *testing.T) {
	for _, failure := range []string{"restart-response", "save", "post-cas", "dispatch-durability"} {
		t.Run(failure, func(t *testing.T) {
			m, db, req, f, _ := frrMigrationEngine(t, true)
			frrMigrationApprove(t, m, req, f)
			initialDir := m.networkJournalDir
			switch failure {
			case "restart-response":
				f.uncertain = true
			case "save":
				m.saveConfig = func(context.Context) *agent.Status { return &agent.Status{Code: 500} }
			case "post-cas":
				f.readHook = func(cmd *exec.Cmd) {
					if strings.Contains(strings.Join(cmd.Args, " "), "sonic-cfggen") && db.HGet(t.Context(), "DEVICE_METADATA|localhost", "frr_mgmt_framework_config").Val() == "true" {
						f.inputs = strings.Repeat("b", 64)
					}
				}
			case "dispatch-durability":
				// Third common journal sync is Dispatched (Prepared then CAS then dispatch).
				calls := 0
				m.journalSync = func(*os.File) error {
					calls++
					if calls == 3 {
						return fmt.Errorf("sync uncertain")
					}
					return nil
				}
			}
			out, st := m.EnsureNetworkResource(f.ctx(t), req)
			if st == nil || out == nil || out.PersistenceVerified {
				t.Fatalf("did not remain pending %+v %v", out, st)
			}
			f.readHook = nil
			f.inputs = strings.Repeat("a", 64)
			m = &SonicAgent{networkJournalDir: initialDir, clientPool: map[string]*redis.Client{"CONFIG_DB": db}, saveConfig: func(context.Context) *agent.Status { return nil }}
			// Recovery carries no approval and never attempts the new spec. Original
			// pending request and receipt drive the callback after restart.
			req.Spec = json.RawMessage(`{"mode":"Unified"}`)
			out, st = m.RecoverNetworkResource(f.ctx(t), req)
			if failure == "dispatch-durability" {
				if st == nil || f.restarts != 0 {
					t.Fatalf("blind dispatch replay %+v %v", out, st)
				}
				return
			}
			if st != nil || !out.RuntimeVerified || !out.PersistenceVerified || f.restarts != 1 {
				t.Fatalf("recover %+v %v restarts=%d", out, st, f.restarts)
			}
		})
	}
}

func TestFRRMigrationRefusalsNoMutation(t *testing.T) {
	for _, failure := range []string{"no-approval", "stale-db", "stale-runtime", "stale-template", "populated", "candidate", "split", "foreign-unified", "storage-file", "storage-symlink", "storage-permissions", "storage-malformed", "timeout"} {
		t.Run(failure, func(t *testing.T) {
			m, db, req, f, saves := frrMigrationEngine(t, true)
			if failure != "no-approval" {
				frrMigrationApprove(t, m, req, f)
			}
			dir := filepath.Join(m.networkJournalDir, "frr-migration")
			switch failure {
			case "stale-db":
				db.HSet(t.Context(), "PORT|Ethernet0", "description", "changed")
			case "stale-runtime":
				f.config = strings.ReplaceAll(f.config, "zebra nexthop-group keep 1\n", "")
			case "stale-template":
				f.inputs = strings.Repeat("b", 64)
			case "populated":
				db.HSet(t.Context(), "STATIC_ROUTE|0.0.0.0/0", "nexthop", "192.0.2.1")
			case "candidate":
				f.candidate += "router bgp 65000\n"
			case "split":
				db.HSet(t.Context(), "DEVICE_METADATA|localhost", "docker_routing_config_mode", "split-unified")
			case "foreign-unified":
				db.HSet(t.Context(), "DEVICE_METADATA|localhost", frrMigrationDesired()["DEVICE_METADATA|localhost"])
				f.fresh = true
			case "storage-file":
				if err := os.WriteFile(dir, []byte("file"), 0600); err != nil {
					t.Fatal(err)
				}
			case "storage-symlink":
				if err := os.Symlink(t.TempDir(), dir); err != nil {
					t.Fatal(err)
				}
			case "storage-permissions":
				if err := os.Mkdir(dir, 0500); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(dir, 0700) })
			case "storage-malformed":
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "launch.json"), []byte("bad"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, _, err := m.vlanChangeSnapshot(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			ctx := f.ctx(t)
			if failure == "timeout" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, st := m.EnsureNetworkResource(ctx, req); st == nil {
				t.Fatal("unsafe migration accepted")
			}
			after, _, err := m.vlanChangeSnapshot(t.Context())
			if err != nil || !reflect.DeepEqual(before, after) || f.restarts != 0 || *saves != 0 {
				t.Fatal("rejected request mutated switch", err)
			}
		})
	}
}

func TestFRRMigrationGetWithoutJournal(t *testing.T) {
	m, _, req, f, _ := frrMigrationEngine(t, false)
	m.networkJournalDir = ""
	frrMigrationApprove(t, m, req, f)
	if _, st := m.EnsureNetworkResource(f.ctx(t), req); st == nil || f.restarts != 0 {
		t.Fatal("write without journal allowed")
	}
}

func TestFRRMigrationObservedPreflightReason(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		validStatus  bool
	}{
		{"completed-helpers", "", true},
		{"supervisor-failure", "SupervisorStatusReadFailed", false},
		{"nonempty-config", "RunningConfigNotEmpty", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _, req, f, _ := frrMigrationEngine(t, false)
			if tc.name == "nonempty-config" {
				f.config += "password secret-sensitive-output\n"
			}
			exitErr := frrMigrationExitError(t, "3")
			ctx := context.WithValue(t.Context(), routingCommandRunnerKey{}, routingCommandRunner(func(cmd *exec.Cmd) ([]byte, error) {
				data, err := f.run(cmd)
				if strings.Join(cmd.Args, " ") == "docker exec bgp supervisorctl status" {
					if !tc.validStatus {
						return []byte("secret-sensitive-output"), exitErr
					}
					return data, exitErr
				}
				return data, err
			}))
			out, st := m.GetNetworkResource(ctx, req)
			if st != nil {
				t.Fatal(st)
			}
			var observed struct {
				Reason   string `json:"preflightReason"`
				Eligible bool   `json:"preflightEligible"`
				Digest   string `json:"adoptionDigest"`
			}
			if json.Unmarshal(out.Observed, &observed) != nil || observed.Reason != tc.reason || observed.Eligible != (tc.reason == "") || (observed.Digest != "") != (tc.reason == "") {
				t.Fatalf("unexpected observation %s", out.Observed)
			}
			if strings.Contains(string(out.Observed), "secret-sensitive-output") {
				t.Fatal("observation leaked command/config content")
			}
			entries, err := os.ReadDir(m.networkJournalDir)
			if err != nil || len(entries) != 1 || f.restarts != 0 {
				t.Fatal("Observe changed migration state")
			}
		})
	}
}

func TestFRRMigrationUnverifiedRestartNeverReplayed(t *testing.T) {
	for _, failure := range []string{"not-fresh", "runtime-populated", "config-drift", "routes-drift"} {
		t.Run(failure, func(t *testing.T) {
			m, db, req, f, _ := frrMigrationEngine(t, true)
			frrMigrationApprove(t, m, req, f)
			f.uncertain = true
			f.restartHook = func() {
				switch failure {
				case "not-fresh":
					f.fresh = false
				case "runtime-populated":
					f.config += "router bgp 65000\n"
				case "config-drift":
					db.HSet(t.Context(), "PORT|Ethernet0", "description", "changed-after-dispatch")
				case "routes-drift":
					f.kernel = `[]`
				}
			}
			if _, st := m.EnsureNetworkResource(f.ctx(t), req); st == nil {
				t.Fatal("uncertain restart accepted")
			}
			m = &SonicAgent{networkJournalDir: m.networkJournalDir, clientPool: map[string]*redis.Client{"CONFIG_DB": db}, saveConfig: func(context.Context) *agent.Status { t.Fatal("saved unverified migration"); return nil }}
			req.Spec = json.RawMessage(`{"mode":"Unified"}`)
			if out, st := m.RecoverNetworkResource(f.ctx(t), req); st == nil || out.PersistenceVerified || f.restarts != 1 {
				t.Fatalf("replayed or accepted unverified restart %+v %v", out, st)
			}
		})
	}
}

func TestFRRMigrationChangedRequestRecoversOriginalFirst(t *testing.T) {
	m, db, req, f, _ := frrMigrationEngine(t, true)
	frrMigrationApprove(t, m, req, f)
	f.uncertain = true
	if _, st := m.EnsureNetworkResource(f.ctx(t), req); st == nil {
		t.Fatal("expected uncertain response")
	}
	m = &SonicAgent{networkJournalDir: m.networkJournalDir, clientPool: map[string]*redis.Client{"CONFIG_DB": db}, saveConfig: func(context.Context) *agent.Status { return nil }}
	req.Spec = json.RawMessage(`{"mode":"Unified","approvedDigest":"` + strings.Repeat("b", 64) + `"}`)
	if out, st := m.EnsureNetworkResource(f.ctx(t), req); st == nil || !out.PersistenceVerified || f.restarts != 1 {
		t.Fatalf("changed request didn't recover original %+v %v", out, st)
	}
	if out, st := m.EnsureNetworkResource(f.ctx(t), req); st != nil || !out.PersistenceVerified || f.restarts != 1 {
		t.Fatalf("terminal request %+v %v", out, st)
	}
}
