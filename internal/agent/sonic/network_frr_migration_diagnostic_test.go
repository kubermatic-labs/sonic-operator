// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

func frrMigrationExitError(t *testing.T, code string) error {
	t.Helper()
	err := exec.Command("sh", "-c", "exit "+code).Run()
	if err == nil {
		t.Fatal("expected process exit")
	}
	return err
}

func TestFRRMigrationSupervisorExitStatus(t *testing.T) {
	for _, tc := range []struct {
		name, extra, exit string
		command           frrMigrationCommand
		accepted          bool
	}{
		{"expected-completed-helpers", "", "3", frrMigrationDaemons, true},
		{"unified-startup-helper", "vtysh_b EXITED Sep 12 01:31 PM\n", "3", frrMigrationDaemons, true},
		{"fatal", "ospfd FATAL secret-sensitive-output\n", "3", frrMigrationDaemons, false},
		{"unexpected-exit", "bgpmon EXITED Sep 12 01:31 PM\n", "3", frrMigrationDaemons, false},
		{"malformed", "secret-sensitive-output\n", "3", frrMigrationDaemons, false},
		{"other-exit", "", "1", frrMigrationDaemons, false},
		{"other-command", "", "3", frrMigrationConfig, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newFRRMigrationFixture()
			exitErr := frrMigrationExitError(t, tc.exit)
			ctx := context.WithValue(t.Context(), routingCommandRunnerKey{}, routingCommandRunner(func(cmd *exec.Cmd) ([]byte, error) {
				data, _ := fixture.run(exec.Command("docker", "exec", "bgp", "supervisorctl", "status"))
				return append(data, []byte(tc.extra)...), exitErr
			}))
			_, err := runFRRMigration(ctx, tc.command)
			if (err == nil) != tc.accepted {
				t.Fatalf("accepted=%v err=%v", tc.accepted, err)
			}
			if err != nil && strings.Contains(err.Error(), "secret-sensitive-output") {
				t.Fatal("raw diagnostic leaked")
			}
		})
	}
}

func TestFRRMigrationDiagnosticReason(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		change       func(*frrMigrationFixture)
	}{
		{"config", "RunningConfigNotEmpty", func(f *frrMigrationFixture) { f.config += "password secret-sensitive-output\n" }},
		{"candidate", "CandidateNotEmpty", func(f *frrMigrationFixture) { f.candidate += "router bgp 65000\n" }},
		{"routes", "KernelIPv4RoutesUnsupported", func(f *frrMigrationFixture) { f.kernel = `[{"dst":"default","dev":"Ethernet0"}]` }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFRRMigrationFixture()
			tc.change(f)
			_, err := inspectFRRMigration(f.ctx(t), frrMigrationTestDB())
			if got := frrMigrationReason(err); got != tc.reason {
				t.Fatalf("reason %q, want %q", got, tc.reason)
			}
			if strings.Contains(err.Error(), "secret-sensitive-output") {
				t.Fatal("secret leaked")
			}
		})
	}
	if got := frrMigrationReason(errors.New("secret-sensitive-output")); got != "PreflightFailed" {
		t.Fatalf("unknown error exposed: %s", got)
	}
}
