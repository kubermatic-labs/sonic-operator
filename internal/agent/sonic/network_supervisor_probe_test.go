// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"os/exec"
	"testing"
)

func TestRoutingSupervisorExitThreeWithCompleteReport(t *testing.T) {
	err := exec.Command("sh", "-c", "exit 3").Run()
	ctx := context.WithValue(t.Context(), routingCommandRunnerKey{}, routingCommandRunner(func(*exec.Cmd) ([]byte, error) {
		return []byte("frrcfgd RUNNING pid 10, uptime 0:01:00\nbgpd RUNNING pid 11, uptime 0:01:00\ndependent-startup EXITED Sep 15\n"), err
	}))
	if _, err := runRoutingRead(ctx, routingBGPDaemons); err != nil {
		t.Fatal(err)
	}
}

func TestEVPNSupervisorKnownOneShots(t *testing.T) {
	err := exec.Command("sh", "-c", "exit 3").Run()
	for _, tc := range []struct {
		report string
		valid  bool
	}{
		{"orchagent RUNNING\nvxlanmgrd RUNNING\nenable_counters EXITED\ngearsyncd EXITED\nrestore_neighbors EXITED\nswssconfig EXITED\nwait_for_link EXITED\n", true},
		{"orchagent FATAL\nvxlanmgrd RUNNING\n", false},
		{"orchagent EXITED\nvxlanmgrd RUNNING\n", false},
		{"orchagent RUNNING\nunknown EXITED\n", false},
		{"orchagent RUNNING\norchagent RUNNING\n", false},
	} {
		if got := evpnSupervisorError([]byte(tc.report), err); (got == nil) != tc.valid {
			t.Fatalf("report=%q accepted=%v", tc.report, got == nil)
		}
	}
}
