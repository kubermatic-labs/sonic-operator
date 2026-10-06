// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestBreakoutNativeValidationBeforeIntent(t *testing.T) {
	for _, noop := range []bool{false, true} {
		t.Run(fmt.Sprint("noop=", noop), func(t *testing.T) {
			m, _, calls, saves := breakoutFixture(t)
			validations := 0
			m.validateBreakoutConfig = func(ctx context.Context) error {
				validations++
				if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 10*time.Second {
					t.Fatal("validation is not bounded")
				}
				if _, err := os.Stat(filepath.Join(m.breakoutJournalDir, "breakout.json")); !os.IsNotExist(err) {
					t.Fatalf("intent exists before validation: %v", err)
				}
				return fmt.Errorf("native CONFIG_DB validation failed: inspect MGMT_PORT")
			}
			r := splitRequest()
			if noop {
				r.Mode = "1x100G[40G]"
			}
			for range 2 {
				got, s := m.ReconcilePortBreakout(t.Context(), r)
				if s == nil || !strings.Contains(s.Message, "MGMT_PORT") || got.Pending {
					t.Fatalf("validation failure: %+v %+v", got, s)
				}
			}
			if validations != 2 || *calls != 0 || *saves != 0 {
				t.Fatalf("validation/CLI/save counts: %d/%d/%d", validations, *calls, *saves)
			}
			if _, err := os.Stat(filepath.Join(m.breakoutJournalDir, "breakout.json")); !os.IsNotExist(err) {
				t.Fatalf("intent created despite validation failure: %v", err)
			}
		})
	}
}

func TestBreakoutNativeValidationCommand(t *testing.T) {
	for _, tc := range []struct {
		name, output, message string
		runErr                error
	}{
		{"success", "ok\n", "", nil},
		{"missing management port", "mgmt_port\n", "MGMT_PORT", nil},
		{"missing management gateway", "mgmt_gateway\n", "gwaddr", nil},
		{"invalid config", "invalid\n", "operator approval", nil},
		{"unexpected output", "SECRET raw config", "validation", nil},
		{"process failure", "SECRET raw config", "validation", fmt.Errorf("SECRET stderr")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &SonicAgent{runBreakout: func(ctx context.Context, cmd *exec.Cmd) ([]byte, error) {
				if !reflect.DeepEqual(cmd.Args, []string{"python3", "-c", breakoutValidationPython}) || cmd.Stdin != nil || cmd.WaitDelay > time.Second {
					t.Fatalf("unsafe validation command: %+v", cmd)
				}
				if !strings.Contains(cmd.Args[2], "ConfigMgmtDPB()") || strings.Contains(cmd.Args[2], "writeConfigDB(") || strings.Contains(cmd.Args[2], "breakOutPort(") {
					t.Fatal("validation must only construct native ConfigMgmt")
				}
				return []byte(tc.output), tc.runErr
			}}
			err := m.checkNativeBreakoutConfig(t.Context())
			if tc.message == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.message) || strings.Contains(err.Error(), "SECRET") {
				t.Fatalf("unsafe/unhelpful validation error: %v", err)
			}
		})
	}
}

func TestBreakoutNativeValidationDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := &SonicAgent{runBreakout: func(ctx context.Context, _ *exec.Cmd) ([]byte, error) { <-ctx.Done(); return nil, ctx.Err() }}
		start := time.Now()
		err := m.checkNativeBreakoutConfig(t.Context())
		if err == nil || !strings.Contains(err.Error(), "deadline") || time.Since(start) != 10*time.Second {
			t.Fatalf("deadline: %v after %s", err, time.Since(start))
		}
	})
}

func TestBreakoutValidationHelperSanitizesConstructorFailure(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 required for fixed helper test")
	}
	for _, tc := range []struct{ name, failure, want string }{
		{"success", "", "ok"},
		{"nested port leafref", "MGMT_PORT leafref non-existing SECRET address", "mgmt_port"},
		{"nested gateway", "Missing mandatory gwaddr SECRET address", "mgmt_gateway"},
		{"unknown", "SECRET configuration", "invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Stand-in constructor logs through both Python and native file
			// descriptors, then wraps its exception like installed ConfigMgmt.
			prefix := fmt.Sprintf(`import os, sys, types
module = types.ModuleType('config.config_mgmt')
def constructor():
    print('SECRET config stdout')
    os.write(1, b'SECRET native stdout')
    os.write(2, b'SECRET native stderr')
    try:
        if %q:
            raise ValueError(%q)
    except Exception:
        raise Exception('ConfigMgmtDPB Class creation failed')
module.ConfigMgmtDPB = constructor
sys.modules['config'] = types.ModuleType('config')
sys.modules['config.config_mgmt'] = module
`, tc.failure, tc.failure)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			out, err := exec.CommandContext(ctx, python, "-c", prefix+breakoutValidationPython).CombinedOutput()
			if err != nil || string(out) != tc.want+"\n" {
				t.Fatalf("helper output: %q err %v", out, err)
			}
		})
	}
}
