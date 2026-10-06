// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestTraditionalBGPUnmanagedPreservation(t *testing.T) {
	t.Parallel()
	s := routingBGPSpec{VRF: "default", LocalASN: 65100, RouterID: "10.1.0.1", Prefixes: []string{"10.1.0.1/32"}}
	baseline := traditionalRuntimeFixture + "password test-token\nenable password test-enable-token\n"
	startup := map[string]string{"bgpd.conf": strings.ReplaceAll(baseline, "PL_LoopbackV4 seq 5 permit", "PL_LoopbackV4 permit")}
	for _, tc := range []struct {
		name, running string
		allowed       bool
	}{
		{"matching unmanaged state", baseline, true},
		{"owned ASN drift", strings.ReplaceAll(baseline, "router bgp 65100", "router bgp 65101"), true},
		{"credential drift", strings.ReplaceAll(baseline, "password test-token", "password changed-token"), false},
		{"enable credential drift", strings.ReplaceAll(baseline, "enable password test-enable-token", "enable password changed-token"), false},
		{"hostname drift", strings.ReplaceAll(baseline, "hostname switch", "hostname changed"), false},
		{"removed logging", strings.ReplaceAll(baseline, "log syslog informational\n", ""), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := traditionalPreflightPolicy(startup, tc.running, s); (err == nil) != tc.allowed {
				t.Fatalf("allowed=%v err=%v", tc.allowed, err)
			}
		})
	}
}

func TestTraditionalBGPActivationPreservesUnmanagedSettings(t *testing.T) {
	t.Parallel()
	s := routingBGPSpec{VRF: "default", LocalASN: 65100, RouterID: "10.1.0.1", Prefixes: []string{"10.1.0.1/32"}}
	baseline := traditionalRuntimeFixture + "password test-token\nenable password test-enable-token\n"
	render, _ := json.Marshal(map[string]string{"bgpd.conf": strings.ReplaceAll(baseline, "PL_LoopbackV4 seq 5 permit", "PL_LoopbackV4 permit"), "zebra.conf": "! baseline", "staticd.conf": "! baseline", "setsrc.conf": "! baseline"})
	for _, tc := range []struct {
		name, running string
		allowed       bool
	}{{"unmanaged credential drift", strings.ReplaceAll(baseline, "password test-token", "password changed-token"), false}} {
		t.Run(tc.name, func(t *testing.T) {
			restarts := 0
			ctx := context.WithValue(t.Context(), routingCommandRunnerKey{}, routingCommandRunner(func(cmd *exec.Cmd) ([]byte, error) {
				a := cmd.Args
				switch {
				case reflect.DeepEqual(a, []string{"python3", "-c", traditionalHostScript}):
					return []byte(traditionalHostDigest), nil
				case len(a) == 6 && a[5] == traditionalBundleScript:
					return []byte(traditionalBundleDigest), nil
				case len(a) == 8 && a[5] == traditionalRenderScript:
					return render, nil
				case reflect.DeepEqual(a, []string{"docker", "inspect", "bgp", "--format", "{{json .Mounts}}"}):
					return []byte(`[{"Type":"bind","Source":"/etc/sonic/frr","Destination":"/etc/frr","RW":true},{"Type":"bind","Source":"/etc/sonic","Destination":"/etc/sonic","RW":false}]`), nil
				case reflect.DeepEqual(a, []string{"docker", "exec", "bgp", "vtysh", "-c", "show running-config"}):
					return []byte(tc.running), nil
				case reflect.DeepEqual(a, []string{"systemctl", "restart", "bgp.service"}):
					restarts++
					return nil, nil
				default:
					return nil, fmt.Errorf("unexpected native command")
				}
			}))
			plan, err := planTraditionalBGP(traditionalDB(), s)
			if err != nil {
				t.Fatal(err)
			}
			err = plan.Activate(ctx, nil)
			if (err == nil) != tc.allowed || restarts != map[bool]int{true: 1, false: 0}[tc.allowed] {
				t.Fatalf("allowed=%v restarts=%d err=%v", tc.allowed, restarts, err)
			}
			if err != nil && strings.Contains(err.Error(), "changed-token") {
				t.Fatal("opaque value leaked into error")
			}
		})
	}
}
