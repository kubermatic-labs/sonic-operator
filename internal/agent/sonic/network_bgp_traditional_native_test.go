// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func TestTraditionalBGPQualification(t *testing.T) {
	t.Parallel()
	const mounts = `[{"Type":"bind","Source":"/etc/sonic/frr","Destination":"/etc/frr","RW":true},{"Type":"bind","Source":"/etc/sonic","Destination":"/etc/sonic","RW":false}]`
	for _, tc := range []struct {
		name, bundle, mounts string
		valid                bool
	}{
		{"qualified", traditionalBundleDigest, mounts, true},
		{"unknown bundle", "other", mounts, false},
		{"unqualified host activation", traditionalBundleDigest, mounts, false},
		{"wrong source", traditionalBundleDigest, strings.ReplaceAll(mounts, `"Source":"/etc/sonic/frr"`, `"Source":"/other"`), false},
		{"missing read-only evidence", traditionalBundleDigest, strings.ReplaceAll(mounts, `,"RW":false`, ``), false},
		{"shadowed startup", traditionalBundleDigest, strings.TrimSuffix(mounts, "]") + `,{"Type":"bind","Source":"/other","Destination":"/etc/frr/bgpd.conf","RW":true}]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.WithValue(t.Context(), routingCommandRunnerKey{}, routingCommandRunner(func(cmd *exec.Cmd) ([]byte, error) {
				if cmd.Args[0] == "python3" {
					if tc.name == "unqualified host activation" {
						return []byte("changed"), nil
					}
					return []byte("0f884c2af47da31b885f5bce8d6f61f9b2964aa9395e142877ba3b14ff34b475"), nil
				}
				if len(cmd.Args) > 5 && cmd.Args[5] == traditionalBundleScript {
					return []byte(tc.bundle), nil
				}
				if len(cmd.Args) > 1 && cmd.Args[1] == "inspect" {
					return []byte(tc.mounts), nil
				}
				return nil, fmt.Errorf("unexpected native read")
			}))
			if err := traditionalQualified(ctx); (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
		})
	}
}
