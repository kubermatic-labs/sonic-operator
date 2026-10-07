// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSafeReason(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{nil, ""},
		{errors.New("agent binary is outside accepted release set"), "agent binary is outside accepted release set"},
		{fmt.Errorf("stage: %w", errors.New("running and installed agent executables differ")), "stage: running and installed agent executables differ"},
		{fmt.Errorf("lock: %w", context.DeadlineExceeded), "deadline exceeded"},
		{context.Canceled, "canceled"},
		{errors.New("confirmation token mismatch"), "confirmation token mismatch"},
		{errors.New("open /host/sonic-operator-artifacts/journal.json: permission denied"), "open /host/sonic-operator-artifacts/journal.json: permission denied"},
		{errors.New("token 0123456789abcdef0123456789abcdef rejected"), "unclassified"},
		{errors.New("-----BEGIN PRIVATE KEY-----"), "unclassified"},
		{errors.New("snmp community public rejected"), "unclassified"},
		{errors.New(`unexpected "quoted" value`), "unclassified"},
		{errors.New("line one\nline two"), "unclassified"},
		{errors.New(strings.Repeat("a ", 150)), "unclassified"},
	} {
		if got := SafeReason(tc.err); got != tc.want {
			t.Errorf("SafeReason(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}
