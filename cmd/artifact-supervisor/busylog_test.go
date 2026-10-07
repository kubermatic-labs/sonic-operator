// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestBusyLogSummarizesLockTimeouts(t *testing.T) {
	now := time.Unix(1000, 0)
	b := &busyLog{interval: time.Minute, now: func() time.Time { return now }}
	reason := func(err error) string { return err.Error() }
	busy := fmt.Errorf("guard: %w", context.DeadlineExceeded)
	step := func(err error, advance time.Duration) string {
		now = now.Add(advance)
		return b.observe(err, "check", reason)
	}
	if got := step(nil, 0); got != "" {
		t.Fatalf("success logged: %q", got)
	}
	if got := step(busy, 0); got != "check: writer locks busy; deferred 1 checks" {
		t.Fatalf("first busy: %q", got)
	}
	for i := 0; i < 5; i++ {
		if got := step(busy, 10*time.Second); got != "" {
			t.Fatalf("busy within interval logged: %q", got)
		}
	}
	if got := step(errors.New("agent binary is outside accepted release set"), time.Second); got != "check: agent binary is outside accepted release set" {
		t.Fatalf("real failure suppressed: %q", got)
	}
	if got := step(busy, 10*time.Second); got != "check: writer locks busy; deferred 6 checks" {
		t.Fatalf("summary after interval: %q", got)
	}
}
