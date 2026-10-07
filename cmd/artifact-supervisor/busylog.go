// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"errors"
	"strconv"
	"time"
)

// busyLog keeps the one-second recovery loop readable. A check that could not
// acquire its locks within the loop budget is retried on the next tick, so
// lock timeouts are summarized at most once per interval. Every other failure
// is reported immediately.
type busyLog struct {
	interval time.Duration
	now      func() time.Time
	last     time.Time
	deferred int
}

// observe returns the line to log for err, or "" when nothing should be logged.
func (b *busyLog) observe(err error, message string, reason func(error) string) string {
	if err == nil {
		return ""
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		return message + ": " + reason(err)
	}
	b.deferred++
	now := b.now()
	if !b.last.IsZero() && now.Sub(b.last) < b.interval {
		return ""
	}
	line := message + ": writer locks busy; deferred " + strconv.Itoa(b.deferred) + " checks"
	b.last, b.deferred = now, 0
	return line
}
