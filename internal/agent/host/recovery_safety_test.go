// SPDX-License-Identifier: Apache-2.0
package host

import (
	"context"
	"testing"
	"time"
)

func TestRolledBackRevisionDoesNotContinuouslyRetry(t *testing.T) {
	e, f, now := newTestEngine(t)
	q := managementRequest()
	q.Management.MAC = "02:00:00:00:00:99"
	if _, err := e.Ensure(context.Background(), q, "c"); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Minute)
	if err := e.RecoverExpired(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Ensure(context.Background(), q, "c2"); err == nil {
		t.Fatal("rolled back revision retried automatically")
	}
	if f.apply != 1 {
		t.Fatal("management flapped after rollback")
	}
}
