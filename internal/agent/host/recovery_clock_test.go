// SPDX-License-Identifier: Apache-2.0
package host

import (
	"context"
	"testing"
	"time"
)

func TestManagementDeadlineSurvivesWallClockChangesAndReboot(t *testing.T) {
	for _, reboot := range []bool{false, true} {
		e, f, now := newTestEngine(t)
		clock := bootClock{ID: "boot-a", Seconds: 100}
		e.bootNow = func() (bootClock, error) { return clock, nil }
		q := managementRequest()
		q.Management.Addresses[0].Prefix = "10.0.0.99/24"
		if _, err := e.Ensure(context.Background(), q, "c"); err != nil {
			t.Fatal(err)
		}
		*now = now.Add(-24 * time.Hour)
		if reboot {
			clock.ID = "boot-b"
			clock.Seconds = 1
		} else {
			clock.Seconds = 161
		}
		if err := e.RecoverExpired(context.Background()); err != nil {
			t.Fatal(err)
		}
		if f.restore != 1 {
			t.Fatal("local deadline depended on adjustable wall clock")
		}
	}
}
