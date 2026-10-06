// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"fmt"
	"time"
)

func (e *Engine) armDeadline(j *journal, now time.Time) error {
	j.Deadline = now.Add(5 * time.Minute)
	if e.BootID != nil {
		j.ActivationBootID = e.BootID()
	}
	if e.Uptime != nil {
		uptime := e.Uptime()
		if uptime < 0 {
			return fmt.Errorf("monotonic recovery clock unavailable")
		}
		j.DeadlineUptime = int64(uptime + 5*time.Minute)
	}
	return nil
}
func (e *Engine) expired(j *journal, now time.Time) bool {
	if e.BootID != nil && j.ActivationBootID != "" && j.ActivationBootID != e.BootID() {
		return true
	}
	if e.Uptime != nil {
		uptime := e.Uptime()
		return uptime < 0 || j.DeadlineUptime <= 0 || int64(uptime) >= j.DeadlineUptime
	}
	return !now.Before(j.Deadline)
}
