// SPDX-License-Identifier: Apache-2.0
package host

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

type bootClock struct {
	ID      string
	Seconds float64
}

func readBootClock() (bootClock, error) {
	// Non-Linux builds are for offline tests only. SONiC always uses the
	// boot-relative clock, so NTP adjustments cannot extend rollback deadlines.
	if runtime.GOOS != "linux" {
		return bootClock{}, nil
	}
	id, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return bootClock{}, ErrStorage
	}
	uptime, e := os.ReadFile("/proc/uptime")
	if e != nil {
		return bootClock{}, ErrStorage
	}
	fields := strings.Fields(string(uptime))
	if len(fields) != 2 {
		return bootClock{}, ErrStorage
	}
	seconds, e := strconv.ParseFloat(fields[0], 64)
	if e != nil || seconds < 0 || len(strings.TrimSpace(string(id))) != 36 {
		return bootClock{}, ErrStorage
	}
	return bootClock{strings.TrimSpace(string(id)), seconds}, nil
}
