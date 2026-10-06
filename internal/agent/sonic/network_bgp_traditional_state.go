// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"fmt"
)

// ZebraSetSrc consumes every Loopback0 address row, selecting the first IPv4
// source and independently generating IPv6 policy. CONFIG_DB alone cannot prove
// that this asynchronous consumer input set is unambiguous. Never clean up or
// take ownership of these rows; even an extra not-yet-ready row is unsupported.
func traditionalLoopbackState(ctx context.Context, m *SonicAgent, s routingBGPSpec) (bool, error) {
	read := qosRedisRead{agent: m}
	const pattern = "INTERFACE_TABLE|Loopback0|*"
	expected := "INTERFACE_TABLE|Loopback0|" + s.Prefixes[0]
	keys, err := read.keys(ctx, "STATE_DB", pattern)
	if err != nil {
		return false, err
	}
	if len(keys) == 0 {
		return false, nil
	}
	if len(keys) != 1 || keys[0] != expected {
		return false, fmt.Errorf("unsupported Loopback0 STATE_DB source set")
	}
	state, err := read.hash(ctx, "STATE_DB", expected)
	if err != nil {
		return false, err
	}
	// Do not combine the expected row with a source set that changed while read.
	latest, err := read.keys(ctx, "STATE_DB", pattern)
	if err != nil {
		return false, err
	}
	if len(latest) != 1 || latest[0] != expected {
		return false, fmt.Errorf("Loopback0 STATE_DB source set changed during observation")
	}
	return state["state"] == "ok", ctx.Err()
}

func traditionalRequireLoopbackState(ctx context.Context, m *SonicAgent, s routingBGPSpec) error {
	ready, err := traditionalLoopbackState(ctx, m, s)
	if err != nil {
		return err
	}
	if !ready {
		return fmt.Errorf("Loopback0 consumer input must converge before BGP regeneration")
	}
	return nil
}
