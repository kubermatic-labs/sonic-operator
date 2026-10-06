// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"context"
	"testing"
)

func TestRetirementCommandsRetainBoundRequestCancellation(t *testing.T) {
	e, _ := testEngine(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e.mu.Lock()
	defer e.mu.Unlock()
	defer e.bindRequest(ctx)()
	calls := 0
	n := &Native{Engine: e, Run: func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
		calls++
		if ctx.Err() == nil {
			t.Fatal("retirement command discarded request cancellation")
		}
		return nil, ctx.Err()
	}}
	if err := n.Finalize(); err == nil {
		t.Fatal("canceled finalization succeeded")
	}
	if err := n.RetirementCheck(); err == nil {
		t.Fatal("canceled retirement check succeeded")
	}
	if calls != 2 {
		t.Fatal("bounded command adapter not used")
	}
}
