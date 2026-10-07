// SPDX-License-Identifier: Apache-2.0
package host

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestArtifactFenceDoesNotWaitForHostReader(t *testing.T) {
	e, _, _ := newTestEngine(t)
	_, unlock, err := lockRecord(t.Context(), e.dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	for name, guard := range map[string]func(context.Context, string, func() error) error{"publication": WithArtifactExclusion, "dependency": WithArtifactAgentRecoveryExclusion} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			start := time.Now()
			err := guard(ctx, e.dir, func() error { t.Error("host exclusion bypassed"); return nil })
			if !errors.Is(err, ErrBusy) || ctx.Err() != nil || time.Since(start) > 250*time.Millisecond {
				t.Fatalf("host busy held outer writers until deadline: %v", err)
			}
		})
	}
}
