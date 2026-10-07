// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestColdBootWaitsForSyncdAndNativeInstallers(t *testing.T) {
	e, _ := testEngine(t)
	e.DeferActivation = true
	syncd, settled := false, false
	n := &Native{Engine: e, Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		text := strings.Join(args, " ")
		if strings.Contains(text, "SubState") {
			if !settled {
				return []byte("start"), nil
			}
			return []byte("exited"), nil
		}
		if strings.Contains(text, "inspect syncd") {
			if syncd {
				return []byte("true"), nil
			}
			return []byte("false"), nil
		}
		if strings.Contains(text, "supervisorctl status") {
			return []byte(args[len(args)-1] + " EXITED done"), nil
		}
		return []byte("true"), nil
	}}
	activations := 0
	e.Activate = func() error {
		if err := n.consumersReady(context.Background(), false); err != nil {
			return err
		}
		activations++
		return nil
	}
	now := time.Now()
	b := testBundle()
	if _, err := e.Ensure(b, now); err != nil {
		t.Fatal(err)
	}
	_ = e.Tick(now)
	for i := 0; i < 3; i++ {
		if i == 1 {
			settled = true
		}
		if i == 2 {
			syncd = true
		}
		if err := e.Tick(now.Add(time.Duration(i) * time.Second)); err != nil {
			t.Fatal(err)
		}
		j, _ := e.load()
		if i < 2 && j.Phase != "Activating" {
			t.Fatal("normal startup ordering triggered rollback")
		}
	}
	if activations != 1 {
		t.Fatalf("activation count %d", activations)
	}
}
