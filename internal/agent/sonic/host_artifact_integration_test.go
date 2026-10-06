// SPDX-License-Identifier: Apache-2.0
package sonic

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/ironcore-dev/sonic-operator/internal/agent/artifactstate"
)

func TestHostNativeRejectsArtifactReservation(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	if err := artifactstate.Store(dir, artifactstate.Reservation{Version: 1, Owner: "artifact", Token: strings.Repeat("a", 32), Manifest: strings.Repeat("b", 64), Phase: "Active"}); err != nil {
		t.Fatal(err)
	}
	m := &SonicAgent{artifactStateDir: dir}
	called := false
	if err := m.withHostMutation(t.Context(), func() error { called = true; return nil }); !errors.Is(err, artifactstate.ErrReserved) || called {
		t.Fatalf("host dispatched under artifact reservation: called=%v err=%v", called, err)
	}
	// The host CAS marker only bypasses its own pending fence.
	ctx := context.WithValue(t.Context(), hostCASKey{}, true)
	if _, err := m.casVLANChange(ctx, "{}", nil, nil); !errors.Is(err, artifactstate.ErrReserved) {
		t.Fatalf("host CAS bypassed artifact: %v", err)
	}
	ctx = context.WithValue(ctx, artifactRecoveryKey{}, true)
	if err := m.NewHostNative().CheckPublication(ctx); !errors.Is(err, artifactstate.ErrReserved) {
		t.Fatalf("new publication inherited recovery privilege: %v", err)
	}
}
