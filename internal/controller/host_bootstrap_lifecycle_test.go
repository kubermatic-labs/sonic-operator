// SPDX-License-Identifier: Apache-2.0
package controller

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ironcore-dev/sonic-operator/internal/agent/artifactstate"
	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
	"github.com/ironcore-dev/sonic-operator/internal/artifact"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Native service probes are simulated; installation, immutable owner, host flock,
// reservation, real mTLS client and supervisor transitions are production code.
type lifecycleHostFence struct {
	verifies, mutations int
	unhealthy           bool
}

func (*lifecycleHostFence) QualifyHostBootstrap(context.Context, []byte, bool) error { return nil }
func (f *lifecycleHostFence) VerifyHostBootstrap(context.Context) error {
	f.verifies++
	if f.unhealthy {
		return fmt.Errorf("timer drift")
	}
	return nil
}
func (f *lifecycleHostFence) WithMutation(_ context.Context, fn func() error) error {
	f.mutations++
	return fn()
}
func (*lifecycleHostFence) WithAgentRecovery(context.Context, string, string, string, func() error) error {
	return fmt.Errorf("not an agent recovery")
}

func TestControllerConfirmsArtifactWithConfirmedHostBootstrap(t *testing.T) {
	// The original base regression staged only a generated AgentUnit. Use the
	// complete accepted A/B recovery fixture required by the integrated floor.
	r, _, obj, s, b, _, _, _ := releaseControllerFixture(t, "unowned")
	unchangedHost := captureReleaseHostSuite(t, s.root)
	reconcile := func() error {
		_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)})
		return err
	}
	if err := reconcile(); err != nil {
		t.Fatal(err)
	}
	s.tick(t, time.Now())
	reservation, err := artifactstate.Read(filepath.Join(s.root, artifactstate.DefaultDir))
	if err != nil || reservation == nil || reservation.Phase != "Active" {
		t.Fatalf("no active reservation: %+v %v", reservation, err)
	}
	receipt, err := os.ReadFile(filepath.Join(s.root, host.RecoveryReceiptFile))
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(filepath.Join(s.root, host.RecoveryBinaryFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, drift := range []string{"timer", "binary"} {
		s.hostFence.unhealthy = drift == "timer"
		if drift == "binary" {
			if err := os.WriteFile(filepath.Join(s.root, host.RecoveryBinaryFile), []byte("drift"), 0755); err != nil {
				t.Fatal(err)
			}
		}
		if err := artifact.EnsureHostBootstrap(t.Context(), s.root, b, s.hostFence, func(context.Context) error { t.Fatal("host repair activated under artifact reservation"); return nil }); err == nil {
			t.Fatal("host drift accepted under reservation", drift)
		}
		after, _ := os.ReadFile(filepath.Join(s.root, host.RecoveryReceiptFile))
		if string(after) != string(receipt) {
			t.Fatal("receipt rewritten under reservation")
		}
		if drift == "binary" {
			if err := os.WriteFile(filepath.Join(s.root, host.RecoveryBinaryFile), binary, 0755); err != nil {
				t.Fatal(err)
			}
		}
	}
	s.hostFence.unhealthy = false
	if err := reconcile(); err != nil {
		t.Fatal("controller cannot confirm through real HostBootstrap/mTLS", err)
	}
	if s.confirms != 1 || s.hostActivations != 1 || s.reservationBootstraps == 0 {
		t.Fatal("unexpected confirmations/host activation/reservation verification")
	}
	if err := artifactstate.CheckPending(filepath.Join(s.root, artifactstate.DefaultDir)); err != nil {
		t.Fatal("confirmed reservation not released", err)
	}
	observed, err := s.engine.Observe(b)
	if err != nil || observed.Phase != "Confirmed" {
		t.Fatal("not confirmed", err)
	}
	unchangedHost()
}
