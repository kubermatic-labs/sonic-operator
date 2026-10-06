// SPDX-License-Identifier: Apache-2.0
package sonic

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/ironcore-dev/sonic-operator/internal/agent/artifactstate"
	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
)

// ArtifactWriterFence reuses the existing journal parsers, checksums and lock
// order. Native platform activation cannot overlap typed network writers or
// bypass their pending recovery. It does not open Redis or mutate CONFIG_DB.
type ArtifactWriterFence struct{ agent *SonicAgent }

func (f *ArtifactWriterFence) VerifyHostBootstrap(ctx context.Context) error {
	n := &host.Native{}
	if err := n.WatchdogReady(ctx); err != nil {
		return err
	}
	profile, err := n.QualifyInstalledProfile(ctx)
	if err != nil || len(profile.LegacyMACHooks) == 0 {
		return err
	}
	return withHostBootstrapBackend(ctx, host.FleetRecoveryConfig().RedisAddress, func(backend *SonicAgent) error {
		return backend.NewHostNative().QualifyImportedAdoption(ctx, profile)
	})
}

func (f *ArtifactWriterFence) QualifyHostBootstrap(ctx context.Context, profile []byte, repair bool) error {
	return withHostBootstrapBackend(ctx, host.FleetRecoveryConfig().RedisAddress, func(backend *SonicAgent) error {
		return backend.NewHostNative().QualifyBootstrapProfile(ctx, profile, repair)
	})
}

func withHostBootstrapBackend(ctx context.Context, address string, qualify func(*SonicAgent) error) error {
	backend, err := NewSonicRedisAgentContext(ctx, address)
	if err != nil {
		return err
	}
	defer func() {
		for _, client := range backend.clientPool {
			_ = client.Close()
		}
	}()
	return qualify(backend)
}

func NewArtifactWriterFence() (*ArtifactWriterFence, error) {
	if _, err := os.Lstat(host.RecoveryBootstrapDir); err == nil {
		// The immutable Fleet installer owns this namespace. Its readiness may
		// be false while files are repaired; supervisor health must still run.
		// Native.WithHostFence continues to reject invalid/missing host config
		// before any ordinary or recovery publication.
		return NewFleetArtifactWriterFence()
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	cfg := host.RecoveryConfig{VLANJournalDir: "/host/sonic-operator-vlan-journal", BreakoutJournalDir: "/host/sonic-operator-breakout-journal", NetworkJournalDir: "/host/sonic-operator-network-journal"}
	if _, err := os.Lstat(host.RecoveryConfigFile); err == nil {
		installed, err := host.ReadRecoveryConfig()
		if err != nil {
			return nil, err
		}
		cfg.JournalDir = installed.JournalDir
		if installed.VLANJournalDir != "" {
			cfg.VLANJournalDir = installed.VLANJournalDir
		}
		if installed.BreakoutJournalDir != "" {
			cfg.BreakoutJournalDir = installed.BreakoutJournalDir
		}
		if installed.NetworkJournalDir != "" {
			cfg.NetworkJournalDir = installed.NetworkJournalDir
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := host.ValidateJournalPaths(cfg.JournalDir, cfg.VLANJournalDir, cfg.BreakoutJournalDir, cfg.NetworkJournalDir, artifactstate.DefaultDir); err != nil {
		return nil, err
	}
	return newArtifactWriterFence(cfg)
}

// Fleet host repair must remain possible when its owned configuration is
// missing or drifted. This constructor selects only the immutable Fleet paths;
// EnsureHostBootstrap still rejects foreign ownership and legacy migrations.
func NewFleetArtifactWriterFence() (*ArtifactWriterFence, error) {
	return newArtifactWriterFence(host.FleetRecoveryConfig())
}

func newArtifactWriterFence(cfg host.RecoveryConfig) (*ArtifactWriterFence, error) {
	m := &SonicAgent{}
	if err := m.ConfigureVLANAuthorityJournal(cfg.VLANJournalDir); err != nil {
		return nil, err
	}
	if err := m.ConfigureBreakoutJournal(cfg.BreakoutJournalDir); err != nil {
		return nil, err
	}
	if err := m.ConfigureNetworkJournal(cfg.NetworkJournalDir); err != nil {
		return nil, err
	}
	return &ArtifactWriterFence{agent: m}, nil
}
func (f *ArtifactWriterFence) WithMutation(ctx context.Context, action func() error) error {
	return f.withLocks(ctx, false, action)
}

// WithAgentRecovery holds and validates foreign journals, but permits a reserved
// supervisor to restore only its old agent dependency. The caller's restricted
// replay must not touch CONFIG_DB/platform inputs or the foreign journals.
func (f *ArtifactWriterFence) WithAgentRecovery(ctx context.Context, owner, token, manifest string, action func() error) error {
	r, err := artifactstate.Read(f.agent.artifactStateDir)
	if err != nil || r == nil || r.Phase == "Idle" || r.Owner != owner || r.Token != token || r.Manifest != manifest {
		return fmt.Errorf("missing agent recovery reservation")
	}
	return f.withLocks(ctx, true, func() error {
		r, err := artifactstate.Read(f.agent.artifactStateDir)
		if err != nil || r == nil || r.Phase == "Idle" || r.Owner != owner || r.Token != token || r.Manifest != manifest {
			return fmt.Errorf("agent recovery reservation changed")
		}
		return action()
	})
}
func (f *ArtifactWriterFence) withLocks(ctx context.Context, dependency bool, action func() error) error {
	m := f.agent
	for !m.configMutex.TryLock() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
	defer m.configMutex.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	vlan, err := m.lockVLANAuthorityJournal(ctx)
	if err != nil {
		return err
	}
	defer vlan.close()
	if err := vlan.checkPendingMode(0, dependency); err != nil {
		return err
	}
	breakout, err := m.lockBreakoutJournal(ctx)
	if err != nil {
		return err
	}
	defer breakout.close()
	br, err := loadBreakoutRecord(breakout)
	if err != nil {
		return err
	}
	if br != nil && br.Pending && !dependency {
		return fmt.Errorf("%w: breakout", artifactstate.ErrForeignPending)
	}
	network, err := m.lockNetworkJournal(ctx)
	if err != nil {
		return err
	}
	defer network.close()
	records, err := loadNetworkJournal(network)
	if err != nil {
		return err
	}
	for _, record := range records.Records {
		if record.Pending != nil && !dependency {
			return fmt.Errorf("%w: network", artifactstate.ErrForeignPending)
		}
	}
	return action()
}
