// SPDX-License-Identifier: Apache-2.0
package host

import (
	"path/filepath"
	"strings"

	"github.com/ironcore-dev/sonic-operator/internal/agent/artifactstate"
)

// RecoveryBackend is configured by the same assembly used by the standalone
// executable. RecoveryConfig is the sole source of journal locations.
type RecoveryBackend interface {
	ConfigureHostJournal(string) error
	ConfigureVLANAuthorityJournal(string) error
	ConfigureBreakoutJournal(string) error
	ConfigureNetworkJournal(string) error
	NewHostNative() *Native
}

func NewRecoveryEngine(cfg RecoveryConfig, backend RecoveryBackend) (*Engine, error) {
	n, err := NewRecoveryNative(cfg, backend)
	if err != nil {
		return nil, err
	}
	return NewEngine(cfg.JournalDir, n)
}

// NewRecoveryNative shares configuration with recovery, without creating runtime
// receipt directories. Local installation checks use this read-only assembly.
func NewRecoveryNative(cfg RecoveryConfig, backend RecoveryBackend) (*Native, error) {
	if backend == nil || cfg.JournalDir == "" {
		return nil, ErrStorage
	}
	if err := ValidateJournalPaths(cfg.JournalDir, cfg.VLANJournalDir, cfg.BreakoutJournalDir, cfg.NetworkJournalDir, artifactstate.DefaultDir); err != nil {
		return nil, err
	}
	// The dependency-recovery callback closes over the backend, not Engine.dir.
	// Bind the host journal there before constructing Native or the engine.
	if err := backend.ConfigureHostJournal(cfg.JournalDir); err != nil {
		return nil, err
	}
	if cfg.VLANJournalDir != "" {
		if err := backend.ConfigureVLANAuthorityJournal(cfg.VLANJournalDir); err != nil {
			return nil, err
		}
	}
	if cfg.BreakoutJournalDir != "" {
		if err := backend.ConfigureBreakoutJournal(cfg.BreakoutJournalDir); err != nil {
			return nil, err
		}
	}
	if cfg.NetworkJournalDir != "" {
		if err := backend.ConfigureNetworkJournal(cfg.NetworkJournalDir); err != nil {
			return nil, err
		}
	}
	n := backend.NewHostNative()
	n.journalDir = cfg.JournalDir
	return n, nil
}

// State roots may never own another journal, including through a nested path.
func ValidateJournalPaths(paths ...string) error {
	var seen []string
	for _, p := range paths {
		if p == "" {
			continue
		}
		clean := filepath.Clean(p)
		if !filepath.IsAbs(p) || clean == string(filepath.Separator) {
			return ErrStorage
		}
		for _, old := range seen {
			if clean == old || strings.HasPrefix(clean, old+string(filepath.Separator)) || strings.HasPrefix(old, clean+string(filepath.Separator)) {
				return ErrStorage
			}
		}
		seen = append(seen, clean)
	}
	return nil
}
