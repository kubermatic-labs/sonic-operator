// SPDX-License-Identifier: Apache-2.0
package host

import "path/filepath"

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
	if backend == nil || cfg.JournalDir == "" {
		return nil, ErrStorage
	}
	seen := map[string]bool{}
	for _, path := range []string{cfg.JournalDir, cfg.VLANJournalDir, cfg.BreakoutJournalDir, cfg.NetworkJournalDir} {
		if path == "" {
			continue
		}
		clean := filepath.Clean(path)
		if !filepath.IsAbs(path) || seen[clean] {
			return nil, ErrStorage
		}
		seen[clean] = true
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
	return NewEngine(cfg.JournalDir, backend.NewHostNative())
}
