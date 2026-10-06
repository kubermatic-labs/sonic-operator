// SPDX-License-Identifier: Apache-2.0
package host

import (
	"os"
	"path/filepath"
)

const RecoveryConfigFile = "/etc/sonic/sonic-operator-host-recovery.json"

type RecoveryConfig struct {
	JournalDir         string `json:"journalDir"`
	RedisAddress       string `json:"redisAddress"`
	VLANJournalDir     string `json:"vlanJournalDir,omitempty"`
	BreakoutJournalDir string `json:"breakoutJournalDir,omitempty"`
	NetworkJournalDir  string `json:"networkJournalDir,omitempty"`
}

func ReadRecoveryConfig() (RecoveryConfig, error) {
	var cfg RecoveryConfig
	info, err := os.Lstat(RecoveryConfigFile)
	if err != nil || secureFile(info, false) != nil {
		return cfg, ErrStorage
	}
	data, err := os.ReadFile(RecoveryConfigFile)
	if err != nil || StrictDecode(data, &cfg) != nil {
		return cfg, ErrStorage
	}
	if !filepath.IsAbs(cfg.JournalDir) || cfg.RedisAddress == "" {
		return cfg, ErrStorage
	}
	for _, p := range []string{cfg.VLANJournalDir, cfg.BreakoutJournalDir, cfg.NetworkJournalDir} {
		if p != "" && !filepath.IsAbs(p) {
			return cfg, ErrStorage
		}
	}
	return cfg, nil
}
