// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/ironcore-dev/sonic-operator/internal/agent/artifactstate"
	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
)

func (n *Native) WithHostFence(ctx context.Context, action func() error) error {
	return n.withHostFence(ctx, false, action)
}
func (n *Native) WithAgentRecoveryFence(ctx context.Context, owner, token, manifest string, action func() error) error {
	r, err := artifactstate.Read(n.Engine.reservationDir())
	if err != nil || r == nil || r.Phase == "Idle" || r.Owner != owner || r.Token != token || r.Manifest != manifest {
		return fmt.Errorf("missing agent dependency reservation")
	}
	return n.withHostFence(ctx, true, action)
}
func (n *Native) withHostFence(ctx context.Context, dependency bool, action func() error) error {
	e := n.Engine
	raw, mode, err := e.read(strings.TrimPrefix(host.RecoveryConfigFile, "/"))
	if errors.Is(err, fs.ErrNotExist) {
		// Before bootstrap there may be no host installation. Once any qualified
		// host store/profile exists, loss of configuration must remain fenced.
		for _, p := range []string{"host/sonic-operator-host-journal", "var/lib/sonic-operator/host", "etc/sonic/sonic-operator-host-profile.json", "host/sonic-operator-host-bootstrap"} {
			if _, err := e.root.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("host recovery configuration missing after installation")
			}
		}
		return action()
	}
	if err != nil || mode != 0600 {
		return fmt.Errorf("host recovery configuration cannot be safely inspected")
	}
	var cfg host.RecoveryConfig
	if host.StrictDecode(raw, &cfg) != nil || cfg.RedisAddress == "" || (cfg.JournalDir != "/host/sonic-operator-host-journal" && cfg.JournalDir != "/var/lib/sonic-operator/host") {
		return fmt.Errorf("unqualified host recovery store")
	}
	if err := host.ValidateJournalPaths(cfg.JournalDir, cfg.VLANJournalDir, cfg.BreakoutJournalDir, cfg.NetworkJournalDir, "/"+e.state); err != nil {
		return err
	}
	dir := strings.TrimPrefix(cfg.JournalDir, "/")
	if err := e.safe(dir + "/lock"); err != nil {
		return err
	}
	local := filepath.Join(e.root.Name(), dir)
	if dependency {
		return host.WithArtifactAgentRecoveryExclusion(ctx, local, action)
	}
	return host.WithArtifactExclusion(ctx, local, action)
}
