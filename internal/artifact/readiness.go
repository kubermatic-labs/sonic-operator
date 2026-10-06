// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"context"
	"errors"
	"os/exec"
	"strings"
)

func (n *Native) containerRunning(ctx context.Context, name string) bool {
	raw, err := n.command(ctx, "/usr/bin/docker", "inspect", name, "--format", "{{.State.Running}}")
	return err == nil && strings.TrimSpace(string(raw)) == "true"
}
func (n *Native) initFinished(ctx context.Context, container, job string) bool {
	args := []string{"exec", container, "supervisorctl", "status", job}
	var raw []byte
	var err error
	if n.Run != nil {
		raw, err = n.Run(ctx, "/usr/bin/docker", args...)
	} else {
		raw, err = exec.CommandContext(ctx, "/usr/bin/docker", args...).Output()
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 3 {
			err = nil
		}
	}
	fields := strings.Fields(string(raw))
	return err == nil && len(fields) >= 2 && fields[0] == job && fields[1] == "EXITED"
}
func (n *Native) consumersReady(ctx context.Context, recovery bool) error {
	raw, err := n.command(ctx, "/usr/bin/systemctl", "show", "--property=SubState", "--value", "platform-modules-z9100.service")
	state := strings.TrimSpace(string(raw))
	if err != nil || (state != "exited" && !(recovery && state == "failed")) {
		return ErrActivationPending
	}
	if !n.containerRunning(ctx, "pmon") {
		return ErrActivationPending
	}
	if !n.initFinished(ctx, "pmon", "dependent-startup") {
		return ErrActivationPending
	}
	if !recovery && (!n.containerRunning(ctx, "syncd") || !n.initFinished(ctx, "syncd", "start")) {
		return ErrActivationPending
	}
	return nil
}
