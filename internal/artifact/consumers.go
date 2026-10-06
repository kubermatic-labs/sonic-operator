// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"bytes"
	"context"
	"errors"
	"fmt"
)

var ErrConsumerMismatch = errors.New("native consumer fingerprint mismatch")

var platformConsumers = map[string]RuntimeFile{
	"pmon-interpreter":         {Container: "pmon", Path: "/usr/bin/python3.11"},
	"pmon-xcvrd":               {Container: "pmon", Path: "/usr/local/bin/xcvrd"},
	"pmon-psud":                {Container: "pmon", Path: "/usr/local/bin/psud"},
	"pmon-syseepromd":          {Container: "pmon", Path: "/usr/local/bin/syseepromd"},
	"pmon-stormond":            {Container: "pmon", Path: "/usr/local/bin/stormond"},
	"pmon-launcher":            {Path: "/usr/bin/pmon.sh"},
	"host-platform-installer":  {Path: "/usr/local/bin/z9100_platform.sh"},
	"pmon-unit":                {Path: "/usr/lib/systemd/system/pmon.service"},
	"syncd-unit":               {Path: "/usr/lib/systemd/system/syncd.service"},
	"swss-unit":                {Path: "/usr/lib/systemd/system/swss.service"},
	"rc-local":                 {Path: "/etc/rc.local"},
	"pmon-init":                {Container: "pmon", Path: "/usr/bin/docker_init.sh"},
	"pmon-supervisor-template": {Container: "pmon", Path: "/usr/share/sonic/templates/docker-pmon.supervisord.conf.j2"},
	"sai-generator":            {Container: "syncd", Path: "/usr/bin/start.sh"},
	"syncd-init":               {Container: "syncd", Path: "/usr/bin/syncd_init_common.sh"},
	"syncd-launcher":           {Container: "syncd", Path: "/usr/bin/syncd_start.sh"},
}

func (n *Native) consumerBaseline(ctx context.Context) error {
	if len(n.Engine.Policy.ConsumerSHA256) != len(platformConsumers) {
		return fmt.Errorf("native consumer qualification incomplete")
	}
	for name, consumer := range platformConsumers {
		expected := n.Engine.Policy.ConsumerSHA256[name]
		if !shaPattern.MatchString(expected) {
			return fmt.Errorf("invalid native consumer fingerprint")
		}
		command := "/usr/bin/sha256sum"
		args := []string{"--", consumer.Path}
		if consumer.Container != "" {
			command = "/usr/bin/docker"
			args = []string{"exec", consumer.Container, "sha256sum", "--", consumer.Path}
		}
		raw, err := n.command(ctx, command, args...)
		fields := bytes.Fields(raw)
		if err != nil || len(fields) < 1 || string(fields[0]) != expected {
			return ErrConsumerMismatch
		}
	}
	return nil
}
