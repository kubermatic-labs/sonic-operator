// SPDX-License-Identifier: Apache-2.0
package host

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

type snmpContainer struct {
	ID    string `json:"Id"`
	Image string `json:"Image"`
	State struct {
		Running bool   `json:"Running"`
		Status  string `json:"Status"`
	} `json:"State"`
	Config struct {
		Entrypoint []string `json:"Entrypoint"`
		Cmd        []string `json:"Cmd"`
	} `json:"Config"`
}

func (n *Native) snmpContainer(ctx context.Context) (snmpContainer, error) {
	var c snmpContainer
	b, e := n.run(ctx, "docker", "inspect", "--format", "{{json .}}", "snmp")
	if e != nil || json.Unmarshal(b, &c) != nil {
		return c, ErrNative
	}
	id, e := hex.DecodeString(c.ID)
	image, e2 := hex.DecodeString(strings.TrimPrefix(c.Image, "sha256:"))
	if e != nil || e2 != nil || len(id) != 32 || len(image) != 32 || !strings.HasPrefix(c.Image, "sha256:") || !slices.Equal(c.Config.Entrypoint, []string{"/usr/bin/docker-snmp-init.sh"}) || len(c.Config.Cmd) != 0 {
		return c, ErrNative
	}
	if !c.State.Running && !slices.Contains([]string{"exited", "created"}, c.State.Status) {
		return c, ErrNative
	}
	return c, nil
}
func (n *Native) containerFile(ctx context.Context, path string) ([]byte, error) {
	c, e := n.snmpContainer(ctx)
	if e != nil {
		return nil, e
	}
	// docker cp reads the filesystem of an existing stopped container. No image
	// is pulled, no temporary container is created, and no daemon must be running.
	b, e := n.run(ctx, "docker", "cp", "-L", c.ID+":"+path, "-")
	if e != nil {
		return nil, e
	}
	r := tar.NewReader(bytes.NewReader(b))
	header, e := r.Next()
	if e != nil || header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > 4<<20 || filepath.Base(header.Name) != header.Name || header.Name == ".." {
		return nil, ErrNative
	}
	data, e := io.ReadAll(io.LimitReader(r, 4<<20+1))
	if e != nil || len(data) > 4<<20 {
		return nil, ErrNative
	}
	if _, e = r.Next(); e != io.EOF {
		return nil, ErrNative
	}
	latest, e := n.snmpContainer(ctx)
	if e != nil || latest.ID != c.ID || latest.Image != c.Image {
		return nil, ErrConflict
	}
	return data, nil
}
func (n *Native) renderStoppedSNMP(ctx context.Context, template string, input []byte) ([]byte, error) {
	if n.stateDir == "" || !slices.Contains([]string{snmpTemplate, "/usr/share/sonic/templates/supervisord.conf.j2"}, template) {
		return nil, ErrStorage
	}
	data, e := n.containerFile(ctx, template)
	if e != nil {
		return nil, e
	}
	p, e := n.profile(ctx, "System")
	if e != nil {
		return nil, e
	}
	digest := p.SNMPSHA256
	if template != snmpTemplate {
		digest = p.ConsumerSHA256["snmp-supervisor-template"]
	}
	if !hashMatches(data, digest) {
		return nil, ErrNative
	}
	f, e := os.CreateTemp(n.stateDir, ".snmp-template-")
	if e != nil {
		return nil, ErrStorage
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, e = f.Write(data); e != nil {
		_ = f.Close()
		return nil, ErrStorage
	}
	if e = f.Close(); e != nil {
		return nil, ErrStorage
	}
	run := n.Run
	if run == nil {
		run = boundedRun
	}
	out, e := run(ctx, []string{"sonic-cfggen", "-j", "/dev/stdin", "-t", f.Name()}, input)
	if e != nil {
		return nil, ErrNative
	}
	return out, nil
}
