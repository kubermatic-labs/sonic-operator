// SPDX-License-Identifier: Apache-2.0
package host

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"path"
	"strings"
)

const snmpPersistentDir = "/var/lib/snmp"

// Net-SNMP stores every loaded USM user with its localized keys in
// /var/lib/snmp/snmpd.conf at startup and shutdown, and reads that file after
// /etc/snmp/snmpd.conf. A persisted user therefore overrides a rotated
// passphrase and resurrects a removed user on the next start. Activation
// removes persisted users while snmpd is stopped; the daemon re-persists the
// declared users from the rendered configuration when it starts.
type snmpPersistent struct {
	header *tar.Header
	data   []byte
}

func (p snmpPersistent) hasUsers() bool {
	return p.header != nil && !bytes.Equal(scrubUSMUsers(p.data), p.data)
}

func scrubUSMUsers(data []byte) []byte {
	var out bytes.Buffer
	for _, line := range bytes.SplitAfter(data, []byte("\n")) {
		if fields := bytes.Fields(line); len(fields) > 0 && strings.EqualFold(string(fields[0]), "usmUser") {
			continue
		}
		out.Write(line)
	}
	return out.Bytes()
}

// snmpPersistentState reads the persistent directory through a bounded docker
// cp archive, which works for running and stopped containers alike. Backup or
// local persistent files are also read by Net-SNMP and stay blocked.
func (n *Native) snmpPersistentState(ctx context.Context, c snmpContainer) (snmpPersistent, error) {
	var p snmpPersistent
	b, e := n.run(ctx, "docker", "cp", c.ID+":"+snmpPersistentDir, "-")
	if e != nil {
		return p, e
	}
	r := tar.NewReader(bytes.NewReader(b))
	for {
		header, e := r.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return p, ErrNative
		}
		name := path.Clean(header.Name)
		if !strings.HasPrefix(name, "snmp/snmpd.") || !strings.HasSuffix(name, ".conf") {
			continue
		}
		if name != "snmp/snmpd.conf" || header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > 4<<20 {
			return p, ErrNative
		}
		data, e := io.ReadAll(io.LimitReader(r, 4<<20+1))
		if e != nil || int64(len(data)) != header.Size {
			return p, ErrNative
		}
		p.header, p.data = header, data
	}
	latest, e := n.snmpContainer(ctx)
	if e != nil || latest.ID != c.ID || latest.Image != c.Image {
		return p, ErrConflict
	}
	return p, nil
}

// scrubSNMPPersistent rewrites the persistent file of a stopped container
// without its usmUser records, preserving ownership, mode and all other state
// (engine ID, boots, serial numbers).
func (n *Native) scrubSNMPPersistent(ctx context.Context, c snmpContainer) error {
	latest, e := n.snmpContainer(ctx)
	if e != nil || latest.State.Running || latest.ID != c.ID || latest.Image != c.Image {
		return ErrConflict
	}
	p, e := n.snmpPersistentState(ctx, c)
	if e != nil || !p.hasUsers() {
		return e
	}
	data := scrubUSMUsers(p.data)
	var archive bytes.Buffer
	w := tar.NewWriter(&archive)
	if w.WriteHeader(&tar.Header{Name: "snmpd.conf", Typeflag: tar.TypeReg, Mode: p.header.Mode & 0o777, Uid: p.header.Uid, Gid: p.header.Gid, Uname: p.header.Uname, Gname: p.header.Gname, ModTime: p.header.ModTime, Size: int64(len(data))}) != nil {
		return ErrNative
	}
	if _, e = w.Write(data); e != nil || w.Close() != nil {
		return ErrNative
	}
	run := n.Run
	if run == nil {
		run = boundedRun
	}
	if _, e = run(ctx, []string{"docker", "cp", "-a", "-", c.ID + ":" + snmpPersistentDir}, archive.Bytes()); e != nil {
		return ErrNative
	}
	verified, e := n.snmpPersistentState(ctx, c)
	if e != nil || verified.header == nil || !bytes.Equal(verified.data, data) || verified.header.Uid != p.header.Uid || verified.header.Gid != p.header.Gid || verified.header.Mode&0o777 != p.header.Mode&0o777 {
		return ErrNative
	}
	return nil
}
