// SPDX-License-Identifier: Apache-2.0
package host

import (
	"context"
	"io"
	"os"
	"syscall"
)

const savedConfigLimit = 4 << 20

// VerifySaved retains the earlier native runtime/gateway/rendered-file proof,
// but never reuses CONFIG_DB persistence across an intervening whole-DB save.
// Load is the typed host database reader; this path must not render or invoke
// native processes. The caller holds all ordered writer and host exclusions.
func (n *Native) VerifySaved(ctx context.Context, q Request) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if ValidateRequest(q) != nil {
		return ErrInvalid
	}
	saved, err := n.saved()
	if err != nil {
		return ErrNative
	}
	db, err := n.Load(ctx)
	if err != nil {
		return ErrNative
	}
	var after Database
	var tables []string
	if q.Kind == "Management" {
		after, err = managementDatabase(db, *q.Management)
		tables = []string{"MGMT_INTERFACE"}
	} else {
		after, err = systemDatabase(db, *q.System)
		tables = systemTables(*q.System)
	}
	if err != nil || !scopedEqual(db, after, tables...) || !scopedEqual(saved, after, tables...) {
		return ErrNative
	}
	return ctx.Err()
}

// A saved file may be rewritten in-place by native SaveConfig. Bound the actual
// read, refuse symlinks/nonregular/untrusted files, and validate the opened file
// and its current path after reading. Each admission opens the current path;
// neither an old descriptor nor an agent-local dirty flag is persistence proof.
func readSavedConfigFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrNative
	}
	defer func() { _ = f.Close() }()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() > savedConfigLimit || before.Mode().Perm()&0022 != 0 {
		return nil, ErrNative
	}
	owner, ok := before.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return nil, ErrNative
	}
	data, err := io.ReadAll(io.LimitReader(f, savedConfigLimit+1))
	if err != nil || len(data) > savedConfigLimit {
		return nil, ErrNative
	}
	after, err := f.Stat()
	if err != nil || !sameRecordIdentity(before, after) {
		return nil, ErrNative
	}
	current, err := os.Lstat(path)
	if err != nil || !sameRecordIdentity(after, current) {
		return nil, ErrNative
	}
	return data, nil
}
