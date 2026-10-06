// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"reflect"
	"strings"
	"syscall"

	"github.com/ironcore-dev/sonic-operator/internal/agent/host"
)

type hostScratchSpec struct {
	hash  string
	mode  fs.FileMode
	limit int
}

// The one install-<identity> directory is a durable binding to the complete
// immutable owner/target/suite, established before any replacement scratch.
// Every scratch name is derived from that binding and a finite destination.
// Neither an arbitrary filename nor a caller-provided path grants reclamation.
type hostInstallWriter struct {
	e       *Engine
	binding host.InstallationReceipt
	id, dir string
	files   map[string]hostScratchSpec
}

func newHostInstallWriter(e *Engine, h *HostRecoveryBootstrap, binding host.InstallationReceipt) *hostInstallWriter {
	binding.Phase = ""
	raw, _ := json.Marshal(binding)
	id := Digest(raw)
	w := &hostInstallWriter{e: e, binding: binding, id: id, dir: e.state + "/install-" + id, files: map[string]hostScratchSpec{}}
	for _, f := range h.files() {
		w.files[strings.TrimPrefix(f.path, "/")] = hostScratchSpec{hash: Digest(f.data), mode: f.mode, limit: len(f.data)}
	}
	_ = h.payloads(func(hash string, p *[]byte, _ uint64) error {
		w.files[e.state+"/content/"+hash] = hostScratchSpec{hash: hash, mode: 0600, limit: len(*p)}
		return nil
	})
	w.files[e.state+"/owner.json"] = hostScratchSpec{mode: 0600, limit: MaxMetadataBytes}
	return w
}
func (w *hostInstallWriter) scratch(dest string) string {
	return path.Join(path.Dir(dest), ".host-install-"+w.id+"-"+Digest([]byte(dest)))
}

func (w *hostInstallWriter) bind() error {
	e := w.e
	if err := e.safe(w.dir); err != nil {
		return err
	}
	info, err := e.root.Lstat(w.dir)
	if errors.Is(err, fs.ErrNotExist) {
		// Reject pre-existing names before assigning this attempt any authority.
		for dest := range w.files {
			if _, err := e.root.Lstat(w.scratch(dest)); !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("unowned host replacement scratch")
			}
		}
		if err = e.mkdirDurable(w.dir); err != nil {
			return err
		}
		info, err = e.root.Lstat(w.dir)
	}
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return fmt.Errorf("unsafe host install binding")
	}
	dir, err := e.root.Open(w.dir)
	if err != nil {
		return err
	}
	entries, err := dir.ReadDir(-1)
	_ = dir.Close()
	if err != nil || len(entries) != 0 {
		return fmt.Errorf("unknown host install binding contents")
	}
	return e.syncDir(e.state)
}

func (w *hostInstallWriter) validateScratch(dest string) (bool, error) {
	tmp := w.scratch(dest)
	spec, ok := w.files[dest]
	if !ok {
		return false, fmt.Errorf("unqualified host scratch target")
	}
	if err := w.e.safe(tmp); err != nil {
		return false, err
	}
	info, err := w.e.root.Lstat(tmp)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil || !info.Mode().IsRegular() || (info.Mode().Perm() != 0600 && info.Mode().Perm() != spec.mode) || info.Size() > int64(spec.limit) {
		return false, fmt.Errorf("untrusted host install scratch")
	}
	return true, nil
}

// Called only under the install lock AND full publication exclusion, after the
// exact binding has been validated. Protected content and foreign nonce scratch
// are never candidates. Reclaim before budget checks so old partial allocation
// cannot consume the reserve required to resume its own replacement.
func (w *hostInstallWriter) reclaim() error {
	for dest := range w.files {
		exists, err := w.validateScratch(dest)
		if err != nil {
			return err
		}
		if exists {
			if err := w.e.root.Remove(w.scratch(dest)); err != nil {
				return err
			}
			if err := w.e.syncDir(path.Dir(dest)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w *hostInstallWriter) write(dest string, data []byte, mode fs.FileMode) error {
	e := w.e
	if e.requestContext != nil {
		if err := e.requestContext.Err(); err != nil {
			return err
		}
	}
	spec, ok := w.files[dest]
	if !ok || mode != spec.mode || len(data) > spec.limit {
		return fmt.Errorf("host replacement outside bound attempt")
	}
	if spec.hash != "" && Digest(data) != spec.hash {
		return fmt.Errorf("host replacement identity differs")
	}
	if spec.hash == "" {
		var r host.InstallationReceipt
		if Decode(data, &r) != nil || (r.Phase != "Prepared" && r.Phase != "Installing" && r.Phase != "Verifying" && r.Phase != "Confirmed") {
			return fmt.Errorf("invalid host receipt replacement")
		}
		r.Phase = ""
		if !reflect.DeepEqual(r, w.binding) {
			return fmt.Errorf("host receipt outside bound attempt")
		}
	}
	if err := e.safe(dest); err != nil {
		return err
	}
	old, oldMode, err := e.read(dest)
	if err == nil && oldMode == mode && Digest(old) == Digest(data) {
		return w.syncMatchingDestination(dest, data, mode)
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := e.mkdirDurable(path.Dir(dest)); err != nil {
		return err
	}
	tmp := w.scratch(dest)
	// bind/reclaim are mandatory before this call; O_EXCL prevents replacement
	// of any file introduced after validation, including by a foreign writer.
	f, err := e.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	checkpoint := func(phase string) error {
		if e.atomicCheckpoint != nil {
			return e.atomicCheckpoint(dest, phase)
		}
		return nil
	}
	if err = checkpoint("temp-created"); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = checkpoint("temp-written"); err != nil {
		return err
	}
	if err = f.Chmod(mode); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = checkpoint("temp-synced"); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if e.requestContext != nil {
		if err := e.requestContext.Err(); err != nil {
			return err
		}
	}
	if err = e.root.Rename(tmp, dest); err != nil {
		return err
	}
	if err = checkpoint("renamed"); err != nil {
		return err
	}
	return w.syncMatchingDestination(dest, data, mode)
}

// A visible matching rename is not a completion receipt. Keep descriptors for
// both the file and its parent through their durability barriers, then validate
// that the same trusted objects still occupy these paths. This also completes a
// rename whose directory sync was interrupted in a previous process, without
// replacing the inode or touching any unrelated entry.
func (w *hostInstallWriter) syncMatchingDestination(dest string, data []byte, mode fs.FileMode) error {
	e := w.e
	if err := e.safe(dest); err != nil {
		return err
	}
	directory, err := e.root.Open(path.Dir(dest))
	if err != nil {
		return err
	}
	defer directory.Close()
	dirInfo, err := directory.Stat()
	if err != nil {
		return err
	}
	dirStat, ok := dirInfo.Sys().(*syscall.Stat_t)
	if !ok || dirStat.Uid != uint32(os.Geteuid()) || !dirInfo.IsDir() || dirInfo.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("host destination directory unavailable")
	}
	f, err := e.root.Open(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !trustedHostDestination(info, mode) {
		return fmt.Errorf("untrusted host destination")
	}
	actual, err := io.ReadAll(io.LimitReader(f, int64(len(data))+1))
	if err != nil || len(actual) != len(data) || Digest(actual) != Digest(data) {
		return fmt.Errorf("host destination changed before durability")
	}
	if e.requestContext != nil {
		if err := e.requestContext.Err(); err != nil {
			return err
		}
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if e.atomicCheckpoint != nil {
		if err = e.atomicCheckpoint(dest, "destination-sync"); err != nil {
			return err
		}
	}
	if err = directory.Sync(); err != nil {
		return err
	}
	if err = e.safe(dest); err != nil {
		return err
	}
	current, err := e.root.Lstat(dest)
	if err != nil || !os.SameFile(info, current) || !trustedHostDestination(current, mode) || info.Size() != current.Size() || !info.ModTime().Equal(current.ModTime()) {
		return fmt.Errorf("host destination identity changed during durability")
	}
	currentDir, err := e.root.Lstat(path.Dir(dest))
	if err != nil || !os.SameFile(dirInfo, currentDir) {
		return fmt.Errorf("host destination directory identity changed during durability")
	}
	if e.atomicCheckpoint != nil {
		return e.atomicCheckpoint(dest, "destination-synced")
	}
	return nil
}

func trustedHostDestination(info os.FileInfo, mode fs.FileMode) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && info.Mode().IsRegular() && info.Mode().Perm() == mode
}

func (w *hostInstallWriter) space(h *HostRecoveryBootstrap) error {
	// Sum the allocations still needed, rather than charging already-protected
	// payloads again on every retry. One receipt replacement is metadata-bounded.
	needed := uint64(MaxMetadataBytes)
	check := func(dest string, data []byte, mode fs.FileMode) error {
		old, oldMode, err := w.e.read(dest)
		if err == nil && oldMode == mode && Digest(old) == Digest(data) {
			return nil
		}
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		needed += uint64(len(data))
		return nil
	}
	if err := h.payloads(func(hash string, p *[]byte, _ uint64) error { return check(w.e.state+"/content/"+hash, *p, 0600) }); err != nil {
		return err
	}
	for _, f := range h.files() {
		if err := check(strings.TrimPrefix(f.path, "/"), f.data, f.mode); err != nil {
			return err
		}
	}
	for dest := range w.files {
		free, err := w.e.available(path.Dir(dest))
		if err != nil || free < needed+RecoveryReserveBytes {
			return fmt.Errorf("host installation lacks recovery reserve")
		}
	}
	return nil
}
