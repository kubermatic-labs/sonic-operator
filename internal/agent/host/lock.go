// SPDX-License-Identifier: Apache-2.0
package host

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"syscall"
	"time"
)

func syncDirectory(f *os.File, syncFn func(*os.File) error) error {
	if syncFn != nil {
		return syncFn(f)
	}
	return f.Sync()
}
func lockMutex(ctx context.Context, mu *sync.Mutex) error {
	for !mu.TryLock() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
	return nil
}
func openStore(dir string) (*os.Root, error) {
	info, e := os.Lstat(dir)
	if e != nil || secureFile(info, true) != nil {
		return nil, ErrStorage
	}
	r, e := os.OpenRoot(dir)
	if e != nil {
		return nil, ErrStorage
	}
	return r, nil
}
func readRecord(root *os.Root) (*record, error) {
	r, _, release, err := readRecordSnapshot(root)
	if release != nil {
		release()
	}
	return r, err
}

// The identity belongs to the same open file whose authenticated bytes were
// decoded. A separate path stat could accidentally identify a later publication.
func readRecordSnapshot(root *os.Root) (*record, os.FileInfo, func(), error) {
	r := &record{}
	f, e := root.OpenFile("host.json", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(e, os.ErrNotExist) {
		return r, nil, func() {}, nil
	}
	if e != nil {
		return nil, nil, nil, ErrStorage
	}
	release := func() { _ = f.Close() }
	info, e := f.Stat()
	if e != nil || secureFile(info, false) != nil {
		release()
		return nil, nil, nil, ErrStorage
	}
	b, e := io.ReadAll(io.LimitReader(f, 64<<10+1))
	if e != nil || StrictDecode(b, r) != nil {
		release()
		return nil, nil, nil, ErrStorage
	}
	latest, e := f.Stat()
	if e != nil || !sameRecordIdentity(info, latest) {
		release()
		return nil, nil, nil, ErrConflict
	}
	return r, info, release, nil
}

func sameRecordIdentity(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime()) && a.Mode() == b.Mode()
}
func lockRecord(ctx context.Context, dir string, syncFn func(*os.File) error) (*record, func(), error) {
	root, e := openStore(dir)
	if e != nil {
		return nil, nil, e
	}
	f, e := root.OpenFile("lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		_ = root.Close()
		return nil, nil, ErrStorage
	}
	unlock := func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close(); _ = root.Close() }
	info, e := f.Stat()
	if e != nil || secureFile(info, false) != nil {
		unlock()
		return nil, nil, ErrStorage
	}
	for {
		if e = ctx.Err(); e != nil {
			unlock()
			return nil, nil, e
		}
		e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if e == nil {
			break
		}
		if !errors.Is(e, syscall.EWOULDBLOCK) && !errors.Is(e, syscall.EAGAIN) {
			unlock()
			return nil, nil, ErrStorage
		}
		select {
		case <-ctx.Done():
			unlock()
			return nil, nil, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
	d, e := root.Open(".")
	if e != nil {
		unlock()
		return nil, nil, ErrStorage
	}
	e = syncDirectory(d, syncFn)
	_ = d.Close()
	if e != nil {
		unlock()
		return nil, nil, ErrStorage
	}
	r, e := readRecord(root)
	if e != nil {
		unlock()
		return nil, nil, e
	}
	return r, unlock, nil
}
