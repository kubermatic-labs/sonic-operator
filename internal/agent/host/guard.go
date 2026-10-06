// SPDX-License-Identifier: Apache-2.0
package host

import (
	"errors"
	"os"
)

// CheckPending does not acquire a reverse host lock. Callers hold their complete
// cooperating-writer exclusion. Completion can be published by Confirm while
// that exclusion is held, so accepting it requires a post-read directory sync
// and an unchanged directory-entry identity. No reverse host lock is acquired.
func CheckPending(dir string) error { return checkPending(dir, nil) }
func checkPending(dir string, sync func(*os.File) error) error {
	if dir == "" {
		return nil
	}
	root, err := openStore(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	d, err := root.Open(".")
	if err != nil {
		return ErrStorage
	}
	defer d.Close()
	if syncDirectory(d, sync) != nil {
		return ErrStorage
	}
	r, identity, release, err := readRecordSnapshot(root)
	if err != nil {
		return err
	}
	// Keep the inode open through validation so an unlinked record's inode
	// cannot be recycled and mistaken for a subsequent publication.
	defer release()
	if r.Pending != nil {
		return ErrConflict
	}
	// This sync covers the actual record/absence read, including a confirmation
	// renamed after the first sync. A later publication invalidates acceptance.
	if syncDirectory(d, sync) != nil {
		return ErrStorage
	}
	latest, err := root.Lstat("host.json")
	if identity == nil && errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return ErrConflict
	}
	if secureFile(latest, false) != nil {
		return ErrStorage
	}
	if !sameRecordIdentity(identity, latest) {
		return ErrConflict
	}
	return nil
}
