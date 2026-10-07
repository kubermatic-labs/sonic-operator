// SPDX-License-Identifier: Apache-2.0
package host

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type Snapshot struct {
	Management Management `json:"management"`
	ActiveMAC  string     `json:"activeMAC"`
}

// RecoveryScope remains durable until restoration is independently verified.
// Candidate is removal authority even after CONFIG_DB has already reverted.
type RecoveryScope struct {
	// Nil preserves historical MAC restoration authority. False owns addresses only.
	MACOwned  *bool
	Before    Snapshot
	Candidate Management
	// ObservedActiveMAC is the actually observed pre-dispatch state. Before's
	// active MAC may instead be the declared repair target for runtime drift.
	ObservedActiveMAC string
}
type claim struct {
	Owner    string `json:"owner"`
	Target   string `json:"target"`
	Revision string `json:"revision"`
}
type transaction struct {
	MACOwned          *bool      `json:"macOwned,omitempty"`
	ID                string     `json:"id"`
	Claim             claim      `json:"claim"`
	Before            Snapshot   `json:"before"`
	Candidate         Management `json:"candidate"`
	ObservedActiveMAC string     `json:"observedActiveMAC,omitempty"`
	Created           time.Time  `json:"created"`
	Deadline          time.Time  `json:"deadline"`
	BootID            string     `json:"bootID,omitempty"`
	DeadlineUptime    float64    `json:"deadlineUptime,omitempty"`
	Connection        string     `json:"connection"`
	RollbackRequired  bool       `json:"rollbackRequired"`
}

// No System or Credential values are permitted in this structure.
type record struct {
	Management *claim       `json:"management,omitempty"`
	System     *claim       `json:"system,omitempty"`
	Pending    *transaction `json:"pending,omitempty"`
	RolledBack *claim       `json:"rolledBack,omitempty"`
}

func secureFile(info os.FileInfo, dir bool) error {
	if info.IsDir() != dir || info.Mode()&os.ModeSymlink != 0 || (!dir && !info.Mode().IsRegular()) || info.Mode().Perm()&0077 != 0 {
		return ErrStorage
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Geteuid()) {
		return ErrStorage
	}
	return nil
}
func (e *Engine) withRecord(ctx context.Context, fn func(*record) error) error {
	if err := lockMutex(ctx, &e.mu); err != nil {
		return err
	}
	defer e.mu.Unlock()
	r, unlock, err := lockRecord(ctx, e.dir, e.syncDir)
	if err != nil {
		return err
	}
	defer unlock()
	return fn(r)
}
func (e *Engine) save(r *record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return ErrStorage
	}
	f, err := os.CreateTemp(e.dir, ".host-*")
	if err != nil {
		return ErrStorage
	}
	name := f.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return ErrStorage
	}
	if err = os.Rename(name, filepath.Join(e.dir, "host.json")); err != nil {
		return ErrStorage
	}
	d, err := os.Open(e.dir)
	if err != nil {
		return ErrStorage
	}
	defer func() { _ = d.Close() }()
	if syncDirectory(d, e.syncDir) != nil {
		return ErrStorage
	}
	return nil
}
