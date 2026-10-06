// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"time"

	"github.com/ironcore-dev/sonic-operator/internal/agent/artifactstate"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"golang.org/x/sys/unix"
)

type vlanAuthorityRecord struct {
	Checksum    string                `json:"checksum"`
	Version     int                   `json:"version"`
	VLANID      uint32                `json:"vlan_id"`
	OwnerID     string                `json:"owner_id"`
	Confirmed   vlanChangeDB          `json:"confirmed"`
	Fingerprint string                `json:"fingerprint"`
	Pending     *vlanAuthorityPending `json:"pending,omitempty"`
}

type vlanAuthorityPending struct {
	Request          agent.VLANAuthorityRequest `json:"request"`
	Before           vlanChangeDB               `json:"before"`
	After            vlanChangeDB               `json:"after"`
	PreHash          string                     `json:"pre_hash"`
	PostHash         string                     `json:"post_hash"`
	Intermediate     vlanChangeDB               `json:"intermediate,omitempty"`
	IntermediateHash string                     `json:"intermediate_hash,omitempty"`
}

// ConfigureVLANAuthorityJournal is a startup-only backend write opt-in. The
// directory MUST be persistent, dedicated to one CONFIG_DB and configured on
// EVERY writer process, including additive-only instances and subsequent starts
// after authority is disabled. Do not clear the journal flag after first use.
// There is no implicit discovery of an arbitrary prior journal path: unconfigured
// instances retain legacy additive behavior and cannot prove ownership absent.
// Configured writers share configMutex locally and flock across processes.
// Noncooperating writes can fail CAS or wedge recovery; they are not serialized.
func (m *SonicAgent) ConfigureVLANAuthorityJournal(dir string) error {
	m.configMutex.Lock()
	defer m.configMutex.Unlock()
	if dir == "" || !filepath.IsAbs(dir) {
		return fmt.Errorf("journal directory must be an explicit absolute persistent path")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("VLAN authority journal requires root")
	}
	dir = filepath.Clean(dir)
	if dir == m.breakoutJournalDir || dir == m.networkJournalDir {
		return fmt.Errorf("VLAN, breakout and network journals require separate directories")
	}
	if m.journalDir != "" && m.journalDir != dir {
		return fmt.Errorf("journal directory already configured")
	}
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if err := vlanAuthoritySecure(info, true); err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	f, err := root.OpenFile(".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return err
	}
	if err := vlanAuthoritySecure(info, false); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return err
	}
	// Persist the directory entry itself as well as its contents.
	parent, err := os.Open(filepath.Dir(dir))
	if err != nil {
		return err
	}
	defer parent.Close()
	if err := parent.Sync(); err != nil {
		return err
	}
	m.journalDir = dir
	return nil
}

func vlanAuthoritySecure(info os.FileInfo, directory bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("journal requires private owner-only files and directory")
	}
	if directory && !info.IsDir() || !directory && (!info.Mode().IsRegular() || stat.Nlink != 1) {
		return fmt.Errorf("invalid journal file type or hard link")
	}
	return nil
}

type vlanAuthorityJournal struct {
	artifactDir string
	root        *os.Root
	lock        *os.File
	syncDir     func(*os.File) error
}

func (j *vlanAuthorityJournal) close() {
	_ = unix.Flock(int(j.lock.Fd()), unix.LOCK_UN)
	_ = j.lock.Close()
	_ = j.root.Close()
}

// Opening/locking never creates files, including on snapshot reads.
func (m *SonicAgent) lockVLANAuthorityJournal(ctx context.Context) (*vlanAuthorityJournal, error) {
	if m.journalDir == "" {
		return nil, fmt.Errorf("VLAN authority journal is not configured")
	}
	info, err := os.Lstat(m.journalDir)
	if err != nil {
		return nil, err
	}
	if err := vlanAuthoritySecure(info, true); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(m.journalDir)
	if err != nil {
		return nil, err
	}
	f, err := root.OpenFile(".lock", os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	j := &vlanAuthorityJournal{root: root, lock: f, syncDir: m.journalSync, artifactDir: m.artifactStateDir}
	info, err = f.Stat()
	if err == nil {
		err = vlanAuthoritySecure(info, false)
	}
	if err != nil {
		j.close()
		return nil, err
	}
	for {
		if err := ctx.Err(); err != nil {
			j.close()
			return nil, err
		}
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			// A previous rename/unlink may be visible despite a failed fsync.
			// Establish durability before trusting either records OR their absence,
			// including after restart. Never recover from visibility alone.
			if err := j.sync(); err != nil {
				j.close()
				return nil, fmt.Errorf("journal directory durability uncertain: %w", err)
			}
			return j, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			j.close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			j.close()
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func vlanAuthorityFile(id uint32) string { return fmt.Sprintf("vlan-%d.json", id) }

func (j *vlanAuthorityJournal) load(id uint32) (*vlanAuthorityRecord, error) {
	f, err := j.root.OpenFile(vlanAuthorityFile(id), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if err := vlanAuthoritySecure(info, false); err != nil {
		return nil, err
	}
	var r vlanAuthorityRecord
	d := json.NewDecoder(io.LimitReader(f, 16<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return nil, fmt.Errorf("invalid VLAN authority journal")
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("trailing or oversized VLAN authority journal")
	}
	checksum := r.Checksum
	r.Checksum = ""
	bound, err := json.Marshal(r)
	if err != nil || checksum != vlanChangeHash(bound) {
		return nil, fmt.Errorf("VLAN authority journal checksum mismatch")
	}
	r.Checksum = checksum
	if r.Version != 1 || r.VLANID != id || id < 1 || id > 4094 || r.OwnerID == "" || len(r.OwnerID) > 256 {
		return nil, fmt.Errorf("invalid VLAN authority identity/version")
	}
	if r.Confirmed != nil {
		if !reflect.DeepEqual(r.Confirmed, vlanChangeTarget(r.Confirmed, id)) || vlanAuthorityTargetSafe(r.Confirmed, id) != nil || !vlanAuthorityDigestValid(r.Fingerprint) {
			return nil, fmt.Errorf("invalid confirmed VLAN target")
		}
	} else if r.Fingerprint != "" || r.Pending == nil {
		return nil, fmt.Errorf("missing confirmed VLAN target")
	}
	if p := r.Pending; p != nil {
		if validateVLANAuthority(&p.Request) != nil || p.Request.VLAN.ID != id || p.Request.OwnerID != r.OwnerID || !vlanAuthorityDigestValid(p.PreHash) || !vlanAuthorityDigestValid(p.PostHash) {
			return nil, fmt.Errorf("invalid pending VLAN identity")
		}
		for _, target := range []vlanChangeDB{p.Before, p.After} {
			if target == nil || !reflect.DeepEqual(target, vlanChangeTarget(target, id)) || vlanAuthorityTargetSafe(target, id) != nil {
				return nil, fmt.Errorf("invalid pending VLAN target")
			}
		}
		if !reflect.DeepEqual(p.After, vlanAuthorityDesired(&p.Request)) {
			return nil, fmt.Errorf("pending VLAN desired target mismatch")
		}
		if p.Intermediate != nil {
			if !reflect.DeepEqual(p.Intermediate, vlanAuthorityIntermediate(p.Before, p.After)) || !vlanAuthorityDigestValid(p.IntermediateHash) {
				return nil, fmt.Errorf("invalid pending VLAN intermediate snapshot")
			}
		} else if p.IntermediateHash != "" {
			return nil, fmt.Errorf("missing pending VLAN intermediate snapshot")
		}
	}
	return &r, nil
}

func (j *vlanAuthorityJournal) store(r *vlanAuthorityRecord) error {
	old, err := j.load(r.VLANID)
	if err != nil {
		return err
	}
	if err := j.artifactPublication(old != nil && old.Pending != nil); err != nil {
		return err
	}
	if artifactstate.CheckPending(j.artifactDir) != nil && r.Pending != nil && (old == nil || old.Pending == nil || !reflect.DeepEqual(r.Pending.Request, old.Pending.Request)) {
		return artifactstate.ErrReserved
	}
	// Detect damaged/partially edited records, including ownership identity. This
	// is an integrity check, not authentication against a privileged local writer.
	copy := *r
	copy.Checksum = ""
	bound, err := json.Marshal(copy)
	if err != nil {
		return err
	}
	copy.Checksum = vlanChangeHash(bound)
	data, err := json.Marshal(copy)
	if err != nil {
		return err
	}
	name := vlanAuthorityFile(r.VLANID)
	tmp := name + ".tmp"
	if err := j.root.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := j.root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := j.root.Rename(tmp, name); err != nil {
		return err
	}
	return j.sync()
}

func (j *vlanAuthorityJournal) remove(id uint32) error {
	if err := j.root.Remove(vlanAuthorityFile(id)); err != nil {
		return err
	}
	return j.sync()
}

func (j *vlanAuthorityJournal) sync() error {
	d, err := j.root.Open(".")
	if err != nil {
		return err
	}
	defer d.Close()
	if j.syncDir != nil {
		return j.syncDir(d)
	}
	return d.Sync()
}
