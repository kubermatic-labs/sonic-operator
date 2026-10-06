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
	"syscall"

	"github.com/ironcore-dev/sonic-operator/internal/agent/artifactstate"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

// One record serializes the whole switch. Only target PORT fields are stored;
// unrelated CONFIG_DB (including credentials) is bound by a fingerprint.
type breakoutRecord struct {
	Checksum        string                    `json:"checksum"`
	Version         int                       `json:"version"`
	Request         agent.PortBreakoutRequest `json:"request"`
	Platform        breakoutPlatform          `json:"platform"`
	Before          vlanChangeDB              `json:"before"`
	Native          vlanChangeDB              `json:"native"`
	After           vlanChangeDB              `json:"after"`
	UnrelatedHash   string                    `json:"unrelated_hash"`
	Pending         bool                      `json:"pending"`
	NativeSucceeded bool                      `json:"native_succeeded"`
}

// ConfigureBreakoutJournal is a startup-only opt-in, not the RPC allow-breakout
// gate. Configure BOTH journal paths on EVERY cooperating writer, even after
// disabling breakout. Keep this private persistent directory across restarts.
// An unresolved native command needs manual inspection, never blind rollback.
func (m *SonicAgent) ConfigureBreakoutJournal(dir string) error {
	m.configMutex.Lock()
	defer m.configMutex.Unlock()
	if dir == "" || !filepath.IsAbs(dir) {
		return fmt.Errorf("breakout journal requires an absolute persistent path")
	}
	dir = filepath.Clean(dir)
	if dir == m.journalDir || dir == m.networkJournalDir {
		return fmt.Errorf("breakout, VLAN and network journals require separate directories")
	}
	if m.breakoutJournalDir != "" && m.breakoutJournalDir != dir {
		return fmt.Errorf("breakout journal already configured")
	}
	// Reuse the secured root-only initialization and fsync discipline.
	j := &SonicAgent{}
	if err := j.ConfigureVLANAuthorityJournal(dir); err != nil {
		return err
	}
	m.breakoutJournalDir = dir
	return nil
}

func (m *SonicAgent) lockBreakoutJournal(ctx context.Context) (*vlanAuthorityJournal, error) {
	if m.breakoutJournalDir == "" {
		return nil, fmt.Errorf("breakout journal is not configured")
	}
	j := &SonicAgent{journalDir: m.breakoutJournalDir, journalSync: m.journalSync, artifactStateDir: m.artifactStateDir}
	return j.lockVLANAuthorityJournal(ctx)
}

func loadBreakoutRecord(j *vlanAuthorityJournal) (*breakoutRecord, error) {
	dir, err := j.root.Open(".")
	if err != nil {
		return nil, err
	}
	entries, err := dir.ReadDir(-1)
	_ = dir.Close()
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.Name() != ".lock" && entry.Name() != "breakout.json" && entry.Name() != "breakout.json.tmp" {
			return nil, fmt.Errorf("unrecognized breakout journal entry; inspect before writes")
		}
	}
	f, err := j.root.OpenFile("breakout.json", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
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
	var r breakoutRecord
	d := json.NewDecoder(io.LimitReader(f, 4<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return nil, fmt.Errorf("invalid breakout journal: %w", err)
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("trailing or oversized breakout journal")
	}
	checksum := r.Checksum
	r.Checksum = ""
	data, err := json.Marshal(r)
	if err != nil || checksum != vlanChangeHash(data) {
		return nil, fmt.Errorf("breakout journal checksum mismatch")
	}
	r.Checksum = checksum
	if r.Version != 1 || validateBreakoutRequest(&r.Request) != nil || validateBreakoutPlatform(&r.Platform) != nil || r.Platform.Port != r.Request.Port || !vlanAuthorityDigestValid(r.UnrelatedHash) || r.Before == nil || r.Native == nil || r.After == nil {
		return nil, fmt.Errorf("invalid breakout journal identity or targets")
	}
	if err := breakoutConfigMatches(r.After, &r.Platform, r.Request.Mode); err != nil {
		return nil, fmt.Errorf("invalid breakout journal desired target: %w", err)
	}
	return &r, nil
}

func storeBreakoutRecord(j *vlanAuthorityJournal, r *breakoutRecord) error {
	old, err := loadBreakoutRecord(j)
	if err != nil {
		return err
	}
	if err := j.artifactPublication(old != nil && old.Pending); err != nil {
		return err
	}
	if artifactstate.CheckPending(j.artifactDir) != nil && r.Pending && (old == nil || !old.Pending || old.Request != r.Request) {
		return artifactstate.ErrReserved
	}
	copy := *r
	copy.Checksum = ""
	data, err := json.Marshal(copy)
	if err != nil {
		return err
	}
	copy.Checksum = vlanChangeHash(data)
	data, err = json.Marshal(copy)
	if err != nil {
		return err
	}
	const tmp = "breakout.json.tmp"
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
	if err := j.root.Rename(tmp, "breakout.json"); err != nil {
		return err
	}
	return j.sync()
}

// Call with configMutex AND the VLAN journal lock (if configured) held. Every
// writer uses VLAN -> breakout -> network ordering, including pending recovery.
func (m *SonicAgent) guardBreakoutWrites(ctx context.Context) (func(), error) {
	if m.breakoutJournalDir == "" {
		return m.guardNetworkWrites(ctx)
	}
	j, err := m.lockBreakoutJournal(ctx)
	if err != nil {
		return nil, err
	}
	r, err := loadBreakoutRecord(j)
	if err == nil && r != nil && r.Pending {
		err = fmt.Errorf("%s has pending breakout; reconcile its recorded request or inspect manually before other writes", r.Request.Port)
	}
	if err != nil {
		j.close()
		return nil, err
	}
	networkUnlock, err := m.guardNetworkWrites(ctx)
	if err != nil {
		j.close()
		return nil, err
	}
	return func() { networkUnlock(); j.close() }, nil
}
