// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
)

// No FRR plaintext or raw CONFIG_DB in the launch receipt or network.json.
// Before contains only the two original mode fields, including absence.
type frrMigrationReceipt struct {
	Mode          string       `json:"mode,omitempty"`
	Owner         string       `json:"owner"`
	Digest        string       `json:"digest"`
	PreHash       string       `json:"preHash"`
	PostHash      string       `json:"postHash"`
	Before        vlanChangeDB `json:"before"`
	StartHash     string       `json:"startHash"`
	ContainerHash string       `json:"containerHash"`
	ConfigHash    string       `json:"configHash"`
	CandidateHash string       `json:"candidateHash"`
	InputsHash    string       `json:"inputsHash"`
	RoutesHash    string       `json:"routesHash"`
	BackupHash    string       `json:"backupHash"`
}

func frrMigrationStorageRoot(dir string) (*os.Root, error) {
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if err = vlanAuthoritySecure(info, true); err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0700 != 0700 {
		return nil, fmt.Errorf("migration storage requires owner access")
	}
	return os.OpenRoot(dir)
}

func frrMigrationReadFile(root *os.Root, name string, limit int64) ([]byte, error) {
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if err = vlanAuthoritySecure(info, false); err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0600 != 0600 {
		return nil, fmt.Errorf("migration file requires owner access")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, fmt.Errorf("migration file unreadable or oversized")
	}
	return data, nil
}

func frrMigrationValidateStorage(dir string) error {
	root, err := frrMigrationStorageRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, err := d.ReadDir(-1)
	_ = d.Close()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := strings.TrimSuffix(entry.Name(), ".tmp")
		switch {
		case name == "launch.json", name == "backup.json", name == ".probe", frrMigrationScopedFile(name):
			if _, err := frrMigrationReadFile(root, entry.Name(), 16<<20); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unrecognized or interrupted migration storage entry")
		}
		if entry.Name() == name && strings.HasPrefix(name, "launch-") && frrMigrationScopedFile(name) {
			digest := strings.TrimSuffix(strings.TrimPrefix(name, "launch-"), ".json")
			if _, err := frrMigrationReceiptFile(filepath.Dir(dir), nil, digest); err != nil {
				return err
			}
		}
	}
	if _, err := frrMigrationReceiptFile(filepath.Dir(dir), nil); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func frrMigrationSyncDir(root *os.Root) error {
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func frrMigrationAtomicFile(root *os.Root, name string, data []byte) error {
	// Temporary files are never selected by the network journal. A crash before
	// rename can be retried; validate permissions/symlinks before discarding one.
	tmp := name + ".tmp"
	if _, err := frrMigrationReadFile(root, tmp, 16<<20); err == nil {
		if err := root.Remove(tmp); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
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
	if err = root.Rename(tmp, name); err != nil {
		return err
	}
	return frrMigrationSyncDir(root)
}

func frrMigrationPrepareStorage(journal string) error {
	if journal == "" {
		return fmt.Errorf("network journal required")
	}
	dir := filepath.Join(journal, "frr-migration")
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := frrMigrationValidateStorage(dir); err != nil {
		return err
	}
	root, err := frrMigrationStorageRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := frrMigrationAtomicFile(root, ".probe", []byte("storage preflight")); err != nil {
		return err
	}
	if err := root.Remove(".probe"); err != nil {
		return err
	}
	if err := frrMigrationSyncDir(root); err != nil {
		return err
	}
	parent, err := os.Open(journal)
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}

func frrMigrationScopedFile(name string) bool {
	for _, prefix := range []string{"launch-", "backup-"} {
		if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ".json") && vlanAuthorityDigestValid(strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".json")) {
			return true
		}
	}
	return false
}

// Immutable, retryable writes. Even an existing identical artifact is synced:
// the previous attempt may have failed after rename but before directory fsync.
func frrMigrationImmutableFile(root *os.Root, name string, data []byte) error {
	existing, err := frrMigrationReadFile(root, name, 16<<20)
	if err == nil {
		if !bytes.Equal(existing, data) {
			return fmt.Errorf("migration artifact differs")
		}
		f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		err = f.Sync()
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		return frrMigrationSyncDir(root)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return frrMigrationAtomicFile(root, name, data)
}

// The common network journal is the atomic active-receipt selector: its pending
// original request contains the digest. Preparing a new intent never replaces
// launch.json (the original forward receipt) or a previous transition artifact.
func frrMigrationPendingReceipt(m *SonicAgent, owner, mode string) (frrMigrationReceipt, error) {
	r, err := frrMigrationRecord(m)
	if err != nil || r == nil || r.OwnerID != owner || r.Pending == nil {
		return frrMigrationReceipt{}, fmt.Errorf("pending migration unavailable")
	}
	var spec frrMigrationSpec
	if json.Unmarshal(r.Pending.Request.Spec, &spec) != nil || frrMigrationMode(spec.Mode) != mode {
		return frrMigrationReceipt{}, fmt.Errorf("pending migration target mismatch")
	}
	receipt, err := frrMigrationReceiptFile(m.networkJournalDir, nil, spec.ApprovedDigest)
	if errors.Is(err, os.ErrNotExist) {
		receipt, err = frrMigrationReceiptFile(m.networkJournalDir, nil)
	}
	if err != nil {
		return receipt, err
	}
	p := r.Pending
	if receipt.Owner != owner || frrMigrationMode(receipt.Mode) != mode || receipt.Digest != spec.ApprovedDigest || receipt.PreHash != p.PreHash || receipt.PostHash != p.PostHash || !reflect.DeepEqual(receipt.Before, p.Before) {
		return receipt, fmt.Errorf("migration receipt binding mismatch")
	}
	return receipt, nil
}

func frrMigrationReceiptFile(journal string, write *frrMigrationReceipt, digest ...string) (frrMigrationReceipt, error) {
	var receipt frrMigrationReceipt
	if journal == "" {
		return receipt, os.ErrNotExist
	}
	root, err := frrMigrationStorageRoot(filepath.Join(journal, "frr-migration"))
	if err != nil {
		return receipt, err
	}
	defer root.Close()
	name, backupName := "launch.json", "backup.json"
	if len(digest) > 0 {
		if !vlanAuthorityDigestValid(digest[0]) {
			return receipt, fmt.Errorf("invalid receipt selector")
		}
		name, backupName = "launch-"+digest[0]+".json", "backup-"+digest[0]+".json"
	}
	if write != nil {
		data, err := json.Marshal(write)
		if err != nil {
			return receipt, err
		}
		if !vlanAuthorityDigestValid(write.Digest) {
			return receipt, fmt.Errorf("invalid receipt digest")
		}
		if err := frrMigrationImmutableFile(root, "launch-"+write.Digest+".json", data); err != nil {
			return receipt, err
		}
		// Retain the first receipt at the old path for backward compatibility.
		if _, err := frrMigrationReadFile(root, "launch.json", 16384); errors.Is(err, os.ErrNotExist) {
			return *write, frrMigrationImmutableFile(root, "launch.json", data)
		} else if err != nil {
			return receipt, err
		}
		return *write, nil
	}
	data, err := frrMigrationReadFile(root, name, 16384)
	if err != nil {
		return receipt, err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&receipt) != nil || d.Decode(new(any)) != io.EOF {
		return receipt, fmt.Errorf("invalid migration receipt")
	}
	if receipt.Owner == "" || len(receipt.Owner) > 256 || receipt.Before == nil || (receipt.Mode != "" && receipt.Mode != "Unified" && receipt.Mode != "Traditional") {
		return receipt, fmt.Errorf("invalid migration receipt identity")
	}
	if len(digest) > 0 && receipt.Digest != digest[0] {
		return receipt, fmt.Errorf("receipt selector mismatch")
	}
	for _, hash := range []string{receipt.Digest, receipt.PreHash, receipt.PostHash, receipt.StartHash, receipt.ContainerHash, receipt.ConfigHash, receipt.CandidateHash, receipt.InputsHash, receipt.RoutesHash, receipt.BackupHash} {
		if !vlanAuthorityDigestValid(hash) {
			return receipt, fmt.Errorf("invalid migration receipt digest")
		}
	}
	for key, fields := range receipt.Before {
		if key != "DEVICE_METADATA|localhost" || len(fields) == 0 {
			return receipt, fmt.Errorf("invalid migration before fields")
		}
		for field, value := range fields {
			if !frrMigrationModeUpdate(key, field, value, frrMigrationDesired(receipt.Mode)[key][field]) {
				return receipt, fmt.Errorf("invalid migration before fields")
			}
		}
	}
	if receipt.Mode != "" {
		backupName = "backup-" + receipt.Digest + ".json"
	}
	backup, err := frrMigrationReadFile(root, backupName, 16<<20)
	if err != nil || vlanChangeHash(backup) != receipt.BackupHash {
		return receipt, fmt.Errorf("migration backup integrity check failed")
	}
	return receipt, nil
}

// Separate 0600 artifact holds startup files and running config (which may have
// passwords). Never feed it into status, log messages, or the common journal.
func frrMigrationBackup(journal string, e frrMigrationEvidence, before vlanChangeDB, digest ...string) (string, error) {
	data, err := json.Marshal(struct {
		Before  vlanChangeDB    `json:"before"`
		Files   json.RawMessage `json:"files"`
		Running string          `json:"running"`
	}{before, e.Startup, e.Config})
	if err != nil {
		return "", err
	}
	root, err := frrMigrationStorageRoot(filepath.Join(journal, "frr-migration"))
	if err != nil {
		return "", err
	}
	defer root.Close()
	if len(digest) > 0 {
		if !vlanAuthorityDigestValid(digest[0]) {
			return "", fmt.Errorf("invalid backup selector")
		}
		if err := frrMigrationImmutableFile(root, "backup-"+digest[0]+".json", data); err != nil {
			return "", err
		}
		if _, err := frrMigrationReadFile(root, "backup.json", 16<<20); errors.Is(err, os.ErrNotExist) {
			if err := frrMigrationImmutableFile(root, "backup.json", data); err != nil {
				return "", err
			}
		} else if err != nil {
			return "", err
		}
		return vlanChangeHash(data), nil
	}
	existing, err := frrMigrationReadFile(root, "backup.json", 16<<20)
	if err == nil {
		if !bytes.Equal(existing, data) {
			return "", fmt.Errorf("existing migration backup differs; inspect before retry")
		}
		return vlanChangeHash(data), frrMigrationImmutableFile(root, "backup.json", data)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return vlanChangeHash(data), frrMigrationAtomicFile(root, "backup.json", data)
}
