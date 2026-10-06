// SPDX-License-Identifier: Apache-2.0
// Package artifactstate is the leaf coordination contract shared by writers and
// the external supervisor. Publication MUST hold the cooperating writer locks.
package artifactstate

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const DefaultDir = "/host/sonic-operator-artifacts"

var ErrReserved = errors.New("artifact recovery reservation blocks new mutation")

// ErrForeignPending identifies a validated foreign journal exclusion. Storage,
// readiness and native failures must not authorize agent dependency restoration.
var ErrForeignPending = errors.New("validated foreign recovery is pending")

type Reservation struct {
	Version  int    `json:"version"`
	Owner    string `json:"owner"`
	Token    string `json:"token"`
	Manifest string `json:"manifest"`
	Phase    string `json:"phase"`
}

func valid(r Reservation) bool {
	_, a := hex.DecodeString(r.Token)
	_, b := hex.DecodeString(r.Manifest)
	return r.Version == 1 && len(r.Owner) > 0 && len(r.Owner) <= 256 && len(r.Token) == 32 && len(r.Manifest) == 64 && a == nil && b == nil && (r.Phase == "Active" || r.Phase == "ForeignRecovery" || r.Phase == "Idle")
}
func secure(info os.FileInfo, dir bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 || info.Mode()&os.ModeSymlink != 0 || info.IsDir() != dir {
		return fmt.Errorf("untrusted artifact reservation storage")
	}
	return nil
}
func Read(dir string) (*Reservation, error) {
	if dir == "" {
		dir = DefaultDir
	}
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := secure(info, true); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	directory, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	err = directory.Sync()
	directory.Close()
	if err != nil {
		return nil, fmt.Errorf("artifact reservation durability unknown")
	}
	f, err := root.OpenFile("reservation.json", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return nil, err
	}
	if err := secure(info, false); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(raw) > 4096 {
		return nil, fmt.Errorf("invalid reservation size")
	}
	// The coordination record is flat: reject duplicate keys as well as unknowns.
	scan := json.NewDecoder(bytes.NewReader(raw))
	token, err := scan.Token()
	if err != nil || token != json.Delim('{') {
		return nil, fmt.Errorf("invalid reservation")
	}
	seen := map[string]bool{}
	for scan.More() {
		key, err := scan.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return nil, fmt.Errorf("ambiguous reservation")
		}
		seen[name] = true
		var value json.RawMessage
		if scan.Decode(&value) != nil {
			return nil, fmt.Errorf("invalid reservation value")
		}
	}
	var r Reservation
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || !valid(r) {
		return nil, fmt.Errorf("invalid artifact reservation")
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, fmt.Errorf("trailing reservation")
	}
	return &r, nil
}
func CheckPending(dir string) error {
	r, err := Read(dir)
	if err != nil {
		return err
	}
	if r != nil && r.Phase != "Idle" {
		return ErrReserved
	}
	return nil
}

// Only an already recorded foreign transaction may use this check, while holding
// the complete publication locks and validating its before/candidate scope. It
// must never authorize a new Pending record. Existing recovery has precedence;
// otherwise reciprocal reservations would deadlock legacy dual-pending states.
func CheckRecovery(dir string) error {
	_, err := Read(dir)
	if err != nil {
		return err
	}
	return nil
}
func Store(dir string, r Reservation) error {
	if !valid(r) {
		return fmt.Errorf("invalid reservation publication")
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if err := secure(info, true); err != nil {
		return err
	}
	if old, err := Read(dir); err != nil {
		return err
	} else if old != nil && old.Phase != "Idle" && (old.Owner != r.Owner || old.Token != r.Token || old.Manifest != r.Manifest) {
		return ErrReserved
	}
	data, _ := json.Marshal(r)
	f, err := os.CreateTemp(dir, ".reservation-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err := os.Rename(name, filepath.Join(dir, "reservation.json")); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
