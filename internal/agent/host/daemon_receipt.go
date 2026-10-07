// SPDX-License-Identifier: Apache-2.0
package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"time"
)

// File timestamps are opaque identity fields, never compared to realtime. No
// content or credential-derived digest is stored in activation/ownership files.
type daemonFile struct {
	Device     uint64 `json:"device"`
	Inode      uint64 `json:"inode"`
	ModifiedNS int64  `json:"modifiedNS"`
	ChangedNS  int64  `json:"changedNS"`
}
type daemonReceipt struct {
	Claim       claim      `json:"claim"`
	Profile     string     `json:"profile"`
	BootID      string     `json:"bootID"`
	PID         int        `json:"pid"`
	StartUptime float64    `json:"startUptime"`
	File        daemonFile `json:"file"`
}
type daemonIntent struct {
	Claim       claim   `json:"claim"`
	BootID      string  `json:"bootID"`
	AfterUptime float64 `json:"afterUptime"`
	PriorPID    int     `json:"priorPID"`
	PriorStart  float64 `json:"priorStart"`
}

func (n *Native) ConfigureState(dir string) error {
	path := filepath.Join(dir, "native-runtime")
	if n.stateDir != "" && n.stateDir != path {
		return ErrStorage
	}
	if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
		return ErrStorage
	}
	info, err := os.Lstat(path)
	if err != nil || secureFile(info, true) != nil {
		return ErrStorage
	}
	n.stateDir = path
	return nil
}
func profileIdentity(p NativeProfile) string {
	b, _ := json.Marshal(p)
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:])
}
func runtimeMode(mode string) bool {
	return slices.Contains([]string{"snmp", "ntpsec", "chrony"}, mode)
}
func (n *Native) writeRuntime(name string, v any) error {
	if n.stateDir == "" {
		return ErrStorage
	}
	data, err := json.Marshal(v)
	if err != nil {
		return ErrStorage
	}
	f, err := os.CreateTemp(n.stateDir, ".runtime-")
	if err != nil {
		return ErrStorage
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err != nil || ce != nil {
		return ErrStorage
	}
	if os.Rename(f.Name(), filepath.Join(n.stateDir, name)) != nil {
		return ErrStorage
	}
	d, err := os.Open(n.stateDir)
	if err != nil {
		return ErrStorage
	}
	defer func() { _ = d.Close() }()
	if d.Sync() != nil {
		return ErrStorage
	}
	return nil
}
func (n *Native) readDaemonReceipt(mode string) (*daemonReceipt, error) {
	if !runtimeMode(mode) || n.stateDir == "" {
		return nil, ErrStorage
	}
	root, err := openStore(n.stateDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	d, err := root.Open(".")
	if err != nil {
		return nil, ErrStorage
	}
	err = d.Sync()
	_ = d.Close()
	if err != nil {
		return nil, ErrStorage
	}
	f, err := root.OpenFile(mode+".receipt.json", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrStorage
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || secureFile(info, false) != nil || info.Size() > 64<<10 {
		return nil, ErrStorage
	}
	var r daemonReceipt
	data, err := io.ReadAll(io.LimitReader(f, 64<<10+1))
	if err != nil || StrictDecode(data, &r) != nil {
		return nil, ErrStorage
	}
	return &r, nil
}
func (n *Native) activateDaemon(ctx context.Context, q Request, p NativeProfile, mode, service string, expected []byte) error {
	if !runtimeMode(mode) || n.stateDir == "" {
		return ErrStorage
	}
	clock := n.bootNow
	if clock == nil {
		clock = readBootClock
	}
	before, err := clock()
	if err != nil || before.ID == "" {
		return ErrStorage
	}
	prior, _ := n.daemonEvidence(ctx, mode)
	intent := daemonIntent{Claim: *requestClaim(q), BootID: before.ID, AfterUptime: before.Seconds, PriorPID: prior.PID, PriorStart: prior.StartUptime}
	if err = n.writeRuntime(mode+".intent.json", intent); err != nil {
		return err
	}
	command := []string{"systemctl", "restart", service}
	var container snmpContainer
	if mode == "snmp" {
		container, err = n.snmpContainer(ctx)
		if err != nil {
			return err
		}
		if !container.State.Running {
			command = []string{"docker", "start", container.ID}
		}
	}
	if _, err = n.run(ctx, command...); err != nil {
		return err
	}
	if mode == "snmp" {
		latest, e := n.snmpContainer(ctx)
		if e != nil || !latest.State.Running || latest.Image != container.Image {
			return ErrNative
		}
		if e = n.verifyConsumers(ctx, p, "snmp"); e != nil {
			return e
		}
	}
	ready, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var observed daemonEvidence
	for {
		observed, err = n.daemonEvidence(ready, mode)
		if err == nil && daemonProcessMatches(mode, observed, expected) && observed.BootID == before.ID && observed.StartUptime >= before.Seconds && (observed.PID != prior.PID || observed.StartUptime != prior.StartUptime) {
			break
		}
		select {
		case <-ready.Done():
			return ErrNative
		case <-time.After(100 * time.Millisecond):
		}
	}
	r := daemonReceipt{Claim: intent.Claim, Profile: profileIdentity(p), BootID: observed.BootID, PID: observed.PID, StartUptime: observed.StartUptime, File: observed.File}
	return n.writeRuntime(mode+".receipt.json", r)
}
