// SPDX-License-Identifier: Apache-2.0
package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
)

const (
	profileFile        = "/etc/sonic/sonic-operator-host-profile.json"
	bootFile           = "/etc/sonic/sonic-operator-management.json"
	interfacesTemplate = "/usr/share/sonic/templates/interfaces.j2"
	chronyTemplate     = "/usr/share/sonic/templates/chrony.conf.j2"
	macDropIn          = "/etc/systemd/system/interfaces-config.service.d/90-sonic-operator-management.conf"
)
const macUnit = "[Service]\nExecStartPost=/usr/local/sbin/sonic-operator-host-recovery --apply-boot-mac\n"

// NativeProfile is an operator-qualified image/template baseline, installed as
// an immutable site artifact. A filename resemblance is never baseline proof.
type NativeProfile struct {
	ImageSHA256            string            `json:"imageSHA256"`
	InterfacesSHA256       string            `json:"interfacesSHA256"`
	ChronySHA256           string            `json:"chronySHA256"`
	SNMPSHA256             string            `json:"snmpSHA256"`
	NTPBackend             string            `json:"ntpBackend"`
	NTPsecSHA256           string            `json:"ntpsecSHA256,omitempty"`
	LegacyMACHooks         []LegacyMACHook   `json:"legacyMACHooks,omitempty"`
	ImportedMACEnvironment string            `json:"importedMACEnvironment,omitempty"`
	ConsumerSHA256         map[string]string `json:"consumerSHA256"`
}

// Native callbacks are internal and wired by the SONiC adapter. Load/CAS operate
// solely on allowlisted host tables. WithMutation holds cooperating-writer locks.
type Native struct {
	BaseMAC           func(context.Context) (string, error)
	Load              func(context.Context) (Database, error)
	CAS               func(context.Context, Database, Database) error
	Save              func(context.Context) error
	WithMutation      func(context.Context, func() error) error
	WithRecovery      func(context.Context, func(context.Context) error) error
	BeforePublication func(context.Context) error
	Run               func(context.Context, []string, []byte) ([]byte, error)
	ReadFile          func(string) ([]byte, error)
	ReadUnitFile      func(string) ([]byte, os.FileInfo, error)
	WriteFile         func(string, []byte, os.FileMode) error
	SNMPExchange      func(context.Context, []byte) ([]byte, error)
	BeforeRecovery    func(context.Context) error
	stateDir          string
	journalDir        string
	bootNow           func() (bootClock, error)
}

type nativeExclusiveKey struct{}

func (n *Native) CheckPublication(ctx context.Context) error {
	if n.BeforePublication == nil {
		return ErrStorage
	}
	if err := n.BeforePublication(ctx); err != nil {
		return err
	}
	return n.WatchdogReady(ctx)
}
func (n *Native) ExclusiveRecovery(ctx context.Context, fn func(context.Context) error) error {
	if n.WithRecovery == nil {
		return ErrStorage
	}
	return n.WithRecovery(ctx, func(locked context.Context) error {
		return fn(context.WithValue(locked, nativeExclusiveKey{}, n))
	})
}

func (n *Native) Exclusive(ctx context.Context, fn func(context.Context) error) error {
	if n.WithMutation == nil {
		return ErrStorage
	}
	return n.WithMutation(ctx, func() error { return fn(context.WithValue(ctx, nativeExclusiveKey{}, n)) })
}
func (n *Native) mutate(ctx context.Context, fn func() error) error {
	if ctx.Value(nativeExclusiveKey{}) == n {
		return fn()
	}
	if n.WithMutation == nil {
		return ErrStorage
	}
	return n.WithMutation(ctx, fn)
}
func (n *Native) RecoverDependencies(ctx context.Context) error {
	if n.BeforeRecovery != nil {
		return n.BeforeRecovery(ctx)
	}
	return nil
}

func boundedRun(ctx context.Context, args []string, input []byte) ([]byte, error) {
	if len(args) == 0 {
		return nil, ErrNative
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.Stdin = bytes.NewReader(input)
	// Native stderr is deliberately discarded: SONiC validators may echo a
	// community or other secret. No argument list or command output is logged.
	cmd.Stderr = io.Discard
	var out limitedBuffer
	cmd.Stdout = &out
	if cmd.Run() != nil || out.exceeded {
		return nil, ErrNative
	}
	return out.Bytes(), nil
}

type limitedBuffer struct {
	bytes.Buffer
	exceeded bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 4<<20 {
		b.exceeded = true
		return 0, ErrNative
	}
	return b.Buffer.Write(p)
}
func (n *Native) run(ctx context.Context, args ...string) ([]byte, error) {
	f := n.Run
	if f == nil {
		f = boundedRun
	}
	b, e := f(ctx, args, nil)
	if e != nil {
		return nil, ErrNative
	}
	return b, nil
}
func (n *Native) read(path string) ([]byte, error) {
	if n.ReadFile != nil {
		return n.ReadFile(path)
	}
	path, limit, e := nativeReadPath(path, filepath.EvalSymlinks)
	if e != nil {
		return nil, e
	}
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	defer func() { _ = f.Close() }()
	i, e := f.Stat()
	if e != nil {
		return nil, ErrNative
	}
	return readNativeContents(f, i, limit)
}

func nativeReadPath(path string, resolve func(string) (string, error)) (string, int64, error) {
	limit := int64(4 << 20)
	if path == "/usr/bin/python3" || path == "/bin/sh" {
		resolved, err := resolve(path)
		if err != nil {
			return "", 0, ErrNative
		}
		allowed := resolved == "/usr/bin/dash" || resolved == "/bin/dash" || resolved == "/usr/bin/python3.11" || resolved == "/usr/bin/python3.13"
		if !allowed {
			return "", 0, ErrNative
		}
		path = resolved
		// Only an explicitly requested, allowlisted interpreter gets the
		// executable bound. Callers still verify its pinned content hash.
		limit = 96 << 20
	}
	if path == RecoveryBinaryFile {
		limit = 96 << 20
	}
	return path, limit, nil
}

func readNativeContents(r io.Reader, i os.FileInfo, limit int64) ([]byte, error) {
	if !i.Mode().IsRegular() || i.Size() > limit {
		return nil, ErrNative
	}
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if int64(len(b)) > limit {
		return nil, ErrNative
	}
	return b, err
}
func (n *Native) write(path string, data []byte, mode os.FileMode) error {
	if n.WriteFile != nil {
		return n.WriteFile(path, data, mode)
	}
	// Destinations are constants at call sites; refuse symlink replacement.
	if info, e := os.Lstat(path); e == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return ErrNative
	} else if e != nil && !errors.Is(e, os.ErrNotExist) {
		return ErrNative
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".sonic-host-*")
	if e != nil {
		return ErrNative
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if e = f.Chmod(mode); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return ErrNative
	}
	if os.Rename(f.Name(), path) != nil {
		return ErrNative
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return ErrNative
	}
	defer func() { _ = d.Close() }()
	if d.Sync() != nil {
		return ErrNative
	}
	return nil
}
func hashMatches(data []byte, want string) bool {
	h := sha256.Sum256(data)
	return len(want) == 64 && hex.EncodeToString(h[:]) == want
}
func (n *Native) profile(ctx context.Context, kind string) (NativeProfile, error) {
	var p NativeProfile
	b, e := n.read(profileFile)
	if e != nil || strictDecodeLimit(b, &p, 256<<10) != nil {
		return p, ErrNative
	}
	b, e = n.read("/etc/sonic/sonic_version.yml")
	if e != nil || !hashMatches(b, p.ImageSHA256) {
		return p, ErrNative
	}
	if kind == "Management" {
		b, e = n.read(interfacesTemplate)
		if e != nil || !hashMatches(b, p.InterfacesSHA256) {
			return p, ErrNative
		}
		if e = n.verifyConsumers(ctx, p, "Management"); e != nil {
			return p, e
		}
		if _, e = n.read("/etc/network/ifupdown2/policy.d/ztp_dhcp.json"); !errors.Is(e, os.ErrNotExist) {
			return p, ErrNative
		}
	}
	return p, nil
}
func (n *Native) saved() (Database, error) {
	read := n.ReadFile
	if read == nil {
		read = readSavedConfigFile
	}
	b, e := read("/etc/sonic/config_db.json")
	if e != nil {
		return nil, e
	}
	var raw map[string]json.RawMessage
	if strictDecodeLimit(b, &raw, savedConfigLimit) != nil {
		return nil, ErrNative
	}
	db := Database{}
	for _, table := range HostTables {
		if len(raw[table]) != 0 {
			var rows map[string]map[string]string
			if json.Unmarshal(raw[table], &rows) != nil {
				return nil, ErrNative
			}
			for key, fields := range rows {
				if len(fields) == 0 {
					rows[key] = map[string]string{"NULL": "NULL"}
				}
			}
			db[table] = rows
		}
	}
	return db, nil
}

var HostTables = []string{"MGMT_INTERFACE", "MGMT_PORT", "MGMT_VRF_CONFIG", "NTP", "NTP_SERVER", "SNMP", "SNMP_COMMUNITY", "SNMP_USER"}

func (n *Native) bootMAC() (string, error) {
	b, e := n.read(bootFile)
	if e != nil {
		if errors.Is(e, os.ErrNotExist) {
			return "", nil
		}
		return "", e
	}
	var v struct {
		MAC string `json:"mac"`
	}
	if StrictDecode(b, &v) != nil {
		return "", ErrNative
	}
	return v.MAC, nil
}
func (n *Native) Observe(ctx context.Context, q Request) (Result, error) {
	out := Result{}
	db, e := n.Load(ctx)
	if e != nil {
		return out, ErrNative
	}
	saved, e := n.saved()
	if e != nil {
		return out, ErrNative
	}
	if q.Kind == "System" {
		out, err := n.observeSystem(ctx, q, db, saved)
		return n.stableObservation(ctx, db, out, err)
	}
	after, e := managementDatabase(db, *q.Management)
	if e != nil {
		return out, e
	}
	mac, e := n.bootMAC()
	if e != nil {
		return out, ErrNative
	}
	out.ConfigurationVerified = scopedEqual(db, after, "MGMT_INTERFACE") && (q.Management.MAC == "" || mac == q.Management.MAC)
	out.PersistenceVerified = scopedEqual(saved, after, "MGMT_INTERFACE") && (q.Management.MAC == "" || mac == q.Management.MAC)
	profile, e := n.profile(ctx, "Management")
	if e != nil {
		return out, e
	}
	if e = n.validateLegacyMACHooks(*q.Management, profile, db); e != nil {
		out.PersistenceVerified = false
		return out, e
	}
	generated, e := n.render(ctx, db, interfacesTemplate, false)
	if e != nil {
		return out, e
	}
	installed, e := n.read("/etc/network/interfaces")
	out.PersistenceVerified = out.PersistenceVerified && e == nil && bytes.Equal(generated, installed)
	if q.Management.MAC != "" {
		unit, e := n.read(macDropIn)
		out.PersistenceVerified = out.PersistenceVerified && e == nil && string(unit) == macUnit
	}
	addresses, e := n.run(ctx, "ip", "-j", "address", "show", "dev", "eth0")
	if e != nil {
		return out, e
	}
	routes, e := n.managementRoutes(ctx)
	if e != nil {
		return out, e
	}
	out.RuntimeVerified = managementRuntimeMatches(*q.Management, addresses, routes)
	for _, a := range q.Management.Addresses {
		rules, e := n.run(ctx, "ip", family(a.Prefix), "-j", "rule", "show")
		if e != nil || !managementRuleMatches(a, rules) {
			out.RuntimeVerified = false
		}
	}
	out.GatewayVerified = true
	for _, a := range q.Management.Addresses {
		if a.Gateway != "" {
			if _, e := n.run(ctx, "ping", family(a.Prefix), "-n", "-c", "1", "-W", "2", "-I", "eth0", a.Gateway); e != nil {
				out.GatewayVerified = false
			}
		}
	}
	return n.stableObservation(ctx, db, out, nil)
}

func (n *Native) stableObservation(ctx context.Context, before Database, out Result, err error) (Result, error) {
	if err != nil {
		return out, err
	}
	after, e := n.Load(ctx)
	if e != nil || !reflect.DeepEqual(before, after) {
		out.ConfigurationVerified = false
		out.RuntimeVerified = false
		out.PersistenceVerified = false
		return out, ErrConflict
	}
	return out, nil
}
func (n *Native) managementRoutes(ctx context.Context) ([]byte, error) {
	var all []json.RawMessage
	for _, f := range []string{"-4", "-6"} {
		b, e := n.run(ctx, "ip", f, "-j", "route", "show", "table", "all", "dev", "eth0")
		if e != nil {
			return nil, e
		}
		var v []map[string]json.RawMessage
		if json.Unmarshal(b, &v) != nil {
			return nil, ErrNative
		}
		for _, route := range v {
			if route == nil {
				return nil, ErrNative
			}
			if raw, ok := route["dev"]; ok {
				var dev string
				if json.Unmarshal(raw, &dev) != nil || dev != "eth0" {
					return nil, ErrNative
				}
			} else {
				route["dev"] = json.RawMessage(`"eth0"`)
			}
			encoded, e := json.Marshal(route)
			if e != nil {
				return nil, ErrNative
			}
			all = append(all, encoded)
		}
	}
	return json.Marshal(all)
}
func (n *Native) Validate(ctx context.Context, q Request) error {
	if ValidateRequest(q) != nil {
		return ErrInvalid
	}
	p, e := n.profile(ctx, q.Kind)
	if e != nil {
		return e
	}
	db, e := n.Load(ctx)
	if e != nil {
		return ErrNative
	}
	if q.Kind == "System" {
		return n.validateSystem(ctx, *q.System, p, db)
	}
	if db["MGMT_VRF_CONFIG"]["vrf_global"]["mgmtVrfEnabled"] == "true" {
		return ErrNative
	}
	after, e := managementDatabase(db, *q.Management)
	if e != nil {
		return e
	}
	if e = n.validateLegacyMACHooks(*q.Management, p, db); e != nil {
		return e
	}
	_, e = n.render(ctx, after, interfacesTemplate, false)
	return e
}
func (n *Native) WatchdogReady(ctx context.Context) error {
	if _, err := n.InstallationReceipt(true); err != nil {
		return err
	}
	if err := n.VerifyRecoveryUnits(ctx); err != nil {
		return err
	}
	for _, op := range []string{"is-enabled", "is-active"} {
		b, e := n.run(ctx, "systemctl", op, "sonic-operator-host-recovery.timer")
		if e != nil || strings.TrimSpace(string(b)) != map[string]string{"is-enabled": "enabled", "is-active": "active"}[op] {
			return ErrNative
		}
	}
	return nil
}
