// SPDX-License-Identifier: Apache-2.0
package host

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type systemFixture struct {
	t                    *testing.T
	n                    *Native
	engine               *Engine
	dir                  string
	files                map[string][]byte
	db, loaded           Database
	running, failRestart bool
	restarts, scrubs     int
	pid                  int
	clock, started, wall float64
	stamp                daemonFile
	// persistent models /var/lib/snmp/snmpd.conf; usm the daemon's loaded users.
	persistent []byte
	usm        map[string]SNMPUser
}

// persist mirrors Net-SNMP's store at startup and shutdown. The fixture
// records passphrases where the native file holds localized keys.
func (f *systemFixture) persist() {
	var b strings.Builder
	b.WriteString("engineBoots 1\n")
	for _, name := range slices.Sorted(maps.Keys(f.usm)) {
		u := f.usm[name]
		fmt.Fprintf(&b, "usmUser 1 3 0x80 0x%x 0x%x NULL .1 0x%x .2 0x%x \"\"\n", name, name, string(u.AuthPassword), string(u.PrivPassword))
	}
	f.persistent = []byte(b.String())
}

// startDaemon loads users from the rendered configuration, then lets persisted
// records override them, exactly as Net-SNMP reads its persistent file last.
func (f *systemFixture) startDaemon() {
	f.usm = map[string]SNMPUser{}
	for name, row := range f.db["SNMP_USER"] {
		u := SNMPUser{Name: name, SecurityLevel: SNMPAuthNoPriv, AuthProtocol: row["SNMP_USER_AUTH_TYPE"], AuthPassword: Credential(row["SNMP_USER_AUTH_PASSWORD"])}
		if row["SNMP_USER_TYPE"] == "Priv" {
			u.SecurityLevel, u.PrivProtocol, u.PrivPassword = SNMPAuthPriv, row["SNMP_USER_ENCRYPTION_TYPE"], Credential(row["SNMP_USER_ENCRYPTION_PASSWORD"])
		}
		f.usm[name] = u
	}
	for _, line := range strings.Split(string(f.persistent), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 11 || fields[0] != "usmUser" {
			continue
		}
		decode := func(v string) string { b, _ := hex.DecodeString(strings.TrimPrefix(v, "0x")); return string(b) }
		u := SNMPUser{Name: decode(fields[4]), SecurityLevel: SNMPAuthNoPriv, AuthProtocol: "SHA", AuthPassword: Credential(decode(fields[8]))}
		if priv := decode(fields[10]); priv != "" {
			u.SecurityLevel, u.PrivProtocol, u.PrivPassword = SNMPAuthPriv, "AES", Credential(priv)
		}
		f.usm[u.Name] = u
	}
	f.persist()
}
func (f *systemFixture) persistedUsers() []string {
	names := []string{}
	for _, line := range strings.Split(string(f.persistent), "\n") {
		if fields := strings.Fields(line); len(fields) > 4 && fields[0] == "usmUser" {
			b, _ := hex.DecodeString(strings.TrimPrefix(fields[4], "0x"))
			names = append(names, string(b))
		}
	}
	return names
}

func (f *systemFixture) request(s SNMP) Request {
	return Request{Kind: "System", Owner: "system-owner", Target: "switch", Revision: "1", System: &System{SNMP: &s}}
}
func (f *systemFixture) config(db Database) []byte {
	b, _ := json.Marshal(map[string]any{"SNMP": db["SNMP"], "SNMP_COMMUNITY": db["SNMP_COMMUNITY"], "SNMP_USER": db["SNMP_USER"]})
	return b
}
func (f *systemFixture) evidence() daemonEvidence {
	v := installedSNMPEvidence()
	v.PID = f.pid
	v.BootID = "test-boot"
	v.StartUptime = f.started
	v.ObservedUptime = f.clock + 1
	v.ObservedWall = f.wall + f.clock
	v.File = f.stamp
	v.ConfigDigest = digestForTest(string(f.files["/etc/snmp/snmpd.conf"]))
	v.PersistedUsers = f.persistedUsers()
	return v
}
func (f *systemFixture) persistentArchive() ([]byte, error) {
	var out bytes.Buffer
	w := tar.NewWriter(&out)
	_ = w.WriteHeader(&tar.Header{Name: "snmp/", Mode: 0755, Typeflag: tar.TypeDir, Uid: 110, Gid: 112})
	if f.persistent != nil {
		_ = w.WriteHeader(&tar.Header{Name: "snmp/snmpd.conf", Mode: 0600, Size: int64(len(f.persistent)), Typeflag: tar.TypeReg, Uid: 110, Gid: 112})
		_, _ = w.Write(f.persistent)
	}
	_ = w.Close()
	return out.Bytes(), nil
}
func (f *systemFixture) restorePersistent(input []byte) ([]byte, error) {
	if f.running {
		f.t.Fatal("persistent USM state rewritten under a running daemon")
	}
	r := tar.NewReader(bytes.NewReader(input))
	h, err := r.Next()
	if err != nil || h.Name != "snmpd.conf" || h.Uid != 110 || h.Gid != 112 || h.Mode != 0600 {
		f.t.Fatal("persistent state archive lost native ownership")
	}
	f.persistent, _ = io.ReadAll(r)
	f.scrubs++
	return nil, nil
}
func (f *systemFixture) run(_ context.Context, args []string, input []byte) ([]byte, error) {
	joined := strings.Join(args, " ")
	if len(args) >= 2 && args[0] == "docker" && args[1] == "inspect" {
		status := "exited"
		if f.running {
			status = "running"
		}
		return json.Marshal(map[string]any{"Id": strings.Repeat("a", 64), "Image": "sha256:" + strings.Repeat("b", 64), "State": map[string]any{"Running": f.running, "Status": status}, "Config": map[string]any{"Entrypoint": []string{"/usr/bin/docker-snmp-init.sh"}}})
	}
	if joined == "docker cp "+strings.Repeat("a", 64)+":"+snmpPersistentDir+" -" {
		return f.persistentArchive()
	}
	if joined == "docker cp -a - "+strings.Repeat("a", 64)+":"+snmpPersistentDir {
		return f.restorePersistent(input)
	}
	if len(args) >= 2 && args[0] == "docker" && args[1] == "cp" {
		_, path, _ := strings.Cut(args[3], ":")
		body, ok := f.files[path]
		if !ok {
			return nil, ErrNative
		}
		var out bytes.Buffer
		w := tar.NewWriter(&out)
		_ = w.WriteHeader(&tar.Header{Name: filepath.Base(path), Mode: 0600, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = w.Write(body)
		_ = w.Close()
		return out.Bytes(), nil
	}
	if len(args) > 3 && args[0] == "docker" && args[1] == "exec" {
		if !f.running {
			return nil, ErrNative
		}
		if args[2] == "-i" {
			args = args[4:]
		} else {
			args = args[3:]
		}
	}
	if args[0] == "cat" {
		v, ok := f.files[args[1]]
		if !ok {
			return nil, ErrNative
		}
		return v, nil
	}
	if args[0] == "sha256sum" {
		v, ok := f.files[args[1]]
		if !ok {
			return nil, ErrNative
		}
		return []byte(digestForTest(string(v)) + "  " + args[1] + "\n"), nil
	}
	if args[0] == "sonic-cfggen" {
		if len(args) == 3 {
			return json.Marshal(f.db)
		}
		path := args[len(args)-1]
		template := f.files[path]
		if template == nil {
			template, _ = os.ReadFile(path)
		}
		if string(template) == "supervisor-template" {
			return []byte("supervisor"), nil
		}
		var db Database
		if json.Unmarshal(input, &db) != nil {
			return nil, ErrNative
		}
		return f.config(db), nil
	}
	if args[0] == "python3" && len(args) > 2 && args[2] == nativeDaemonProbe {
		if !f.running {
			return []byte(`{}`), nil
		}
		return json.Marshal(f.evidence())
	}
	if joined == "systemctl stop snmp.service" {
		if f.running {
			f.persist()
		}
		f.running = false
		return nil, nil
	}
	if joined == "systemctl restart snmp.service" || joined == "systemctl start snmp.service" || (len(args) == 3 && args[0] == "docker" && args[1] == "start") {
		if f.running {
			f.persist()
		}
		f.restarts++
		f.running = false
		if f.failRestart {
			return nil, ErrNative
		}
		s := SNMP{Location: f.db["SNMP"]["LOCATION"]["Location"]}
		for c := range f.db["SNMP_COMMUNITY"] {
			s.Community = Credential(c)
		}
		if !snmpBootstrapMatches(f.files[snmpBootstrapPath], s) {
			f.t.Fatal("restart would reimport retired credentials")
		}
		f.running = true
		f.pid++
		f.clock++
		f.started = f.clock
		f.stamp.Inode++
		f.stamp.ChangedNS++
		f.files["/etc/snmp/snmpd.conf"] = f.config(f.db)
		f.loaded = cloneDB(f.db)
		f.startDaemon()
		return nil, nil
	}
	return nil, ErrNative
}
func newSystemFixture(t *testing.T) *systemFixture {
	f := &systemFixture{t: t, dir: t.TempDir(), files: map[string][]byte{}, db: Database{"SNMP": {"LOCATION": {"Location": "public"}}, "SNMP_COMMUNITY": {}}, running: true, pid: 42, clock: 100, started: 50, wall: 1000, stamp: daemonFile{Device: 1, Inode: 2, ModifiedNS: 3, ChangedNS: 4}, persistent: []byte("engineBoots 1\n"), usm: map[string]SNMPUser{}}
	_ = os.Chmod(f.dir, 0700)
	f.loaded = cloneDB(f.db)
	f.files["/etc/snmp/snmpd.conf"] = f.config(f.db)
	f.files["/etc/supervisor/conf.d/supervisord.conf"] = []byte("supervisor")
	f.files[snmpTemplate] = []byte("snmp-template")
	f.files[snmpBootstrapPath] = []byte("snmp_location: public\n")
	f.files["/etc/sonic/sonic_version.yml"] = []byte("image")
	p := NativeProfile{ImageSHA256: digestForTest("image"), SNMPSHA256: digestForTest("snmp-template"), ConsumerSHA256: map[string]string{}}
	for _, c := range consumerPaths("snmp") {
		f.files[c.path] = []byte("consumer:" + c.key)
		if c.key == "snmp-supervisor-template" {
			f.files[c.path] = []byte("supervisor-template")
		}
		p.ConsumerSHA256[c.key] = digestForTest(string(f.files[c.path]))
	}
	f.files[profileFile], _ = json.Marshal(p)
	installFixtureSuite(f.files, p)
	f.files["/etc/sonic/config_db.json"], _ = json.Marshal(f.db)
	n := &Native{BeforePublication: func(context.Context) error { return nil }, WithRecovery: func(ctx context.Context, fn func(context.Context) error) error { return fn(ctx) }, Load: func(context.Context) (Database, error) { return cloneDB(f.db), nil }, CAS: func(_ context.Context, _, after Database) error { f.db = cloneDB(after); return nil }, Save: func(context.Context) error { f.files["/etc/sonic/config_db.json"], _ = json.Marshal(f.db); return nil }, WithMutation: func(_ context.Context, fn func() error) error { return fn() }, Run: f.run, ReadFile: func(path string) ([]byte, error) {
		b, ok := f.files[path]
		if !ok {
			return nil, os.ErrNotExist
		}
		return b, nil
	}, WriteFile: func(path string, data []byte, mode os.FileMode) error {
		if path == snmpBootstrapPath && mode != 0600 {
			t.Fatal("bootstrap credential permissions")
		}
		f.files[path] = append([]byte(nil), data...)
		return nil
	}, bootNow: func() (bootClock, error) { return bootClock{ID: "test-boot", Seconds: f.clock}, nil }}
	n.Run = func(ctx context.Context, args []string, input []byte) ([]byte, error) {
		if b, ok := fixtureRecoveryUnit(args); ok {
			return b, nil
		}
		return f.run(ctx, args, input)
	}
	n.SNMPExchange = func(ctx context.Context, packet []byte) ([]byte, error) {
		var v3 snmpV3Message
		if _, e := asn1.Unmarshal(packet, &v3); e == nil && v3.Version == 3 {
			agent := &fakeUSMAgent{engineID: []byte{0x80, 0, 0x1f, 0x88, 0x80, 9}, boots: 1, time: 10, users: f.usm, location: f.loaded["SNMP"]["LOCATION"]["Location"], contact: "contact"}
			return agent.exchange(ctx, packet)
		}
		var req snmpMessage
		if _, e := asn1.Unmarshal(packet, &req); e != nil {
			return nil, ErrNative
		}
		if f.loaded["SNMP_COMMUNITY"][string(req.Community)] == nil {
			return nil, ErrNative
		}
		body, _ := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: req.PDU.Bytes})
		var pdu snmpPDU
		_, _ = asn1.Unmarshal(body, &pdu)
		pdu.Variables[0].Value = asn1.RawValue{Tag: asn1.TagOctetString, Bytes: []byte(f.loaded["SNMP"]["LOCATION"]["Location"])}
		pdu.Variables[1].Value = asn1.RawValue{Tag: asn1.TagOctetString, Bytes: []byte("contact")}
		body, _ = asn1.Marshal(pdu)
		var seq asn1.RawValue
		_, _ = asn1.Unmarshal(body, &seq)
		return asn1.Marshal(snmpMessage{Version: 1, Community: req.Community, PDU: asn1.RawValue{Class: 2, Tag: 2, IsCompound: true, Bytes: seq.Bytes}})
	}
	f.n = n
	var err error
	f.engine, err = NewEngine(f.dir, n)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestSystemActivationReceiptSurvivesClockStepsAndAgentRestart(t *testing.T) {
	f := newSystemFixture(t)
	q := f.request(SNMP{Location: "public"})
	initial, err := f.engine.Get(t.Context(), q, "read")
	if err != nil || initial.RuntimeVerified {
		t.Fatal("unproven adoption must not infer daemon load from wall time")
	}
	if result, err := f.engine.Ensure(t.Context(), q, "writer"); err != nil || !result.Ready() {
		t.Fatal("qualified activation failed", err)
	}
	for _, offset := range []float64{-86400, 86400} {
		f.wall = offset
		restart, err := NewEngine(f.dir, f.n)
		if err != nil {
			t.Fatal(err)
		}
		result, err := restart.Get(t.Context(), q, "fresh")
		if err != nil || !result.Ready() {
			t.Fatal("clock step invalidated unchanged boot/process/file receipt")
		}
	}
	f.stamp.ChangedNS++
	result, err := f.engine.Get(t.Context(), q, "read")
	if err != nil || result.RuntimeVerified {
		t.Fatal("unrestarted file rewrite obtained native readiness")
	}
	files, _ := os.ReadDir(f.n.stateDir)
	for _, file := range files {
		data, _ := os.ReadFile(filepath.Join(f.n.stateDir, file.Name()))
		if bytes.Contains(data, []byte("configDigest")) || bytes.Contains(data, []byte(f.evidence().ConfigDigest)) {
			t.Fatal("credential-derived digest persisted")
		}
	}
}

func TestStoppedSNMPContainerRecoversThroughGetEnsureAndRestart(t *testing.T) {
	f := newSystemFixture(t)
	f.running = false
	q := f.request(SNMP{Location: "public"})
	result, err := f.engine.Get(t.Context(), q, "read")
	if err != nil || result.RuntimeVerified {
		t.Fatal("qualified stopped service must be a negative observation, not an error", err)
	}
	f.failRestart = true
	if _, err = f.engine.Ensure(t.Context(), q, "writer"); err == nil {
		t.Fatal("interrupted service restart succeeded")
	}
	f.failRestart = false
	restarted := *f.n
	restarted.stateDir = ""
	f.n = &restarted
	f.engine, err = NewEngine(f.dir, f.n)
	if err != nil {
		t.Fatal(err)
	}
	if result, err = f.engine.Get(t.Context(), q, "read"); err != nil || result.RuntimeVerified {
		t.Fatal("stopped-after-dispatch state cannot reach recovery", err)
	}
	if result, err = f.engine.Ensure(t.Context(), q, "writer"); err != nil || !result.Ready() {
		t.Fatal("new agent did not recover stopped consumer", err)
	}
}

func TestStoppedUnknownConsumerNeverStarts(t *testing.T) {
	f := newSystemFixture(t)
	f.running = false
	f.files["/usr/sbin/snmpd"] = []byte("unqualified daemon")
	q := f.request(SNMP{Location: "public"})
	if _, err := f.engine.Get(t.Context(), q, "read"); err == nil {
		t.Fatal("unknown stopped container was treated as recoverable")
	}
	if _, err := f.engine.Ensure(t.Context(), q, "writer"); err == nil {
		t.Fatal("unknown stopped consumer accepted for activation")
	}
	if f.restarts != 0 {
		t.Fatal("unqualified image inputs were started")
	}
}

func TestEmptyCommunityRemovalNeedsNewProcessEvenAfterClockJump(t *testing.T) {
	f := newSystemFixture(t)
	old := f.request(SNMP{Location: "public", Community: Credential("retired-fixture-secret")})
	if result, err := f.engine.Ensure(t.Context(), old, "writer"); err != nil || !result.Ready() {
		t.Fatal(err)
	}
	q := f.request(SNMP{Location: "public"})
	f.db["SNMP_COMMUNITY"] = map[string]map[string]string{}
	f.files["/etc/sonic/config_db.json"], _ = json.Marshal(f.db)
	f.files["/etc/snmp/snmpd.conf"] = f.config(f.db)
	f.files[snmpBootstrapPath], _ = snmpBootstrap(*q.System.SNMP)
	f.stamp.ChangedNS++
	for _, wall := range []float64{100000, -100000} {
		f.wall = wall
		result, err := f.engine.Get(t.Context(), q, "read")
		if err != nil || !result.ConfigurationVerified || !result.PersistenceVerified || result.RuntimeVerified {
			t.Fatal("wall step certified unrestarted credential removal")
		}
	}
	if f.loaded["SNMP_COMMUNITY"]["retired-fixture-secret"] == nil {
		t.Fatal("fixture no longer represents stale daemon credentials")
	}
}
