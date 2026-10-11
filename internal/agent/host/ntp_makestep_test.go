// SPDX-License-Identifier: Apache-2.0
package host

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// chronyFixture models chronyd: conf.d is read only at start, and the daemon
// probe reports the makestep drop-in identity and digest.
type chronyFixture struct {
	t                    *testing.T
	n                    *Native
	engine               *Engine
	files                map[string][]byte
	stamps               map[string]daemonFile
	db                   Database
	pid, inode           int
	clock                float64
	restarts             int
	loadedStep           []byte
	loadedStepFileExists bool
}

func (f *chronyFixture) touch(path string) {
	f.inode++
	f.stamps[path] = daemonFile{Device: 1, Inode: uint64(f.inode), ModifiedNS: int64(f.inode), ChangedNS: int64(f.inode)}
}
func (f *chronyFixture) evidence() daemonEvidence {
	v := daemonEvidence{PID: f.pid, BootID: "test-boot", File: f.stamps["/etc/chrony/chrony.conf"], Arguments: []string{"/usr/sbin/chronyd", "-F", "1"}, StartUptime: f.clock, ObservedUptime: f.clock + 1, ConfigDigest: digestForTest(string(f.files["/etc/chrony/chrony.conf"])), EnvironmentClean: true, AuxiliaryClean: true}
	if step, ok := f.files[chronyStepFile]; ok {
		stamp := f.stamps[chronyStepFile]
		v.StepFile, v.StepDigest = &stamp, digestForTest(string(step))
	}
	return v
}
func (f *chronyFixture) run(_ context.Context, args []string, input []byte) ([]byte, error) {
	if b, ok := fixtureRecoveryUnit(args); ok {
		return b, nil
	}
	joined := strings.Join(args, " ")
	switch {
	case joined == "sonic-cfggen -d --print-data":
		return json.Marshal(f.db)
	case len(args) == 5 && args[0] == "sonic-cfggen" && args[4] == chronyTemplate:
		var db map[string]json.RawMessage
		if json.Unmarshal(input, &db) != nil {
			return nil, ErrNative
		}
		return append([]byte("chrony:"), db["NTP_SERVER"]...), nil
	case joined == "chronyd -p -f /dev/stdin", joined == "systemctl is-active chrony.service":
		return []byte("active"), nil
	case joined == "chronyc -c -N sources":
		var rows []string
		for server := range f.db["NTP_SERVER"] {
			rows = append(rows, "^,*,"+server)
		}
		return []byte(strings.Join(rows, "\n")), nil
	case len(args) == 4 && args[0] == "python3" && args[2] == nativeDaemonProbe && args[3] == "chrony":
		return json.Marshal(f.evidence())
	case joined == "systemctl restart chrony.service":
		f.restarts++
		f.pid++
		f.clock++
		f.loadedStep, f.loadedStepFileExists = f.files[chronyStepFile]
		return nil, nil
	}
	return nil, ErrNative
}

func newChronyFixture(t *testing.T) *chronyFixture {
	f := &chronyFixture{t: t, files: map[string][]byte{}, stamps: map[string]daemonFile{}, db: Database{"NTP": {"global": {"admin_state": "enabled", "dhcp": "enabled", "server_role": "disabled", "src_intf": "eth0", "vrf": "default", "authentication": "disabled"}}, "NTP_SERVER": {"10.0.0.1": {"NULL": "NULL"}}}, pid: 7, clock: 100}
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	f.files["/etc/sonic/sonic_version.yml"] = []byte("image")
	f.files[chronyTemplate] = []byte("chrony")
	p := NativeProfile{ImageSHA256: digestForTest("image"), SNMPSHA256: digestForTest("snmp"), ConsumerSHA256: map[string]string{}}
	for _, c := range consumerPaths("snmp") {
		p.ConsumerSHA256[c.key] = digestForTest(c.key)
	}
	for _, c := range consumerPaths("chrony") {
		f.files[c.path] = []byte(c.key)
	}
	installFixtureSuite(f.files, p)
	f.files["/etc/sonic/config_db.json"], _ = json.Marshal(f.db)
	f.files["/etc/chrony/chrony.conf"] = []byte(`chrony:{"10.0.0.1":{"NULL":"NULL"}}`)
	f.touch("/etc/chrony/chrony.conf")
	f.n = &Native{BeforePublication: func(context.Context) error { return nil }, WithRecovery: func(ctx context.Context, fn func(context.Context) error) error { return fn(ctx) }, Load: func(context.Context) (Database, error) { return cloneDB(f.db), nil }, CAS: func(_ context.Context, _, after Database) error { f.db = cloneDB(after); return nil }, Save: func(context.Context) error { f.files["/etc/sonic/config_db.json"], _ = json.Marshal(f.db); return nil }, WithMutation: func(_ context.Context, fn func() error) error { return fn() }, Run: f.run, ReadFile: func(path string) ([]byte, error) {
		b, ok := f.files[path]
		if !ok {
			return nil, os.ErrNotExist
		}
		return b, nil
	}, WriteFile: func(path string, data []byte, _ os.FileMode) error {
		f.files[path] = append([]byte(nil), data...)
		f.touch(path)
		return nil
	}, RemoveFile: func(path string) error {
		delete(f.files, path)
		delete(f.stamps, path)
		return nil
	}, bootNow: func() (bootClock, error) { return bootClock{ID: "test-boot", Seconds: f.clock}, nil }}
	var err error
	if f.engine, err = NewEngine(dir, f.n); err != nil {
		t.Fatal(err)
	}
	return f
}
func ntpRequest(revision string, m *NTPMakeStep) Request {
	return Request{Kind: "System", Owner: "system-owner", Target: "switch", Revision: revision, System: &System{NTP: &NTP{Servers: []string{"10.0.0.1"}, MakeStep: m}}}
}

func TestChronyMakeStepDropInLifecycle(t *testing.T) {
	f := newChronyFixture(t)
	// The manual hotfix found on the fleet: same path, different bytes.
	f.files[chronyStepFile] = []byte("# Z9100 RTC is not readable by hwclock; step at boot instead of slewing for days.\nmakestep 1 3\n")
	f.touch(chronyStepFile)
	q := ntpRequest("1", &NTPMakeStep{ThresholdSeconds: 1, Limit: 3})
	if result, err := f.engine.Get(t.Context(), q, "read"); err != nil || result.PersistenceVerified || result.RuntimeVerified {
		t.Fatal("unowned drop-in bytes must not be adopted as declared", err)
	}
	if result, err := f.engine.Ensure(t.Context(), q, "writer"); err != nil || !result.Ready() {
		t.Fatal("declared makestep did not converge", err)
	}
	if string(f.loadedStep) != string(chronyStepContent(q.System.NTP.MakeStep)) || f.restarts != 1 {
		t.Fatal("chronyd was not restarted with the canonical drop-in")
	}

	// Rewriting the drop-in without a restart is not what chronyd loaded.
	f.files[chronyStepFile] = chronyStepContent(&NTPMakeStep{ThresholdSeconds: 1, Limit: 3})
	f.touch(chronyStepFile)
	if result, err := f.engine.Get(t.Context(), q, "read"); err != nil || !result.PersistenceVerified || result.RuntimeVerified {
		t.Fatal("unrestarted drop-in rewrite certified as loaded", err)
	}

	q = ntpRequest("2", &NTPMakeStep{ThresholdSeconds: 10, Limit: 5})
	if result, err := f.engine.Ensure(t.Context(), q, "writer"); err != nil || !result.Ready() || !strings.Contains(string(f.loadedStep), "makestep 10 5\n") {
		t.Fatal("changed makestep did not converge", err)
	}

	q = ntpRequest("3", nil)
	if result, err := f.engine.Ensure(t.Context(), q, "writer"); err != nil || !result.Ready() {
		t.Fatal("omitted makestep did not remove the drop-in", err)
	}
	if _, ok := f.files[chronyStepFile]; ok || f.loadedStepFileExists {
		t.Fatal("removed drop-in is still installed or loaded")
	}
}

func TestChronyStepEvidenceMatchesDeclaration(t *testing.T) {
	m := &NTPMakeStep{ThresholdSeconds: 1, Limit: 3}
	stamp := daemonFile{Device: 1, Inode: 9}
	with := daemonEvidence{StepFile: &stamp, StepDigest: digestForTest(string(chronyStepContent(m)))}
	for _, tc := range []struct {
		name string
		mode string
		m    *NTPMakeStep
		v    daemonEvidence
		ok   bool
	}{
		{"declared-present", "chrony", m, with, true},
		{"declared-absent", "chrony", m, daemonEvidence{}, false},
		{"declared-other-bytes", "chrony", &NTPMakeStep{ThresholdSeconds: 2, Limit: 3}, with, false},
		{"omitted-absent", "chrony", nil, daemonEvidence{}, true},
		{"omitted-present", "chrony", nil, with, false},
		{"other-daemon", "snmp", nil, daemonEvidence{}, true},
	} {
		if chronyStepLoaded(tc.mode, ntpRequest("1", tc.m), tc.v) != tc.ok {
			t.Fatalf("%s: wrong step evidence decision", tc.name)
		}
	}
	v := installedSNMPEvidence()
	v.Arguments = []string{"/usr/sbin/chronyd", "-F", "1"}
	v.StepFile = &stamp
	receipt := evidenceReceipt(v)
	receipt.StepFile = &daemonFile{Device: 1, Inode: 9}
	if !daemonConfigLoaded("chrony", v, []byte("generated"), receipt) {
		t.Fatal("unchanged drop-in identity rejected")
	}
	for _, r := range []*daemonFile{nil, {Device: 1, Inode: 10}} {
		receipt.StepFile = r
		if daemonConfigLoaded("chrony", v, []byte("generated"), receipt) {
			t.Fatal("drop-in changed since activation certified as loaded")
		}
	}
}

func TestMakeStepValidation(t *testing.T) {
	ok := System{NTP: &NTP{Servers: []string{"10.0.0.1"}, MakeStep: &NTPMakeStep{ThresholdSeconds: 1, Limit: 3}}}
	if ValidateSystem(ok) != nil || validateNTPImage(NativeProfile{NTPBackend: "chrony"}, ok.NTP) != nil {
		t.Fatal("valid makestep rejected")
	}
	if validateNTPImage(NativeProfile{NTPBackend: "ntpsec"}, ok.NTP) != ErrInvalid {
		t.Fatal("makestep accepted for the ntpsec backend")
	}
	for _, m := range []NTPMakeStep{{0, 3}, {86401, 3}, {1, 0}, {1, 11}, {1, -1}} {
		bad := System{NTP: &NTP{Servers: []string{}, MakeStep: &m}}
		if ValidateSystem(bad) != ErrInvalid {
			t.Fatalf("out-of-range makestep %+v accepted", m)
		}
	}
}

func TestProbeReportsOnlyTheOwnedChronyDropIn(t *testing.T) {
	root := t.TempDir()
	confd := filepath.Join(root, "etc/chrony/conf.d")
	if err := os.MkdirAll(confd, 0755); err != nil {
		t.Fatal(err)
	}
	definitions := strings.Split(nativeDaemonProbe, "\ntry:\n")[0]
	probe := func() string {
		t.Helper()
		out, err := exec.Command("python3", "-c", definitions+"\ntry:\n    s,d=chrony_step_file(Path(sys.argv[1]))\n    print('none' if s is None else d)\nexcept ValueError:\n    print('invalid')", root).CombinedOutput()
		if err != nil {
			t.Fatal(string(out))
		}
		return strings.TrimSpace(string(out))
	}
	if probe() != "none" {
		t.Fatal("absent drop-in reported")
	}
	content := chronyStepContent(&NTPMakeStep{ThresholdSeconds: 1, Limit: 3})
	path := filepath.Join(confd, "sonic-operator-makestep.conf")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}
	if probe() != digestForTest(string(content)) {
		t.Fatal("drop-in digest differs from the agent's canonical bytes")
	}
	_ = os.Remove(path)
	if err := os.Symlink(filepath.Join(root, "elsewhere"), path); err != nil {
		t.Fatal(err)
	}
	if probe() != "invalid" {
		t.Fatal("symlinked drop-in accepted")
	}
	_ = os.Remove(path)
	if err := os.WriteFile(path, []byte(strings.Repeat("#", 4097)), 0644); err != nil {
		t.Fatal(err)
	}
	if probe() != "invalid" {
		t.Fatal("oversized drop-in accepted")
	}
}
