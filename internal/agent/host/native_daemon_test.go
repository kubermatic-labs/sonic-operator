// SPDX-License-Identifier: Apache-2.0
package host

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func installedSNMPEvidence() daemonEvidence {
	return daemonEvidence{PID: 42, BootID: "test-boot", File: daemonFile{Device: 1, Inode: 2, ModifiedNS: 3, ChangedNS: 4}, Arguments: []string{"/usr/sbin/snmpd", "-f", "-LS0-2d", "-u", "Debian-snmp", "-g", "Debian-snmp", "-I", "-smux", "mteTrigger", "mteTriggerConf", "ifTable", "ifXTable", "inetCidrRouteTable", "ipCidrRouteTable", "ip", "disk_hw", "-p", "/run/snmpd.pid"}, StartUptime: 648, ObservedWall: 1791176894.0759254, ObservedUptime: 5888.727178549, ConfigModified: 1791171653.1440194, ConfigChanged: 1791171653.1440194, ConfigDigest: digestForTest("generated"), EnvironmentClean: true, AuxiliaryClean: true}
}
func evidenceReceipt(v daemonEvidence) *daemonReceipt {
	return &daemonReceipt{BootID: v.BootID, PID: v.PID, StartUptime: v.StartUptime, File: v.File}
}
func TestInstalledSNMPDefaultConfigAndFractionalBootEpoch(t *testing.T) {
	v := installedSNMPEvidence()
	if !daemonConfigLoaded("snmp", v, []byte("generated"), evidenceReceipt(v)) {
		t.Fatal("actual default-config argv and fractional boot epoch were rejected")
	}
	for _, mutate := range []func(*daemonEvidence){func(v *daemonEvidence) { v.Arguments = append(v.Arguments, "-C") }, func(v *daemonEvidence) { v.Arguments = append(v.Arguments, "-c", "/other.conf") }, func(v *daemonEvidence) { v.File.ChangedNS++ }, func(v *daemonEvidence) { v.EnvironmentClean = false }, func(v *daemonEvidence) { v.AuxiliaryClean = false }, func(v *daemonEvidence) { v.ConfigDigest = "wrong" }} {
		bad := installedSNMPEvidence()
		mutate(&bad)
		if daemonConfigLoaded("snmp", bad, []byte("generated"), evidenceReceipt(v)) {
			t.Fatal("unproven daemon configuration reported loaded")
		}
	}
}
func TestNTPRuntimeMustConsumeTheDeclaredGeneratedFile(t *testing.T) {
	v := installedSNMPEvidence()
	v.Arguments = []string{"/usr/sbin/ntpd", "-p", "/run/ntpd.pid", "-c", "/etc/ntpsec/ntp.conf", "-x", "-N", "-u", "ntpsec:ntpsec"}
	if !daemonConfigLoaded("ntpsec", v, []byte("generated"), evidenceReceipt(v)) {
		t.Fatal("installed ntpsec wrapper argv rejected")
	}
	v.Arguments[4] = "/run/ntpsec/ntp.conf.dhcp"
	if daemonConfigLoaded("ntpsec", v, []byte("generated"), evidenceReceipt(v)) {
		t.Fatal("DHCP config override was mistaken for desired input")
	}
	v.Arguments = []string{"/usr/sbin/chronyd", "-F", "1"}
	if !daemonConfigLoaded("chrony", v, []byte("generated"), evidenceReceipt(v)) {
		t.Fatal("installed chrony argv rejected")
	}
	v.Arguments = append(v.Arguments, "-f", "/other.conf")
	if daemonConfigLoaded("chrony", v, []byte("generated"), evidenceReceipt(v)) {
		t.Fatal("chrony override was ignored")
	}
}

func TestDaemonReceiptIgnoresRealtimeStepsButRejectsUnrestartedFile(t *testing.T) {
	v := installedSNMPEvidence()
	receipt := evidenceReceipt(v)
	for _, step := range []float64{-86400, 86400} {
		current := v
		current.ObservedWall += step
		if !daemonConfigLoaded("snmp", current, []byte("generated"), receipt) {
			t.Fatal("wall adjustment invalidated unchanged causal receipt")
		}
		current.File.ChangedNS++
		if daemonConfigLoaded("snmp", current, []byte("generated"), receipt) {
			t.Fatal("new empty-community file accepted without a new daemon")
		}
	}
}

func TestNativeMappedLibraryUsesBytesAcrossOverlayDevices(t *testing.T) {
	dir := t.TempDir()
	proc := filepath.Join(dir, "proc")
	root := filepath.Join(proc, "root")
	for _, path := range []string{filepath.Join(proc, "map_files"), filepath.Join(root, "usr/lib/x86_64-linux-gnu")} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(proc, "maps"), "1000-2000 r-xp 00000000 08:03 424996 /usr/lib/x86_64-linux-gnu/libnetsnmp.so.40.2.0\n")
	write(filepath.Join(root, "usr/lib/x86_64-linux-gnu/libnetsnmp.so.40"), "qualified-library-fixture")
	write(filepath.Join(proc, "map_files/1000-2000"), "qualified-library-fixture")
	definitions := strings.Split(nativeDaemonProbe, "\ntry:\n")[0]
	check := func(want string) {
		t.Helper()
		cmd := exec.Command("python3", "-c", definitions+"\nprint(mapped_library_matches(Path(sys.argv[1]),Path(sys.argv[1])/'root'))", proc)
		out, err := cmd.CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) != want {
			t.Fatal("mapped library qualification did not match actual bytes")
		}
	}
	check("True")
	write(filepath.Join(proc, "map_files/1000-2000"), "old-loaded-library-fixture")
	check("False")
	write(filepath.Join(proc, "map_files/1000-2000"), "qualified-library-fixture")
	write(filepath.Join(proc, "maps"), "1000-2000 r-xp 00000000 08:03 424996 /usr/lib/x86_64-linux-gnu/libnetsnmp.so.40.2.0 (deleted)\n")
	check("False")
}

func TestClockStepCannotProveAnUnrestartedEmptyCommunityConfig(t *testing.T) {
	v := installedSNMPEvidence()
	v.StartUptime = 100
	v.ObservedUptime = 300
	v.ObservedWall = 1420
	v.ConfigModified = 1150
	v.ConfigChanged = 1150
	// Daemon started at realtime 1100, file changed at 1150, clock then advanced
	// by 120. The old reconstructed start (1220) falsely accepts the new file.
	if daemonConfigLoaded("snmp", v, []byte("generated")) {
		t.Fatal("wall-clock step certified an unchanged process with retired credentials")
	}
}
