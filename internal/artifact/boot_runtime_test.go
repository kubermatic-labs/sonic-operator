// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBootRuntimeProbeTracksIncarnationAndMissingInputs(t *testing.T) {
	root := t.TempDir()
	write := func(name, data string) {
		t.Helper()
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	config := "etc/supervisor/conf.d/supervisord.conf"
	write(config, "wrapped commands")
	write("usr/local/libexec/sonic-operator-platform-launch.py", "wrapper")
	write("var/lib/sonic-operator-platform/active.json", "manifest")
	write("proc/42/cmdline", "wrapped daemon\x00")
	stat := "42 (daemon name) " + strings.Repeat("0 ", 19) + "12345 "
	write("proc/42/stat", stat+"0")
	// Only the namespace and supervisor PID lookup are simulated; execute the
	// production Python fingerprint against real files, including absent proofs.
	script := "import subprocess\nsubprocess.check_output=lambda *a,**k:b'42'\n" + bootRuntimeProbe
	script = strings.NewReplacer("'/etc/", "'"+root+"/etc/", "'/usr/", "'"+root+"/usr/", "'/var/", "'"+root+"/var/", "'/proc", "'"+root+"/proc").Replace(script)
	probe := func() string {
		t.Helper()
		out, err := exec.Command("python3", "-I", "-B", "-c", script).CombinedOutput()
		if err != nil {
			t.Fatalf("probe: %v: %s", err, out)
		}
		got := strings.TrimSpace(string(out))
		if !shaPattern.MatchString(got) {
			t.Fatalf("invalid fingerprint: %q", got)
		}
		return got
	}
	first := probe()
	write("proc/42/stat", stat+"17")
	if probe() != first {
		t.Fatal("ordinary proc counters invalidated progress")
	}
	write("proc/42/stat", strings.Replace(stat, "12345", "12346", 1)+"17")
	if probe() == first {
		t.Fatal("PID reuse did not invalidate progress")
	}
	second := probe()
	if err := os.Remove(filepath.Join(root, config)); err != nil {
		t.Fatal(err)
	}
	if probe() == second {
		t.Fatal("missing generated configuration did not invalidate progress")
	}
	third := probe()
	write("var/lib/sonic-operator-platform/proofs/xcvrd.json", "new proof")
	if probe() == third {
		t.Fatal("changed launch proof did not invalidate progress")
	}
}
