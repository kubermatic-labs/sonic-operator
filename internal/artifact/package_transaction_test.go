// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestPackageRepairAfterMissingRecordAndPartialUninstall(t *testing.T) {
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	state := filepath.Join(root, "state")
	pkg := filepath.Join(root, "lib")
	os.MkdirAll(pkg, 0700)
	before := packageSnapshot{Version: 1, Entries: map[string]packageEntry{"sonic_platform/chassis.py": {Data: []byte("old code"), Mode: 0644}, "sonic_platform-1.0.dist-info/METADATA": {Data: []byte("old metadata"), Mode: 0644}, "sonic_platform-1.0.dist-info/RECORD": {Data: []byte("old record"), Mode: 0644}}}
	candidate := packageSnapshot{Version: 1, Entries: map[string]packageEntry{"sonic_platform/chassis.py": {Data: []byte("new code"), Mode: 0644}, "sonic_platform-1.0.dist-info/METADATA": {Data: []byte("new metadata"), Mode: 0644}, "sonic_platform-1.0.dist-info/RECORD": {Data: []byte("new record"), Mode: 0644}}}
	for name, entry := range before.Entries {
		p := filepath.Join(pkg, name)
		os.MkdirAll(filepath.Dir(p), 0700)
		os.WriteFile(p, entry.Data, os.FileMode(entry.Mode))
	}
	packet, _ := json.Marshal(map[string]any{"before": before, "candidate": candidate, "root": pkg, "state": state})
	script := packageTransactionScript + `
r=json.load(sys.stdin)
def interrupt(name):
 if name.endswith('/METADATA'):
  (Path(r['root'])/'sonic_platform-1.0.dist-info/RECORD').unlink(missing_ok=True)
  (Path(r['root'])/'sonic_platform/chassis.py').unlink(missing_ok=True)
  os._exit(72)
transaction(r['root'],r['state'],'a'*32,'apply',r['before'],r['candidate'],interrupt)
`
	command := exec.Command("python3", "-I", "-B", "-c", script)
	command.Stdin = bytes.NewReader(packet)
	if err := command.Run(); err == nil {
		t.Fatal("fault did not interrupt package mutation")
	}
	// A new process repairs from the protected pair, not the broken live RECORD.
	restore := packageTransactionScript + "\nr=json.load(sys.stdin)\ntransaction(r['root'],r['state'],'a'*32,'restore',r['before'],r['candidate'])\n"
	command = exec.Command("python3", "-I", "-B", "-c", restore)
	command.Stdin = bytes.NewReader(packet)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("repair failed: %v %s", err, out)
	}
	for name, entry := range before.Entries {
		actual, err := os.ReadFile(filepath.Join(pkg, name))
		if err != nil || !bytes.Equal(actual, entry.Data) {
			t.Fatalf("before package not restored: %s", name)
		}
	}
}

func TestPackageRepairWaitsForSurvivingInstallerLock(t *testing.T) {
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	state := filepath.Join(root, "state")
	pkg := filepath.Join(root, "lib")
	os.MkdirAll(state, 0700)
	os.MkdirAll(pkg, 0700)
	marker := filepath.Join(root, "held")
	holder := exec.Command("python3", "-I", "-B", "-c", "import fcntl,time,pathlib,sys\nf=open(sys.argv[1],'w');fcntl.flock(f,fcntl.LOCK_EX);pathlib.Path(sys.argv[2]).write_text('held');time.sleep(.4)", filepath.Join(state, "lock"), marker)
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	defer holder.Wait()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("lock holder did not start")
		}
		time.Sleep(time.Millisecond)
	}
	snapshot := packageSnapshot{Version: 1, Entries: map[string]packageEntry{}}
	packet, _ := json.Marshal(map[string]any{"before": snapshot, "candidate": snapshot, "root": pkg, "state": state})
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", "-I", "-B", "-c", packageTransactionScript+"\nr=json.load(sys.stdin)\ntransaction(r['root'],r['state'],'b'*32,'restore',r['before'],r['candidate'])")
	cmd.Stdin = bytes.NewReader(packet)
	if err := cmd.Run(); err == nil {
		t.Fatal("repair bypassed surviving installer lock")
	}
}

func TestRepairSerializesWithInstallerSurvivingClientCancellation(t *testing.T) {
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	pkg := filepath.Join(root, "lib")
	state := filepath.Join(root, "state")
	os.MkdirAll(pkg, 0700)
	before := packageSnapshot{Version: 1, Entries: map[string]packageEntry{"sonic_platform/chassis.py": {Data: []byte("before"), Mode: 0644}, "sonic_platform-1.0.dist-info/METADATA": {Data: []byte("before metadata"), Mode: 0644}, "sonic_platform-1.0.dist-info/RECORD": {Data: []byte("before receipt"), Mode: 0644}}}
	candidate := packageSnapshot{Version: 1, Entries: map[string]packageEntry{"sonic_platform/chassis.py": {Data: []byte("candidate"), Mode: 0644}, "sonic_platform-1.0.dist-info/METADATA": {Data: []byte("candidate metadata"), Mode: 0644}, "sonic_platform-1.0.dist-info/RECORD": {Data: []byte("candidate receipt"), Mode: 0644}}}
	for name, entry := range before.Entries {
		p := filepath.Join(pkg, name)
		os.MkdirAll(filepath.Dir(p), 0700)
		os.WriteFile(p, entry.Data, 0644)
	}
	marker, finished := filepath.Join(root, "held"), filepath.Join(root, "finished")
	packet, _ := json.Marshal(map[string]any{"root": pkg, "state": state, "before": before, "candidate": candidate, "marker": marker, "finished": finished})
	worker := packageTransactionScript + `
import time
r=json.loads(sys.argv[1])
def wait_after_metadata(name):
 if name.endswith('/METADATA'):
  Path(r['marker']).write_text('locked')
  time.sleep(.4)
transaction(r['root'],r['state'],'c'*32,'apply',r['before'],r['candidate'],wait_after_metadata)
Path(r['finished']).write_text('done')
`
	parent := `import subprocess,sys,time
p=subprocess.Popen([sys.executable,'-I','-B','-c',sys.argv[1],sys.argv[2]],start_new_session=True)
p.wait()
`
	ctx, cancel := context.WithCancel(context.Background())
	client := exec.CommandContext(ctx, "python3", "-I", "-B", "-c", parent, worker, string(packet))
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			client.Wait()
			t.Fatal("installer did not hold transaction fence")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	_ = client.Wait() // Docker-exec client dies; independent installer survives.
	repair := packageTransactionScript + "\nr=json.loads(sys.argv[1]);transaction(r['root'],r['state'],'c'*32,'restore',r['before'],r['candidate'])"
	started := time.Now()
	cmd := exec.Command("python3", "-I", "-B", "-c", repair, string(packet))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("serialized repair failed: %v %s", err, out)
	}
	if time.Since(started) < 200*time.Millisecond {
		t.Fatal("repair did not wait for surviving installer")
	}
	if _, err := os.Stat(finished); err != nil {
		t.Fatal("surviving installer did not finish before repair")
	}
	for name, entry := range before.Entries {
		data, _ := os.ReadFile(filepath.Join(pkg, name))
		if !bytes.Equal(data, entry.Data) {
			t.Fatalf("late installer overwrote repaired %s", name)
		}
	}
}
