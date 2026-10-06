// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPackageAtomicCrashIsRecoveredByFreshProcess(t *testing.T) {
	for _, phase := range []string{"created", "synced", "renamed"} {
		for _, member := range []string{"sonic_platform/chassis.py", "sonic_platform-1.0.dist-info/METADATA"} {
			t.Run(phase+"/"+member, func(t *testing.T) {
				root := t.TempDir()
				root, _ = filepath.EvalSymlinks(root)
				pkg := filepath.Join(root, "lib")
				state := filepath.Join(root, "state")
				os.MkdirAll(pkg, 0700)
				before := packageSnapshot{Version: 1, Entries: map[string]packageEntry{"sonic_platform/chassis.py": {Data: []byte("old code"), Mode: 0644}, "sonic_platform-1.0.dist-info/METADATA": {Data: []byte("old metadata"), Mode: 0644}, "sonic_platform-1.0.dist-info/RECORD": {Data: []byte("old receipt"), Mode: 0644}}}
				candidate := packageSnapshot{Version: 1, Entries: map[string]packageEntry{}}
				for name, entry := range before.Entries {
					p := filepath.Join(pkg, name)
					os.MkdirAll(filepath.Dir(p), 0700)
					os.WriteFile(p, entry.Data, 0644)
					candidate.Entries[name] = packageEntry{Data: append([]byte("new "), entry.Data...), Mode: 0644}
				}
				packet, _ := json.Marshal(map[string]any{"root": pkg, "state": state, "before": before, "candidate": candidate, "phase": phase, "member": member})
				script := packageTransactionScript + `
r=json.load(sys.stdin)
original_atomic,original_open,original_replace=atomic,os.open,os.replace
destination=None
def track(path,data,mode=0o600,**kwargs):
 global destination
 destination=path
 return original_atomic(path,data,mode,**kwargs)
def crash_open(path,flags,*args,**kwargs):
 fd=original_open(path,flags,*args,**kwargs)
 if flags & os.O_EXCL and r['phase']=='created' and str(destination).endswith(r['member']): os._exit(78)
 return fd
def crash_replace(source,target):
 if r['phase']=='synced' and str(target).endswith(r['member']): os._exit(78)
 original_replace(source,target)
 if r['phase']=='renamed' and str(target).endswith(r['member']): os._exit(78)
atomic,os.open,os.replace=track,crash_open,crash_replace
transaction(r['root'],r['state'],'d'*32,'apply',r['before'],r['candidate'])
`
				cmd := exec.Command("python3", "-I", "-B", "-c", script)
				cmd.Stdin = bytes.NewReader(packet)
				err := cmd.Run()
				exit, ok := err.(*exec.ExitError)
				if !ok || exit.ExitCode() != 78 {
					t.Fatalf("did not crash inside atomic %s: %v", phase, err)
				}
				restore := packageTransactionScript + "\nr=json.load(sys.stdin)\ntransaction(r['root'],r['state'],'d'*32,'restore',r['before'],r['candidate'])\n"
				cmd = exec.Command("python3", "-I", "-B", "-c", restore)
				cmd.Stdin = bytes.NewReader(packet)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("fresh recovery failed: %v %s", err, out)
				}
				for name, entry := range before.Entries {
					got, err := os.ReadFile(filepath.Join(pkg, name))
					if err != nil || !bytes.Equal(got, entry.Data) {
						t.Fatalf("unrestored %s", name)
					}
				}
				filepath.WalkDir(pkg, func(p string, d os.DirEntry, err error) error {
					if err == nil && !d.IsDir() && filepath.Ext(p) == ".tmp" {
						t.Errorf("owned temporary left behind: %s", p)
					}
					return err
				})
				if phase == "synced" && member == "sonic_platform/chassis.py" {
					foreign := filepath.Join(pkg, "sonic_platform/.package-foreign")
					os.WriteFile(foreign, []byte("unowned"), 0600)
					cmd = exec.Command("python3", "-I", "-B", "-c", restore)
					cmd.Stdin = bytes.NewReader(packet)
					if err := cmd.Run(); err == nil {
						t.Fatal("foreign package temporary accepted")
					}
					got, _ := os.ReadFile(foreign)
					if string(got) != "unowned" {
						t.Fatal("foreign package file removed")
					}
					os.Remove(foreign)
					staging := filepath.Join(pkg, ".sonic-operator-package-staging", strings.Repeat("d", 32))
					os.MkdirAll(staging, 0700)
					sum := sha256.Sum256([]byte(member))
					link := filepath.Join(staging, hex.EncodeToString(sum[:])+".tmp")
					outside := filepath.Join(root, "outside")
					os.WriteFile(outside, []byte("preserve"), 0600)
					os.Symlink(outside, link)
					cmd = exec.Command("python3", "-I", "-B", "-c", restore)
					cmd.Stdin = bytes.NewReader(packet)
					if err := cmd.Run(); err == nil {
						t.Fatal("symlink temporary accepted")
					}
					got, _ = os.ReadFile(outside)
					if string(got) != "preserve" {
						t.Fatal("symlink target changed")
					}
					if _, err := os.Lstat(link); err != nil {
						t.Fatal("untrusted temporary removed")
					}
				}
			})
		}
	}
}
