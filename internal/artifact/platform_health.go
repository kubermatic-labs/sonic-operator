// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
)

// Read metadata and bytes without importing or instantiating hardware classes.
const packageHashProbe = `import hashlib,importlib.util,json,marshal,pathlib,re,sys,stat
root=pathlib.Path(sys.argv[1])
if root.resolve()!=root: raise RuntimeError('untrusted package root')
names={'__init__','chassis','component','eeprom','fan','fan_drawer','platform','psu','sfp','thermal'}
files={}
for directory in [root/'sonic_platform',root/'sonic_platform-1.0.dist-info']:
 if not directory.is_dir() or directory.is_symlink(): raise RuntimeError('missing package tree')
 for p in directory.rglob('*'):
  relative=str(p.relative_to(root))
  if p.is_symlink(): raise RuntimeError('package link')
  if p.is_dir():
   if relative!='sonic_platform/__pycache__': raise RuntimeError('unrecorded package directory')
   continue
  info=p.stat()
  if not stat.S_ISREG(info.st_mode) or info.st_size>1024*1024: raise RuntimeError('unqualified package file')
  data=p.read_bytes()
  if len(data)>1024*1024: raise RuntimeError('package member too large')
  if relative in {'sonic_platform/'+n+'.py' for n in names} or relative in {'sonic_platform-1.0.dist-info/'+n for n in ['METADATA','WHEEL','top_level.txt']}:
   files[relative]=hashlib.sha256(data).hexdigest();continue
  if relative in {'sonic_platform-1.0.dist-info/'+n for n in ['RECORD','INSTALLER','REQUESTED','direct_url.json']}: continue
  match=re.fullmatch(r'sonic_platform/__pycache__/([a-z_]+)\.cpython-\d+(\.opt-[12])?\.pyc',relative)
  if match is None or match.group(1) not in names or data[:4]!=importlib.util.MAGIC_NUMBER: raise RuntimeError('unrecorded package member')
  source=root/'sonic_platform'/(match.group(1)+'.py')
  cached=marshal.loads(data[16:])
  if cached!=compile(source.read_bytes(),cached.co_filename,'exec',optimize=int(match.group(2)[-1]) if match.group(2) else 0): raise RuntimeError('stale executable bytecode')
print(json.dumps({'root':str(root),'files':files}))`

func verifyPackageHashes(raw []byte, root string, members map[string][]byte) error {
	var observed struct {
		Root  string            `json:"root"`
		Files map[string]string `json:"files"`
	}
	if Decode(raw, &observed) != nil || observed.Root != root {
		return fmt.Errorf("platform distribution location changed")
	}
	for name, expected := range members {
		if strings.HasSuffix(name, "/RECORD") {
			continue
		}
		if observed.Files[name] != Digest(expected) {
			return fmt.Errorf("installed platform distribution differs from generating wheel")
		}
	}
	// Extra source modules can execute during package imports; do not silently
	// accept a module absent from the declared generating wheel.
	for name := range observed.Files {
		if _, ok := members[name]; !ok {
			return fmt.Errorf("unowned platform package member")
		}
	}
	return nil
}
func verifyDaemonStatus(raw []byte, names []string) error {
	expected := map[string]bool{}
	for _, name := range names {
		expected[name] = false
	}
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		fields := bytes.Fields(line)
		if len(fields) < 2 {
			return fmt.Errorf("invalid native daemon status")
		}
		name := string(fields[0])
		if _, ok := expected[name]; !ok {
			return fmt.Errorf("unexpected daemon in bounded status response")
		}
		if string(fields[1]) != "RUNNING" {
			return fmt.Errorf("native platform daemon is not running")
		}
		expected[name] = true
	}
	for _, seen := range expected {
		if !seen {
			return fmt.Errorf("native platform daemon missing")
		}
	}
	return nil
}
func (n *Native) platformHealth(ctx context.Context, j *journal) error {
	for _, f := range j.Files {
		p, _, err := Destination(f.Slot)
		if err == nil && p == "" {
			if err := n.consumerBaseline(ctx); err != nil {
				return err
			}
			break
		}
	}
	containers := map[string]bool{}
	hasWheel := false
	for _, f := range j.Files {
		p, _, err := Destination(f.Slot)
		if err != nil || p != "" {
			continue
		}
		hash := f.Hash
		if j.Phase == "RollingBack" {
			if !f.Existed {
				continue
			}
			hash = f.PreviousHash
		}
		if f.Slot == "PlatformWheel" {
			data, _, err := n.Engine.read(f.Path)
			if err != nil || Digest(data) != hash {
				return fmt.Errorf("platform wheel not verified")
			}
			members, err := wheelMembers(data)
			if err != nil {
				return err
			}
			host, err := n.command(ctx, "/usr/bin/python3", "-I", "-S", "-B", "-c", packageHashProbe, "/usr/local/lib/python3.13/dist-packages")
			if err != nil {
				return err
			}
			if err := verifyPackageHashes(host, "/usr/local/lib/python3.13/dist-packages", members); err != nil {
				return err
			}
			pmon, err := n.command(ctx, "/usr/bin/docker", "exec", "pmon", "python3", "-I", "-S", "-B", "-c", packageHashProbe, "/usr/local/lib/python3.11/dist-packages")
			if err != nil {
				return err
			}
			if err := verifyPackageHashes(pmon, "/usr/local/lib/python3.11/dist-packages", members); err != nil {
				return err
			}
			hasWheel = true
			containers["pmon"] = true
			continue
		}
		if _, module := platformModules[f.Slot]; module {
			continue
		} // verified through wheel package hashes
		runtime := n.Engine.Policy.Runtime[f.Slot]
		if !runtimePath(f.Slot, runtime) {
			return fmt.Errorf("unqualified platform runtime path")
		}
		out, err := n.command(ctx, "/usr/bin/docker", "exec", runtime.Container, "sha256sum", "--", runtime.Path)
		fields := bytes.Fields(out)
		if err != nil || len(fields) < 1 || string(fields[0]) != hash {
			return fmt.Errorf("platform native consumer differs from declared file")
		}
		containers[runtime.Container] = true
		if f.Slot == "SAIProfile" {
			generated, err := n.command(ctx, "/usr/bin/docker", "exec", "syncd", "sha256sum", "--", "/etc/sai.d/sai.profile")
			fields := bytes.Fields(generated)
			if err != nil || len(fields) < 1 || string(fields[0]) != hash {
				return fmt.Errorf("generated SAI profile differs from owned input")
			}
			pid, err := n.command(ctx, "/usr/bin/docker", "exec", "syncd", "supervisorctl", "pid", "syncd")
			number, parseErr := strconv.Atoi(strings.TrimSpace(string(pid)))
			if err != nil || parseErr != nil || number < 1 {
				return fmt.Errorf("syncd consumer process missing")
			}
			args, err := n.command(ctx, "/usr/bin/docker", "exec", "syncd", "cat", "/proc/"+strconv.Itoa(number)+"/cmdline")
			if err != nil {
				return err
			}
			if err := verifySAICommand(args); err != nil {
				return err
			}
		}
	}
	for _, f := range j.Files {
		if _, module := platformModules[f.Slot]; module && !hasWheel {
			return fmt.Errorf("host modules lack verified wheel runtime")
		}
	}
	if hasWheel {
		if err := n.verifyProvenance(ctx, j); err != nil {
			return err
		}
	}
	// The observed init/dependency/lm-sensors/pcied jobs legitimately exit. Only
	// exact persistent native daemons participate in the runtime health contract.
	for container := range containers {
		names := []string{"syncd", "rsyslogd", "supervisor-proc-exit-listener"}
		if container == "pmon" {
			names = []string{"xcvrd", "psud", "syseepromd", "stormond", "rsyslogd", "supervisor-proc-exit-listener"}
		}
		args := append([]string{"exec", container, "supervisorctl", "status"}, names...)
		raw, err := n.command(ctx, "/usr/bin/docker", args...)
		if err != nil {
			return fmt.Errorf("native platform daemon probe failed")
		}
		if err := verifyDaemonStatus(raw, names); err != nil {
			return err
		}
	}
	return nil
}
