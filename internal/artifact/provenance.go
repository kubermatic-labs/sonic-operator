// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

const launcherProofProbe = `import hashlib,json,pathlib,sys
pid=int(sys.argv[1]);name=sys.argv[2]
if name not in ['xcvrd','psud','syseepromd','stormond']: raise RuntimeError('unknown daemon')
base=pathlib.Path('/var/lib/sonic-operator-platform')
p=json.loads((base/'proofs'/(name+'.json')).read_bytes())
argv=pathlib.Path('/proc/'+str(pid)+'/cmdline').read_bytes().rstrip(b'\0').split(b'\0')
expected=[b'/usr/bin/python3.11',b'-I',b'-S',b'/usr/local/libexec/sonic-operator-platform-launch.py',name.encode()]
if argv!=expected: raise RuntimeError('unqualified daemon argv')
if p['pid']!=pid or p['manifest']!=sys.argv[3]: raise RuntimeError('stale launch manifest')
if p['boot']!=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(): raise RuntimeError('old boot proof')
if p['startTicks']!=pathlib.Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split()[19]: raise RuntimeError('reused process')
if p['searchPath']!=['/usr/lib/python3.11','/usr/lib/python3.11/lib-dynload','/usr/local/lib/python3.11/dist-packages','/usr/lib/python3/dist-packages']: raise RuntimeError('unqualified import path')
if hashlib.sha256(pathlib.Path('/proc/'+str(pid)+'/exe').read_bytes()).hexdigest()!=sys.argv[4]: raise RuntimeError('interpreter changed')
if hashlib.sha256(pathlib.Path('/usr/local/libexec/sonic-operator-platform-launch.py').read_bytes()).hexdigest()!=sys.argv[5]: raise RuntimeError('launcher changed')
manifestRaw=(base/'active.json').read_bytes()
if hashlib.sha256(manifestRaw).hexdigest()!=sys.argv[3]: raise RuntimeError('persistent launch manifest drift')
manifest=json.loads(manifestRaw)
expectedOrigins={n:'/usr/local/lib/python3.11/dist-packages/sonic_platform/'+n+'.py' for n in manifest['sources']}
if p['origins']!=expectedOrigins: raise RuntimeError('wrong import origins')
print('verified')`

func (n *Native) verifyProvenance(ctx context.Context, j *journal) error {
	if !shaPattern.MatchString(j.LauncherManifest) {
		return fmt.Errorf("process-start import provenance requires guarded activation")
	}
	for _, name := range []string{"xcvrd", "psud", "syseepromd", "stormond"} {
		raw, err := n.command(ctx, "/usr/bin/docker", "exec", "pmon", "supervisorctl", "pid", name)
		pid, parseErr := strconv.Atoi(strings.TrimSpace(string(raw)))
		if err != nil || parseErr != nil || pid < 1 {
			return fmt.Errorf("native daemon process unavailable")
		}
		proof, err := n.command(ctx, "/usr/bin/docker", "exec", "pmon", "python3", "-I", "-B", "-c", launcherProofProbe, strconv.Itoa(pid), name, j.LauncherManifest, n.Engine.Policy.ConsumerSHA256["pmon-interpreter"], Digest([]byte(platformLauncher)))
		if err != nil || strings.TrimSpace(string(proof)) != "verified" {
			return fmt.Errorf("native daemon import provenance unverified")
		}
	}
	return nil
}
