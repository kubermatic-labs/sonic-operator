// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
)

//go:embed platform_launcher.py
var platformLauncher string

const configureLauncherScript = `import base64,configparser,hashlib,json,os,pathlib,sys
r=json.load(sys.stdin)
base=pathlib.Path('/var/lib/sonic-operator-platform');base.mkdir(mode=0o700,exist_ok=True)
wrapper=pathlib.Path('/usr/local/libexec/sonic-operator-platform-launch.py');wrapper.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
config=pathlib.Path('/etc/supervisor/conf.d/supervisord.conf')
p=configparser.ConfigParser(interpolation=None);p.read_string(config.read_text())
for name in ['xcvrd','psud','syseepromd','stormond']:
 section='program:'+name
 expected='/usr/bin/python3.11 -I -S '+str(wrapper)+' '+name
 old=p[section]['command']
 if old not in ['python3 /usr/local/bin/'+name,'/usr/local/bin/'+name,expected]: raise RuntimeError('unqualified daemon launch command')
 p[section]['command']=expected
def atomic(path,data,mode):
 if path.is_symlink(): raise RuntimeError('launcher symlink')
 temp=path.with_name('.launch-'+os.urandom(12).hex())
 fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,mode)
 with os.fdopen(fd,'wb') as f:
  f.write(data);f.flush();os.fchmod(f.fileno(),mode);os.fsync(f.fileno())
 os.replace(temp,path)
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
atomic(wrapper,base64.b64decode(r['wrapper']),0o644)
atomic(base/'active.json',base64.b64decode(r['manifest']),0o600)
import io
out=io.StringIO();p.write(out);atomic(config,out.getvalue().encode(),0o644)
print('ready')`

func (n *Native) configureLaunchers(ctx context.Context, j *journal, restore bool) error {
	return n.configureLaunchersFrom(ctx, j, j, restore)
}
func (n *Native) configureLaunchersFrom(ctx context.Context, j, source *journal, restore bool) error {
	var snapshot packageSnapshot
	found := false
	for _, entry := range source.Packages {
		if entry.Target != "pmon" {
			continue
		}
		which, hash := "candidate", entry.Candidate
		if restore {
			which, hash = "before", entry.Before
		}
		raw, err := n.Engine.readPackagePayload(source, entry, which)
		if err != nil || Digest(raw) != hash || Decode(raw, &snapshot) != nil {
			return fmt.Errorf("launcher package authority unavailable")
		}
		found = true
	}
	if !found {
		return nil
	}
	sources := map[string]string{}
	for _, name := range platformModules {
		entry, ok := snapshot.Entries["sonic_platform/"+name]
		if !ok {
			return fmt.Errorf("launcher source missing")
		}
		sources[strings.TrimSuffix(name, ".py")] = Digest(entry.Data)
	}
	programs := map[string]string{}
	for _, name := range []string{"xcvrd", "psud", "syseepromd", "stormond"} {
		hash := n.Engine.Policy.ConsumerSHA256["pmon-"+name]
		if !shaPattern.MatchString(hash) {
			return fmt.Errorf("daemon entrypoint fingerprint missing")
		}
		programs[name] = hash
	}
	manifest, _ := json.Marshal(map[string]any{"version": 1, "sources": sources, "programs": programs})
	packet, _ := json.Marshal(map[string][]byte{"wrapper": []byte(platformLauncher), "manifest": manifest})
	if _, err := n.inputCommand(ctx, packet, "/usr/bin/docker", "exec", "-i", "pmon", "python3", "-I", "-B", "-c", configureLauncherScript); err != nil {
		return err
	}
	for _, args := range [][]string{{"exec", "pmon", "supervisorctl", "reread"}, {"exec", "pmon", "supervisorctl", "update"}, {"exec", "pmon", "supervisorctl", "restart", "xcvrd", "psud", "syseepromd", "stormond"}} {
		if _, err := n.command(ctx, "/usr/bin/docker", args...); err != nil {
			return err
		}
	}
	j.LauncherManifest = Digest(manifest)
	return n.Engine.save(j)
}
