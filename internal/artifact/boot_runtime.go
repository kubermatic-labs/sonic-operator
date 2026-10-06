// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"context"
	"fmt"
	"strings"
)

// Progress is scoped to generated configuration and the processes consuming it.
// Container identity alone misses regeneration within the same running container.
const bootRuntimeProbe = `import hashlib,pathlib,subprocess
h=hashlib.sha256()
def read(p):
 try: return p.read_bytes()
 except FileNotFoundError: return b'<missing>'
for name in ['/etc/supervisor/conf.d/supervisord.conf','/usr/local/libexec/sonic-operator-platform-launch.py','/var/lib/sonic-operator-platform/active.json']:
 h.update(read(pathlib.Path(name)));h.update(b'\0')
for name in ['xcvrd','psud','syseepromd','stormond']:
 h.update(read(pathlib.Path('/var/lib/sonic-operator-platform/proofs')/(name+'.json')));h.update(b'\0')
 pid=int(subprocess.check_output(['supervisorctl','pid',name],timeout=5).strip())
 p=pathlib.Path('/proc')/str(pid)
 h.update(str(pid).encode());h.update(b'\0')
 stat=read(p/'stat')
 h.update(stat.rsplit(b')',1)[1].split()[19] if stat!=b'<missing>' else stat);h.update(b'\0')
 h.update(read(p/'cmdline'));h.update(b'\0')
print(h.hexdigest())`

func (n *Native) bootRuntimeIdentity(ctx context.Context) (string, error) {
	container, err := n.command(ctx, "/usr/bin/docker", "inspect", "--format", "{{.Id}} {{.State.StartedAt}}", "pmon")
	if err != nil || strings.TrimSpace(string(container)) == "" {
		return "", ErrActivationPending
	}
	raw, err := n.command(ctx, "/usr/bin/docker", "exec", "pmon", "python3", "-I", "-B", "-c", bootRuntimeProbe)
	if err != nil {
		return "", ErrActivationPending
	}
	identity := strings.TrimSpace(string(raw))
	if !shaPattern.MatchString(identity) {
		return "", fmt.Errorf("invalid native runtime identity")
	}
	if n.Engine.BootID == nil || n.Engine.BootID() == "" {
		return "", fmt.Errorf("boot identity unavailable")
	}
	return Digest([]byte(n.Engine.BootID() + "\x00" + strings.TrimSpace(string(container)) + "\x00" + identity)), nil
}

func (n *Native) qualifiedBootRuntimeIdentity(ctx context.Context, j *journal) (string, error) {
	before, err := n.bootRuntimeIdentity(ctx)
	if err != nil {
		return "", err
	}
	if err := n.verifyProvenance(ctx, j); err != nil {
		return "", ErrActivationPending
	}
	after, err := n.bootRuntimeIdentity(ctx)
	if err != nil {
		return "", err
	}
	if before != after {
		return "", ErrActivationPending
	}
	return after, nil
}
