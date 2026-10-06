# SPDX-License-Identifier: Apache-2.0
"""Process-start-bound platform import policy; no hardware classes instantiated."""
import hashlib
import importlib.abc
import importlib.util
import json
import os
from pathlib import Path
import runpy
import sys
import stat

ROOT = Path('/usr/local/lib/python3.11/dist-packages/sonic_platform')
BASE = Path('/var/lib/sonic-operator-platform')
PROGRAMS = {'xcvrd', 'psud', 'syseepromd', 'stormond'}

def digest(data):
    return hashlib.sha256(data).hexdigest()

class VerifiedSource(importlib.abc.Loader):
    def __init__(self, filename, content, package):
        self.filename, self.content, self.package = filename, content, package
    def create_module(self, spec):
        return None
    def exec_module(self, module):
        # Compile verified source directly. SourceFileLoader is deliberately not
        # used: -B alone still permits reading an old Python-valid .pyc.
        module.__file__ = str(self.filename)
        if self.package:
            module.__path__ = [str(self.filename.parent)]
        exec(compile(self.content, str(self.filename), 'exec'), module.__dict__)

class PlatformImports(importlib.abc.MetaPathFinder):
    def __init__(self, root, sources):
        self.root, self.sources = root, sources
    def find_spec(self, fullname, path=None, target=None):
        if fullname != 'sonic_platform' and not fullname.startswith('sonic_platform.'):
            return None
        name = '__init__' if fullname == 'sonic_platform' else fullname.removeprefix('sonic_platform.')
        if name not in self.sources:
            raise ImportError('undeclared platform module')
        filename = self.root / (name + '.py')
        if filename.resolve() != filename:
            raise ImportError('platform import symlink')
        info = filename.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
            raise ImportError('unqualified platform source')
        data = filename.read_bytes()
        if digest(data) != self.sources[name]:
            raise ImportError('platform import content changed')
        return importlib.util.spec_from_loader(fullname, VerifiedSource(filename, data, name == '__init__'), is_package=name == '__init__')

def main():
    if not sys.flags.isolated or not sys.flags.no_site:
        raise RuntimeError('platform launcher requires isolated no-site interpreter')
    daemon = sys.argv[1]
    if daemon not in PROGRAMS:
        raise RuntimeError('unqualified platform daemon')
    raw = (BASE / 'active.json').read_bytes()
    manifest = json.loads(raw)
    entry = Path('/usr/local/bin') / daemon
    if digest(entry.read_bytes()) != manifest['programs'][daemon]:
        raise RuntimeError('native daemon entrypoint changed')
    # Qualified Debian interpreter/library paths. No script-directory, cwd,
    # PYTHONPATH, user site, .pth or sitecustomize execution participates.
    sys.path[:] = ['/usr/lib/python3.11', '/usr/lib/python3.11/lib-dynload',
                   '/usr/local/lib/python3.11/dist-packages', '/usr/lib/python3/dist-packages']
    source_names = {n + '.py' for n in manifest['sources']}
    if {p.name for p in ROOT.iterdir() if p.is_file() and p.suffix == '.py'} != source_names:
        raise RuntimeError('unrecorded platform source')
    finder = PlatformImports(ROOT, manifest['sources'])
    for name in manifest['sources']:
        finder.find_spec('sonic_platform' if name == '__init__' else 'sonic_platform.' + name)
    sys.meta_path.insert(0, finder)
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    start = Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19]
    proof = {'version': 1, 'pid': os.getpid(), 'boot': boot, 'startTicks': start,
             'manifest': digest(raw), 'searchPath': list(sys.path),
             'origins': {n: str(ROOT / (n + '.py')) for n in manifest['sources']}}
    proofs = BASE / 'proofs'
    proofs.mkdir(mode=0o700, exist_ok=True)
    temporary = proofs / (daemon + '.tmp')
    temporary.write_text(json.dumps(proof, sort_keys=True))
    os.chmod(temporary, 0o600)
    os.replace(temporary, proofs / (daemon + '.json'))
    sys.argv = [str(entry)] + sys.argv[2:]
    runpy.run_path(str(entry), run_name='__main__')

if __name__ == '__main__':
    main()
