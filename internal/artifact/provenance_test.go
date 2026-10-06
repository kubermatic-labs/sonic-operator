// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSourceLoaderDefeatsShadowPackageAndValidStaleBytecode(t *testing.T) {
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	expected := filepath.Join(root, "owned", "sonic_platform")
	shadow := filepath.Join(root, "shadow", "sonic_platform")
	os.MkdirAll(expected, 0700)
	os.MkdirAll(shadow, 0700)
	os.WriteFile(filepath.Join(shadow, "__init__.py"), []byte("VALUE = 'shadow'\n"), 0644)
	source := []byte("VALUE = 'actual'\n")
	os.WriteFile(filepath.Join(expected, "__init__.py"), source, 0644)
	payload, _ := json.Marshal(map[string]any{"root": expected, "shadow": filepath.Dir(shadow), "hash": Digest(source)})
	script := `import json,sys,pathlib,py_compile,os,importlib
r=json.loads(sys.argv[1]);root=pathlib.Path(r['root']);p=root/'__init__.py';stamp=p.stat().st_mtime
p.write_text("VALUE = 'cached'\n");py_compile.compile(str(p),doraise=True)
p.write_text("VALUE = 'actual'\n");os.utime(p,(stamp,stamp))
ns={'__name__':'artifact_launcher_library'}
exec(sys.stdin.read(),ns)
sys.path.insert(0,r['shadow'])
sys.meta_path.insert(0,ns['PlatformImports'](root,{'__init__':r['hash']}))
import sonic_platform
if sonic_platform.VALUE!='actual' or sonic_platform.__file__!=str(p): raise RuntimeError('unverified code executed')
`
	cmd := exec.Command("python3", "-I", "-S", "-B", "-c", script, string(payload))
	cmd.Stdin = strings.NewReader(platformLauncher)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("provenance policy failed: %v %s", err, out)
	}
}

func TestTreeProbeRejectsUnrecordedSourceAndStaleCache(t *testing.T) {
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	pkg := filepath.Join(root, "sonic_platform")
	metadata := filepath.Join(root, "sonic_platform-1.0.dist-info")
	os.MkdirAll(pkg, 0700)
	os.MkdirAll(metadata, 0700)
	os.WriteFile(filepath.Join(pkg, "unrecorded.py"), []byte("bad"), 0644)
	cmd := exec.Command("python3", "-I", "-S", "-B", "-c", packageHashProbe, root)
	if err := cmd.Run(); err == nil {
		t.Fatal("unrecorded package source ignored")
	}
	os.Remove(filepath.Join(pkg, "unrecorded.py"))
	p := filepath.Join(pkg, "__init__.py")
	script := `import pathlib,py_compile,os,sys
p=pathlib.Path(sys.argv[1]);p.write_text("VALUE='old'\n");py_compile.compile(str(p),doraise=True);stamp=p.stat().st_mtime;p.write_text("VALUE='new'\n");os.utime(p,(stamp,stamp))`
	if out, err := exec.Command("python3", "-I", "-B", "-c", script, p).CombinedOutput(); err != nil {
		t.Fatalf("cache fixture: %v %s", err, out)
	}
	cmd = exec.Command("python3", "-I", "-S", "-B", "-c", packageHashProbe, root)
	if err := cmd.Run(); err == nil {
		t.Fatal("valid stale cache passed runtime proof")
	}
}
