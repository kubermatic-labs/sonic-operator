// SPDX-License-Identifier: Apache-2.0
package host

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

func TestImportedNativeUnitUntrustedFilesystem(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("unprivileged ancestor rejection test")
	}
	path := filepath.Join(t.TempDir(), "environment.conf")
	if err := os.WriteFile(path, []byte(importedEnvironment), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readNativeUnitFile(path); !errors.Is(err, ErrNative) {
		t.Fatalf("accepted user-owned ancestor: %v", err)
	}
	n := &Native{} // Exercise the default reader, without a metadata callback.
	if err := n.nativeUnitFile(path, importedEnvironment); !errors.Is(err, ErrNative) {
		t.Fatalf("qualified user-owned native file: %v", err)
	}
}

// A trusted positive control is necessary to prove rejection of each individual
// filesystem mutation. /tmp cannot provide it: its writable ancestor is rejected.
// This test uses only a disposable /run subdirectory on a root Linux test runner;
// it never opens the real SONiC unit paths or executes a helper/systemctl.
func TestImportedNativeUnitTrustedFilesystem(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("requires a root Linux test runner with trusted /run")
	}
	base, err := os.MkdirTemp("/run", "sonic-native-unit-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	for _, change := range []string{"valid", "writable-ancestor", "unowned-ancestor", "symlink-ancestor", "symlink-file", "mode", "owner", "group", "hardlink", "oversize", "directory", "fifo"} {
		t.Run(change, func(t *testing.T) {
			parent := filepath.Join(base, change)
			if err := os.Mkdir(parent, 0755); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(parent, "environment.conf")
			if err := os.WriteFile(path, []byte(importedEnvironment), 0644); err != nil {
				t.Fatal(err)
			}
			n := &Native{}
			if err := n.nativeUnitFile(path, importedEnvironment); err != nil {
				t.Fatalf("trusted positive control: %v", err)
			}
			var err error
			switch change {
			case "writable-ancestor":
				err = os.Chmod(parent, 0777)
			case "unowned-ancestor":
				err = os.Chown(parent, 1, 0)
			case "symlink-ancestor":
				link := filepath.Join(base, "parent-link")
				err = os.Symlink(parent, link)
				path = filepath.Join(link, "environment.conf")
			case "symlink-file":
				link := filepath.Join(parent, "file-link")
				err = os.Symlink(path, link)
				path = link
			case "mode":
				err = os.Chmod(path, 0664)
			case "owner":
				err = os.Chown(path, 1, 0)
			case "group":
				err = os.Chown(path, 0, 1)
			case "hardlink":
				err = os.Link(path, filepath.Join(parent, "hardlink"))
			case "oversize":
				err = os.WriteFile(path, make([]byte, (64<<10)+1), 0644)
			case "directory", "fifo":
				if err = os.Remove(path); err == nil {
					if change == "directory" {
						err = os.Mkdir(path, 0644)
					} else {
						err = syscall.Mkfifo(path, 0644)
					}
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			err = n.nativeUnitFile(path, importedEnvironment)
			if (err == nil) != (change == "valid") {
				t.Fatalf("default native file reader: %v", err)
			}
		})
	}
}
