// SPDX-License-Identifier: Apache-2.0
package host

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestNativeReadInterpreterAdmission(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name, request, target string
		allowed               bool
	}{
		{"python311", "/usr/bin/python3", "/usr/bin/python3.11", true},
		{"python313", "/usr/bin/python3", "/usr/bin/python3.13", true},
		{"usrDash", "/bin/sh", "/usr/bin/dash", true},
		{"binDash", "/bin/sh", "/bin/dash", true},
		{"unknownPython", "/usr/bin/python3", "/usr/bin/python3.14", false},
		{"untrustedTarget", "/usr/bin/python3", "/tmp/python3.13", false},
		{"recoveryTarget", "/usr/bin/python3", RecoveryBinaryFile, false},
		{"unknownShell", "/bin/sh", "/bin/bash", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path, limit, err := nativeReadPath(tt.request, func(path string) (string, error) {
				if path != tt.request {
					t.Fatalf("resolved unexpected request %q", path)
				}
				return tt.target, nil
			})
			if !tt.allowed {
				if !errors.Is(err, ErrNative) {
					t.Fatalf("unapproved target admitted: %v", err)
				}
				return
			}
			if err != nil || path != tt.target {
				t.Fatalf("approved target rejected: %q %v", path, err)
			}
			f, err := os.CreateTemp(t.TempDir(), "interpreter")
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			// Exact size of the pinned Python 3.13 observed on a reference switch.
			const size = 6820528
			if err := f.Truncate(size); err != nil {
				t.Fatal(err)
			}
			info, err := f.Stat()
			if err != nil {
				t.Fatal(err)
			}
			b, err := readNativeContents(f, info, limit)
			if err != nil || len(b) != size {
				t.Fatalf("approved interpreter read: bytes=%d err=%v", len(b), err)
			}
			if limit != 96<<20 {
				t.Fatalf("executable limit = %d", limit)
			}
			if err := f.Truncate((96 << 20) + 1); err != nil {
				t.Fatal(err)
			}
			info, err = f.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if b, err := readNativeContents(f, info, limit); !errors.Is(err, ErrNative) || b != nil {
				t.Fatalf("oversized interpreter admitted: bytes=%d err=%v", len(b), err)
			}
		})
	}
}

func TestNativeReadConfigAndPathGuards(t *testing.T) {
	t.Parallel()
	for _, path := range []string{profileFile, "/usr/bin/python3.13", "/usr/bin/python3.11", "/bin/dash", "/tmp/python3", RecoveryBinaryFile} {
		t.Run(path, func(t *testing.T) {
			got, limit, err := nativeReadPath(path, func(string) (string, error) {
				t.Fatal("non-interpreter request resolved")
				return "", nil
			})
			want := int64(4 << 20)
			if path == RecoveryBinaryFile {
				want = 96 << 20
			}
			if err != nil || got != path || limit != want {
				t.Fatalf("path=%q limit=%d err=%v", got, limit, err)
			}
		})
	}
	if _, _, err := nativeReadPath("/usr/bin/python3", func(string) (string, error) {
		return "", os.ErrNotExist
	}); !errors.Is(err, ErrNative) {
		t.Fatalf("resolution error admitted: %v", err)
	}
	f, err := os.CreateTemp(t.TempDir(), "config")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate((4 << 20) + 1); err != nil {
		t.Fatal(err)
	}
	n := &Native{}
	if b, err := n.read(f.Name()); !errors.Is(err, ErrNative) || b != nil {
		t.Fatalf("oversized config admitted: bytes=%d err=%v", len(b), err)
	}
	if err := f.Truncate(0); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "symlink")
	if err := os.Symlink(f.Name(), link); err != nil {
		t.Fatal(err)
	}
	if _, err := n.read(link); err == nil {
		t.Fatal("unresolved symlink admitted")
	}
	if _, err := n.read(t.TempDir()); !errors.Is(err, ErrNative) {
		t.Fatalf("directory admitted: %v", err)
	}
}

func TestNativeReadBoundedAfterStat(t *testing.T) {
	t.Parallel()
	f, err := os.CreateTemp(t.TempDir(), "growing")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	const limit = 64
	for _, tt := range []struct {
		name string
		size int
	}{
		{"atLimit", limit},
		{"oneOver", limit + 1},
		{"growthBeyondLimit", 4 * limit},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// Empty-file metadata followed by a larger stream models growth after Stat.
			r := bytes.NewReader(bytes.Repeat([]byte("x"), tt.size))
			b, err := readNativeContents(r, info, limit)
			if tt.size <= limit {
				if err != nil || len(b) != tt.size {
					t.Fatalf("bounded content rejected: bytes=%d err=%v", len(b), err)
				}
			} else if !errors.Is(err, ErrNative) || b != nil {
				t.Errorf("grown file admitted: bytes=%d err=%v", len(b), err)
			}
			consumed := tt.size - r.Len()
			if consumed > limit+1 {
				t.Errorf("read %d bytes, exceeds limit+1", consumed)
			}
		})
	}
}
