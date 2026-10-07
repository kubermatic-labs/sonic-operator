// SPDX-License-Identifier: Apache-2.0
package host

import (
	"context"
	"io"
	"os"
	"slices"
	"strings"
	"syscall"
)

// ImportedMACEnvironmentNone is an explicit immutable-profile qualification of
// native generated output, not ownership of that file or its producer. The
// output is remeasured after regeneration, including bootstrap repair and boot.
const ImportedMACEnvironmentNone = "sonic-dpu-none-v1"

const importedEnvironmentPath = "/run/systemd/generator/interfaces-config.service.d/environment.conf"
const importedFragmentPath = "/usr/lib/systemd/system/interfaces-config.service"
const importedEnvironment = "[Service]\nEnvironment=\"NUM_DPU=0\"\nEnvironment=\"IS_DPU_DEVICE=false\"\n"
const importedFragment = `[Unit]
Description=Update interfaces configuration
Requires=config-setup.service
After=config-setup.service
BindsTo=sonic.target
After=sonic.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/interfaces-config.sh

[Install]
WantedBy=sonic.target
`

// Separate from ReadFile: bootstrap overlays owned payloads, never native unit
// bytes or metadata. Both callbacks are internal adapter/test boundaries.
func (n *Native) nativeUnitFile(path string, want string) error {
	read := n.ReadUnitFile
	if read == nil {
		read = readNativeUnitFile
	}
	b, info, err := read(path)
	if err != nil || info == nil || len(b) > 64<<10 || !info.Mode().IsRegular() || info.Mode() != 0644 || info.Size() != int64(len(b)) || string(b) != want {
		return ErrNative
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || st.Gid != 0 || st.Nlink != 1 {
		return ErrNative
	}
	return nil
}

func readNativeUnitFile(path string) ([]byte, os.FileInfo, error) {
	// Reject writable or symlinked ancestors as well as the final component.
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	parent := ""
	for _, part := range parts[:len(parts)-1] {
		parent += "/" + part
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&0022 != 0 {
			return nil, nil, ErrNative
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || st.Gid != 0 {
			return nil, nil, ErrNative
		}
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() > 64<<10 {
		return nil, nil, ErrNative
	}
	b, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	after, statErr := f.Stat()
	current, pathErr := os.Lstat(path)
	if err != nil || statErr != nil || pathErr != nil || !sameRecordIdentity(before, after) || !sameRecordIdentity(after, current) {
		return nil, nil, ErrNative
	}
	// Validate the latest path metadata too (chown need not change mtime).
	return b, current, nil
}

func originalImportedCommand(kind string) string {
	_, helper, _ := ImportedMACPaths(kind)
	if IsImportedPythonKind(kind) {
		return "/usr/bin/python3 " + helper + " boot"
	}
	return helper
}

// Parse property boundaries, not substrings in values. systemctl may omit empty
// properties; Id may be first, last, or lack a final newline. Repeated command
// properties describe multi-command services: retain every row for inspection.
func unitProperties(block string) (map[string][]string, error) {
	p := map[string][]string{}
	for _, line := range strings.Split(strings.ReplaceAll(block, "\r\n", "\n"), "\n") {
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" || strings.ContainsAny(line, "\r\x00") {
			return nil, ErrNative
		}
		if key != "Id" && key != "ExecStart" && key != "ExecStartPre" && key != "ExecStartPost" {
			return nil, ErrNative
		}
		p[key] = append(p[key], value)
	}
	return p, nil
}

func exactUnitCommand(value, command string) bool {
	if command == "" {
		return value == ""
	}
	return strings.Count(value, "path=") == 1 && strings.Count(value, "argv[]=") == 1 &&
		strings.HasPrefix(value, "{ path="+strings.Fields(command)[0]+" ; ") &&
		strings.Contains(value, "argv[]="+command+" ;") &&
		!strings.Contains(value, "ignore_errors=yes") && strings.HasSuffix(strings.TrimSpace(value), "}")
}

func exactUnitPaths(value, want string) bool {
	a, b := strings.Fields(value), strings.Fields(want)
	if len(a) != len(b) {
		return false
	}
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

func (n *Native) qualifyImportedEnvironment(ctx context.Context, p NativeProfile) error {
	if p.ImportedMACEnvironment != ImportedMACEnvironmentNone || len(p.LegacyMACHooks) != 1 {
		return ErrNative
	}
	if n.nativeUnitFile(importedEnvironmentPath, importedEnvironment) != nil || n.nativeUnitFile(importedFragmentPath, importedFragment) != nil {
		return ErrNative
	}
	want := map[string]string{
		"FragmentPath": importedFragmentPath, "Environment": "NUM_DPU=0 IS_DPU_DEVICE=false",
		"EnvironmentFiles": "", "PassEnvironment": "", "UnsetEnvironment": "",
		"User": "", "Group": "", "SupplementaryGroups": "", "DynamicUser": "no",
		"RootDirectory": "", "RootImage": "", "WorkingDirectory": "", "ExecSearchPath": "",
		"ExecStartPre": "", "ExecStart": "/usr/bin/interfaces-config.sh", "ExecReload": "", "ExecStop": "", "ExecStopPost": "",
		"Type": "oneshot", "RemainAfterExit": "yes",
	}
	for property, expected := range want {
		b, err := n.run(ctx, "systemctl", "show", "--property="+property, "--value", "interfaces-config.service")
		value := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
		match := value == expected
		if property == "ExecStart" {
			match = exactUnitCommand(value, expected)
		}
		if err != nil || len(b) > 64<<10 || !match {
			return ErrNative
		}
	}
	// Native bytes must still agree after the effective-property reads. This does
	// not pin inode identity across generator runs or create a restoration source.
	if n.nativeUnitFile(importedEnvironmentPath, importedEnvironment) != nil || n.nativeUnitFile(importedFragmentPath, importedFragment) != nil {
		return ErrNative
	}
	return nil
}

func qualifyLoadedImportedUnits(raw []byte, kind string, adoption bool) error {
	if len(raw) == 0 || len(raw) > 4<<20 {
		return ErrNative
	}
	seen := map[string]bool{}
	for _, block := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n\n") {
		if strings.TrimSpace(block) == "" {
			continue
		}
		p, err := unitProperties(block)
		if err != nil || len(p["Id"]) != 1 || p["Id"][0] == "" || seen[p["Id"][0]] {
			return ErrNative
		}
		id := p["Id"][0]
		seen[id] = true
		lower := strings.ToLower(block)
		if strings.Contains(lower, "rollback") && strings.Contains(lower, "mac") {
			return ErrConflict
		}
		for key, values := range p {
			// The protected unit has exactly one command per property. Other
			// native services may have several; none of their rows is exempted.
			if id == "interfaces-config.service" && len(values) != 1 {
				return ErrNative
			}
			for _, value := range values {
				if strings.Contains(value, "--apply-imported-boot-mac") {
					if id != "interfaces-config.service" || key != "ExecStartPost" || !exactUnitCommand(value, RecoveryBinaryFile+" --apply-imported-boot-mac="+kind) {
						return ErrConflict
					}
				}
				if strings.Contains(value, "dc-management-only-mac.py") || strings.Contains(value, "set-management-mac") {
					if !adoption || id != "interfaces-config.service" || key != "ExecStartPost" || !exactUnitCommand(value, originalImportedCommand(kind)) {
						return ErrConflict
					}
				}
			}
		}
	}
	if len(seen) == 0 {
		return ErrNative
	}
	return nil
}
