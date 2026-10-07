// SPDX-License-Identifier: Apache-2.0
package host

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

type importedUnitFixture struct {
	*systemFixture
	p          NativeProfile
	properties map[string]string
	unitFiles  map[string][]byte
	info       unitFixtureInfo
	loaded     string
	active     string
	calls      int
}

func newImportedUnitFixture(t *testing.T, kind, phase string) *importedUnitFixture {
	f := &importedUnitFixture{systemFixture: newSystemFixture(t), properties: map[string]string{}, unitFiles: map[string][]byte{}}
	f.files[interfacesTemplate], f.files[chronyTemplate] = []byte("interfaces"), []byte("chrony")
	for _, domain := range []string{"Management", "chrony"} {
		for _, c := range consumerPaths(domain) {
			f.files[c.path] = []byte(c.key)
		}
	}
	if err := json.Unmarshal(f.files[profileFile], &f.p); err != nil {
		t.Fatal(err)
	}
	h := LegacyMACHook{Kind: kind, BaseMAC: "00:00:5e:00:53:01", MAC: "02:00:5e:00:53:01", Addresses: []Address{{Prefix: "10.0.0.22/24", Gateway: "10.0.0.1"}}, HelperSHA256: ImportedHelperSHA256(kind), HookSHA256: digestForTest(string(ImportedMACUnit(kind)))}
	helperName, key, interpreter := "set-management-mac.sh", "imported-shell", "/bin/sh"
	if kind == ImportedKindPython {
		h.BaseMAC, h.MAC, h.Addresses[0].Prefix, h.Hostname = "00:00:5e:00:53:02", "02:00:5e:00:53:02", "10.0.0.21/24", "leaf-01"
		helperName, key, interpreter = "management-only-mac.py", "imported-python", "/usr/bin/python3"
	}
	f.p.LegacyMACHooks = []LegacyMACHook{h}
	f.p.ImportedMACEnvironment = ImportedMACEnvironmentNone
	f.p.ConsumerSHA256[key] = digestForTest("interpreter")
	f.files[interpreter] = []byte("interpreter")
	f.files["/proc/sys/kernel/hostname"] = []byte("leaf-01\n")
	hook, helper, _ := ImportedMACPaths(kind)
	read := func(name string) []byte {
		b, err := os.ReadFile("testdata/imported-mac/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	f.files[helper] = capturedMACHelper(t, helperName)
	if !hashMatches(f.files[helper], h.HelperSHA256) {
		t.Fatal("helper fixture not measured bytes")
	}
	f.files[RecoveryBootstrapDir+"/content/"+h.HelperSHA256] = f.files[helper]
	f.files[hook] = ImportedMACUnit(kind)
	f.unitFiles[importedEnvironmentPath] = read("environment.conf")
	f.unitFiles[importedFragmentPath] = read("interfaces-config.service")
	f.unitFiles[hook] = f.files[hook]
	f.info = unitFixtureInfo{mode: 0644, stat: syscall.Stat_t{Uid: 0, Gid: 0, Nlink: 1}}
	f.properties["DropInPaths"] = importedEnvironmentPath + " " + hook
	f.properties["NeedDaemonReload"] = "no"
	command := RecoveryBinaryFile + " --apply-imported-boot-mac=" + kind
	if phase == "bootstrap" || phase == "repair" {
		command = originalImportedCommand(kind)
		f.unitFiles[hook] = []byte("[Service]\nExecStartPost=" + command + "\n")
	}
	f.properties["ExecStartPost"] = "{ path=" + strings.Fields(command)[0] + " ; argv[]=" + command + " ; ignore_errors=no ; }"
	f.loaded = strings.TrimSuffix(string(read("loaded-interfaces.txt")), "\n")
	f.loaded = strings.ReplaceAll(f.loaded, "path=/usr/local/sbin/set-management-mac", "path="+strings.Fields(command)[0])
	f.loaded = strings.ReplaceAll(f.loaded, "argv[]=/usr/local/sbin/set-management-mac", "argv[]="+command)
	f.active = h.MAC
	if phase == "boot" {
		f.active = h.BaseMAC
	}
	f.db = Database{"MGMT_INTERFACE": {"eth0|" + h.Addresses[0].Prefix: {"gwaddr": "10.0.0.1"}}}
	f.n.BaseMAC = func(context.Context) (string, error) { return h.BaseMAC, nil }
	f.n.journalDir = t.TempDir()
	if err := os.Chmod(f.n.journalDir, 0700); err != nil {
		t.Fatal(err)
	}
	f.n.ReadUnitFile = func(path string) ([]byte, os.FileInfo, error) {
		b, ok := f.unitFiles[path]
		if !ok {
			return nil, nil, os.ErrNotExist
		}
		i := f.info
		i.size = int64(len(b))
		return b, i, nil
	}
	priorRun := f.n.Run
	f.n.Run = func(ctx context.Context, args []string, input []byte) ([]byte, error) {
		joined := strings.Join(args, " ")
		if b, ok := fixtureRecoveryUnit(args); ok {
			return b, nil
		}
		if args[0] == "systemctl" {
			for _, a := range args {
				if strings.HasPrefix(a, "--property=") {
					key := strings.TrimPrefix(a, "--property=")
					if v, ok := f.properties[key]; ok {
						return []byte(v + "\n"), nil
					}
				}
			}
			if b, ok := fixtureImportedEnvironmentProperty(args); ok {
				return b, nil
			}
			if strings.Contains(joined, "--property=Id,ExecStart,ExecStartPre,ExecStartPost") {
				return []byte(f.loaded), nil
			}
			return nil, ErrNative
		}
		source := strings.TrimSuffix(h.Addresses[0].Prefix, "/24")
		if strings.Contains(joined, "-j address") {
			return []byte(`[{"ifname":"eth0","address":"` + f.active + `","flags":["UP"],"addr_info":[{"local":"` + source + `","prefixlen":24,"scope":"global"}]}]`), nil
		}
		if strings.Contains(joined, "-j rule") {
			return []byte(`[{"priority":32765,"src":"` + source + `","table":"default"}]`), nil
		}
		if strings.Contains(joined, "-j route") {
			if args[1] == "-6" {
				return []byte(`[]`), nil
			}
			return []byte(`[{"dst":"10.0.0.0/24","table":"default"},{"dst":"default","gateway":"10.0.0.1","table":"default","metric":201}]`), nil
		}
		if joined == originalImportedCommand(kind) {
			f.calls++
			f.active = h.MAC
			return nil, nil
		}
		return priorRun(ctx, args, input)
	}
	f.files[profileFile], _ = json.Marshal(f.p)
	var r InstallationReceipt
	_ = json.Unmarshal(f.files[RecoveryReceiptFile], &r)
	r.Files[profileFile], r.Files[helper], r.Files[hook] = digestForTest(string(f.files[profileFile])), h.HelperSHA256, h.HookSHA256
	source := []byte("[Service]\nExecStartPost=" + originalImportedCommand(kind) + "\n")
	r.Sources = map[string]string{kind: digestForTest(string(source))}
	f.files[RecoveryBootstrapDir+"/content/"+r.Sources[kind]] = source
	f.files[RecoveryReceiptFile], _ = json.Marshal(r)
	return f
}

func (f *importedUnitFixture) qualify(t *testing.T, phase string) error {
	switch phase {
	case "bootstrap", "repair":
		return f.n.QualifyBootstrapProfile(t.Context(), f.files[profileFile], phase == "repair")
	case "boot":
		return f.n.ApplyImportedBootMAC(t.Context(), f.p.LegacyMACHooks[0].Kind)
	default:
		p, err := f.n.QualifyInstalledProfile(t.Context())
		if err != nil {
			return err
		}
		return f.n.QualifyImportedAdoption(t.Context(), p)
	}
}

func TestImportedMACNativeQualification(t *testing.T) {
	for _, kind := range []string{"management-mac-shell", "management-mac-python"} {
		for _, phase := range []string{"bootstrap", "installed", "repair", "boot"} {
			for _, change := range []string{"valid", "crlf", "id-first", "path-order", "extra-path", "duplicate-path", "missing-environment", "file-env", "duplicate-env", "file-directive", "fragment-directive", "owner", "group", "mode", "symlink", "hardlink", "effective-env", "environment-file", "exec-pre", "exec-stop", "effective-owner", "foreign-helper", "spoofed-id", "duplicate-id", "duplicate-service", "helper-in-pre", "wrong-helper-kind", "foreign-adapter", "repair-missing-hook", "repair-unknown-hook", "overlay-environment", "regenerated-inode"} {
				t.Run(kind+"/"+phase+"/"+change, func(t *testing.T) {
					f := newImportedUnitFixture(t, kind, phase)
					hook, helper, _ := ImportedMACPaths(kind)
					wantOK := change == "valid" || change == "crlf" || change == "id-first" || change == "path-order" || change == "regenerated-inode" || (change == "repair-missing-hook" && phase == "repair")
					switch change {
					case "path-order":
						f.properties["DropInPaths"] = hook + " " + importedEnvironmentPath
					case "crlf":
						f.loaded = strings.ReplaceAll(f.loaded+"\n\nId=harmless.service\nExecStart=\n", "\n", "\r\n")
					case "id-first":
						f.loaded = "Id=interfaces-config.service\n" + strings.TrimSuffix(f.loaded, "\nId=interfaces-config.service") + "\n"
					case "extra-path":
						f.properties["DropInPaths"] += " /etc/systemd/system/interfaces-config.service.d/foreign.conf"
					case "duplicate-path":
						f.properties["DropInPaths"] += " " + importedEnvironmentPath
					case "missing-environment":
						delete(f.unitFiles, importedEnvironmentPath)
					case "file-env", "overlay-environment":
						f.unitFiles[importedEnvironmentPath] = []byte("[Service]\nEnvironment=LD_PRELOAD=/evil.so\n")
						f.files[importedEnvironmentPath] = []byte(importedEnvironment)
					case "duplicate-env":
						f.unitFiles[importedEnvironmentPath] = append(f.unitFiles[importedEnvironmentPath], []byte("Environment=NUM_DPU=0\n")...)
					case "file-directive":
						f.unitFiles[importedEnvironmentPath] = append(f.unitFiles[importedEnvironmentPath], []byte("ExecStartPre=/bin/false\n")...)
					case "fragment-directive":
						f.unitFiles[importedFragmentPath] = append(f.unitFiles[importedFragmentPath], []byte("[Service]\nExecStartPre=/bin/false\n")...)
					case "owner":
						f.info.stat.Uid = 42
					case "group":
						f.info.stat.Gid = 42
					case "mode":
						f.info.mode = 0664
					case "symlink":
						f.info.mode = os.ModeSymlink | 0644
					case "hardlink":
						f.info.stat.Nlink = 2
					case "effective-env":
						f.properties["Environment"] = "NUM_DPU=0 IS_DPU_DEVICE=false LD_PRELOAD=/evil.so"
					case "environment-file":
						f.properties["EnvironmentFiles"] = "/etc/evil.env"
					case "exec-pre":
						f.properties["ExecStartPre"] = "{ path=/bin/false ; argv[]=/bin/false ; }"
					case "exec-stop":
						f.properties["ExecStop"] = "{ path=/bin/false ; argv[]=/bin/false ; }"
					case "effective-owner":
						f.properties["User"] = "other"
					case "foreign-helper":
						f.loaded += "\n\nId=other.service\nExecStart={ path=" + helper + " ; argv[]=" + helper + " ; }"
					case "spoofed-id":
						f.loaded = strings.ReplaceAll(f.loaded, "Id=interfaces-config.service", "Description=Id=interfaces-config.service\nId=other.service")
					case "duplicate-id":
						f.loaded += "\nId=other.service"
					case "duplicate-service":
						f.loaded += "\n\nId=interfaces-config.service\nExecStart="
					case "helper-in-pre":
						f.loaded += "\nExecStartPre={ path=" + helper + " ; argv[]=" + helper + " ; }"
					case "wrong-helper-kind":
						f.loaded += "\n\nId=other.service\nExecStart=/usr/local/sbin/dc-management-only-mac.py /usr/local/sbin/set-management-mac"
					case "foreign-adapter":
						f.loaded += "\n\nId=other.service\nExecStartPost={ path=" + RecoveryBinaryFile + " ; argv[]=" + RecoveryBinaryFile + " --apply-imported-boot-mac=" + kind + " ; }"
					case "repair-missing-hook":
						delete(f.files, hook)
						delete(f.unitFiles, hook)
						f.properties["DropInPaths"] = importedEnvironmentPath
						f.properties["ExecStartPost"] = ""
						f.properties["NeedDaemonReload"] = "yes"
						f.loaded = "Id=interfaces-config.service\nExecStart=/usr/bin/interfaces-config.sh"
					case "repair-unknown-hook":
						f.properties["ExecStartPost"] = "{ path=/bin/false ; argv[]=/bin/false ; }"
					case "regenerated-inode":
						read := f.n.ReadUnitFile
						f.n.ReadUnitFile = func(path string) ([]byte, os.FileInfo, error) {
							f.info.stat.Ino++
							return read(path)
						}
					}
					err := f.qualify(t, phase)
					if (err == nil) != wantOK {
						t.Fatalf("qualification=%v want success=%v", err, wantOK)
					}
					wantCalls := 0
					if wantOK && phase == "boot" {
						wantCalls = 1
					}
					if f.calls != wantCalls {
						t.Fatalf("helper calls %d, want %d", f.calls, wantCalls)
					}
				})
			}
		}
	}
}

// capturedMACHelper reads a site's captured legacy MAC helper script. The
// helpers contain site addresses, so they are not part of the repository; set
// SONIC_TEST_MAC_FIXTURE_DIR to run the tests that need their exact bytes.
func capturedMACHelper(t *testing.T, name string) []byte {
	t.Helper()
	dir := os.Getenv("SONIC_TEST_MAC_FIXTURE_DIR")
	if dir == "" {
		t.Skip("set SONIC_TEST_MAC_FIXTURE_DIR to the captured MAC helper scripts")
	}
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestImportedMACFixtureIdentities(t *testing.T) {
	b, err := os.ReadFile("testdata/imported-mac/environment.conf")
	if err != nil || !hashMatches(b, "d94870480b37feb5248af1789284acb2345bdbdd2e4c387b2b3b767bba68728b") {
		t.Fatal("environment.conf", err)
	}
	for name, hash := range map[string]string{"set-management-mac.sh": ImportedHelperSHA256(ImportedKindShell), "management-only-mac.py": ImportedHelperSHA256(ImportedKindPython)} {
		if !hashMatches(capturedMACHelper(t, name), hash) {
			t.Fatal(name)
		}
	}
}

func TestImportedLegacyRepairRejectsForeignDropins(t *testing.T) {
	f := newImportedUnitFixture(t, "management-mac-shell", "repair")
	f.p.ImportedMACEnvironment = ""
	f.files[profileFile], _ = json.Marshal(f.p)
	if err := f.qualify(t, "repair"); err == nil {
		t.Fatal("repair accepted undeclared native environment")
	}
}

func TestImportedProfileQualificationMeasuresEnvironment(t *testing.T) {
	f := newImportedUnitFixture(t, "management-mac-shell", "installed")
	f.unitFiles[importedEnvironmentPath] = []byte("[Service]\nEnvironment=NUM_DPU=1\n")
	if _, err := f.n.QualifyInstalledProfile(t.Context()); err == nil {
		t.Fatal("installed profile qualified different native environment")
	}
}

func TestImportedBootstrapRejectsMutatingSourceHook(t *testing.T) {
	f := newImportedUnitFixture(t, "management-mac-shell", "bootstrap")
	hook, _, _ := ImportedMACPaths("management-mac-shell")
	f.unitFiles[hook] = append(f.unitFiles[hook], []byte("Environment=LD_PRELOAD=/evil.so\n")...)
	if err := f.qualify(t, "bootstrap"); err == nil {
		t.Fatal("overlay qualified mutating original source")
	}
}

func TestImportedBootstrapUndeclaredMeasuredEnvironment(t *testing.T) {
	f := newImportedUnitFixture(t, "management-mac-shell", "bootstrap")
	f.p.ImportedMACEnvironment = ""
	f.files[profileFile], _ = json.Marshal(f.p)
	if err := f.qualify(t, "bootstrap"); !errors.Is(err, ErrNative) {
		t.Fatalf("measured two-drop-in unit qualified without profile opt-in: %v", err)
	}
}

func TestImportedLoadedInventoryBoundaries(t *testing.T) {
	for _, change := range []string{"bound", "duplicate-property", "missing-id", "owner-suffix", "bare-cr"} {
		t.Run(change, func(t *testing.T) {
			f := newImportedUnitFixture(t, "management-mac-shell", "bootstrap")
			switch change {
			case "bound":
				f.loaded = "Id=other.service\nExecStart=" + strings.Repeat("x", 4<<20)
			case "duplicate-property":
				f.loaded += "\nExecStart="
			case "missing-id":
				f.loaded = strings.TrimSuffix(f.loaded, "\nId=interfaces-config.service")
			case "owner-suffix":
				f.loaded = strings.ReplaceAll(f.loaded, "Id=interfaces-config.service", "Id=other-interfaces-config.service")
			case "bare-cr":
				f.loaded = strings.ReplaceAll(f.loaded, "\n", "\r")
			}
			if err := f.qualify(t, "bootstrap"); err == nil || f.calls != 0 {
				t.Fatal("ambiguous inventory qualified", err)
			}
		})
	}
}

func TestImportedLoadedRepeatedNativeCommands(t *testing.T) {
	for _, change := range []string{"legitimate", "first-helper", "second-helper", "first-basename", "second-basename", "first-env-path", "second-env-path", "foreign-env-path", "duplicate-id"} {
		t.Run(change, func(t *testing.T) {
			f := newImportedUnitFixture(t, "management-mac-shell", "bootstrap")
			raw, err := os.ReadFile("testdata/imported-mac/loaded-ssh.txt")
			if err != nil {
				t.Fatal(err)
			}
			block := string(raw)
			switch change {
			case "first-helper":
				block = strings.ReplaceAll(block, "/usr/local/bin/host-ssh-keygen.sh", "/usr/local/sbin/set-management-mac")
			case "second-helper":
				block = strings.ReplaceAll(block, "/usr/sbin/sshd -t", "/usr/local/sbin/set-management-mac")
			case "first-basename", "second-basename", "first-env-path", "second-env-path":
				command := "set-management-mac"
				if strings.HasSuffix(change, "env-path") {
					command = "/usr/bin/env PATH=/usr/local/sbin:/usr/bin:/bin set-management-mac"
				}
				old := "/usr/local/bin/host-ssh-keygen.sh"
				if strings.HasPrefix(change, "second-") {
					old = "/usr/sbin/sshd -t"
				}
				block = strings.ReplaceAll(block, "argv[]="+old, "argv[]="+command)
				block = strings.ReplaceAll(block, "path="+strings.Fields(old)[0], "path="+strings.Fields(command)[0])
			case "foreign-env-path":
				block = "Id=other.service\nExecStart={ path=/usr/bin/env ; argv[]=/usr/bin/env PATH=/usr/local/sbin:/usr/bin:/bin set-management-mac ; ignore_errors=no ; }\n"
			case "duplicate-id":
				block += "Id=interfaces-config.service\n"
			}
			f.loaded += "\n\n" + block
			err = f.qualify(t, "bootstrap")
			if (err == nil) != (change == "legitimate") || f.calls != 0 {
				t.Fatal("repeated native command qualification", err)
			}
			if change != "legitimate" && change != "duplicate-id" && !errors.Is(err, ErrConflict) {
				t.Fatalf("foreign helper must conflict: %v", err)
			}
		})
	}
}

// Optional OFFLINE replay of the protected capture. Only loadedActivation is
// decoded; private configuration is neither retained nor printed nor copied to Git.
func TestCapturedImportedLoadedInventory(t *testing.T) {
	path := os.Getenv("SONIC_TEST_MAC_CAPTURE")
	if path == "" {
		t.Skip("set local protected capture path for offline replay")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("capture unavailable")
	}
	var captured struct {
		LoadedActivation struct {
			Stdout string `json:"stdout"`
		} `json:"loadedActivation"`
	}
	if json.Unmarshal(raw, &captured) != nil || captured.LoadedActivation.Stdout == "" {
		t.Fatal("invalid capture structure")
	}
	f := newImportedUnitFixture(t, "management-mac-shell", "bootstrap")
	f.loaded = captured.LoadedActivation.Stdout
	if err := f.qualify(t, "bootstrap"); err != nil || f.calls != 0 {
		t.Fatal("captured native inventory did not qualify", err)
	}
}
