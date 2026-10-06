// SPDX-License-Identifier: Apache-2.0
package host

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ironcore-dev/sonic-operator/internal/agent/artifactstate"
)

func TestImportedMACFixedCommands(t *testing.T) {
	for _, kind := range []string{"management-mac-python", "management-mac-shell"} {
		hook, helper, err := ImportedMACPaths(kind)
		if err != nil || hook == "" || helper == "" {
			t.Fatal(err)
		}
		if len(ImportedMACUnit(kind)) == 0 {
			t.Fatal("missing adapter")
		}
	}
	for _, kind := range []string{"rollback-management-mac", "rollback", "boot", "../management-mac-shell", "management-mac-shell; reboot"} {
		if _, _, err := ImportedMACPaths(kind); err == nil {
			t.Fatal("unknown helper accepted", kind)
		}
		n := &Native{}
		if n.ApplyImportedBootMAC(t.Context(), kind) == nil {
			t.Fatal("unknown helper dispatched")
		}
	}
}

func TestCapturedImportedBootMACGuards(t *testing.T) {
	for _, kind := range []string{"management-mac-python", "management-mac-shell"} {
		for _, change := range []string{"valid", "bootstrap-newline", "bootstrap-environment", "foreign-mac", "base", "addresses", "foreign-interface", "hostname", "vrf", "gateway", "helper", "interpreter", "typed-boot", "typed-dropin", "rollback-unit", "pending", "reservation"} {
			t.Run(kind+"/"+change, func(t *testing.T) {
				if change == "hostname" && kind == "management-mac-shell" {
					t.Skip("shell helper has no hostname selector")
				}
				helperName := "set-management-mac.sh"
				if kind == "management-mac-python" {
					helperName = "management-only-mac.py"
				}
				dir := os.Getenv("SONIC_TEST_MAC_FIXTURE_DIR")
				if dir == "" {
					t.Skip("set SONIC_TEST_MAC_FIXTURE_DIR to the captured MAC helper scripts")
				}
				helper, err := os.ReadFile(filepath.Join(dir, helperName))
				if err != nil {
					t.Fatal("captured helper fixture unavailable", err)
				}
				if !hashMatches(helper, ImportedHelperSHA256(kind)) {
					t.Fatal("capture differs from approved helper")
				}
				h := LegacyMACHook{Kind: kind, BaseMAC: "00:00:5e:00:53:01", MAC: "02:00:5e:00:53:01", Addresses: []Address{{Prefix: "10.0.0.22/24", Gateway: "10.0.0.1"}}, HelperSHA256: ImportedHelperSHA256(kind), HookSHA256: digestForTest(string(ImportedMACUnit(kind)))}
				if kind == "management-mac-python" {
					h.BaseMAC = "00:00:5e:00:53:02"
					h.MAC = "02:00:5e:00:53:02"
					h.Addresses[0].Prefix = "10.0.0.21/24"
					h.Hostname = "leaf-01"
				}
				files := map[string][]byte{"/etc/sonic/sonic_version.yml": []byte("image"), interfacesTemplate: []byte("interfaces"), chronyTemplate: []byte("chrony"), snmpTemplate: []byte("snmp"), "/usr/bin/python3": []byte("interpreter"), "/bin/sh": []byte("interpreter")}
				files["/proc/sys/kernel/hostname"] = []byte("leaf-01\n")
				p := NativeProfile{ImageSHA256: digestForTest("image"), SNMPSHA256: digestForTest("snmp"), ConsumerSHA256: map[string]string{}, LegacyMACHooks: []LegacyMACHook{h}}
				for _, domain := range []string{"Management", "chrony", "snmp"} {
					for _, c := range consumerPaths(domain) {
						files[c.path] = []byte(c.key)
						p.ConsumerSHA256[c.key] = digestForTest(c.key)
					}
				}
				key := "imported-shell"
				if kind == "management-mac-python" {
					key = "imported-python"
				}
				p.ConsumerSHA256[key] = digestForTest("interpreter")
				installFixtureSuite(files, p)
				hookPath, helperPath, _ := ImportedMACPaths(kind)
				files[hookPath] = ImportedMACUnit(kind)
				files[helperPath] = helper
				var receipt InstallationReceipt
				_ = json.Unmarshal(files[RecoveryReceiptFile], &receipt)
				receipt.Files[hookPath] = h.HookSHA256
				receipt.Files[helperPath] = h.HelperSHA256
				sourceHash := digestForTest("original-source")
				receipt.Sources = map[string]string{h.Kind: sourceHash}
				files[RecoveryBootstrapDir+"/content/"+sourceHash] = []byte("original-source")
				files[RecoveryReceiptFile], _ = json.Marshal(receipt)
				_ = json.Unmarshal(files[profileFile], &p)
				active, base := h.BaseMAC, h.BaseMAC
				bootstrap := strings.HasPrefix(change, "bootstrap-")
				if bootstrap {
					active = h.MAC
				}
				if change == "bootstrap-environment" {
					var raw map[string]any
					_ = json.Unmarshal(files[profileFile], &raw)
					raw["importedMACEnvironment"] = "sonic-dpu-none-v1"
					files[profileFile], _ = json.Marshal(raw)
				}
				source := strings.TrimSuffix(h.Addresses[0].Prefix, "/24")
				gateway := "10.0.0.1"
				db := Database{"MGMT_INTERFACE": {"eth0|" + h.Addresses[0].Prefix: {"gwaddr": gateway}}}
				journal := t.TempDir()
				_ = os.Chmod(journal, 0700)
				reservation := t.TempDir()
				_ = os.Chmod(reservation, 0700)
				var pendingEngine *Engine
				var pendingClock *time.Time
				switch change {
				case "foreign-mac":
					active = "02:00:00:00:00:88"
				case "base":
					base = "02:00:00:00:00:88"
				case "addresses":
					db["MGMT_INTERFACE"] = map[string]map[string]string{"eth0|10.0.0.88/24": {"gwaddr": gateway}}
				case "foreign-interface":
					db["MGMT_INTERFACE"]["eth1|192.0.2.1/24"] = map[string]string{"NULL": "NULL"}
				case "hostname":
					files["/proc/sys/kernel/hostname"] = []byte("unknown-switch\n")
				case "vrf":
					db["MGMT_VRF_CONFIG"] = map[string]map[string]string{"vrf_global": {"mgmtVrfEnabled": "true"}}
				case "gateway":
					gateway = "10.0.0.2"
				case "helper":
					files[helperPath] = []byte("unknown")
				case "interpreter":
					files["/usr/bin/python3"] = []byte("unknown")
					files["/bin/sh"] = []byte("unknown")
				case "typed-boot":
					files[bootFile] = []byte(`{"mac":"02:00:00:00:00:88"}`)
				case "typed-dropin":
					files[macDropIn] = []byte(macUnit)
				case "pending":
					e, _, clock := newTestEngine(t)
					pendingEngine, pendingClock = e, clock
					q := managementRequest()
					q.Management.Addresses[0].Prefix = "10.0.0.99/24"
					if _, err := e.Ensure(t.Context(), q, "first"); err != nil {
						t.Fatal(err)
					}
					journal = e.dir
				case "reservation":
					raw, _ := json.Marshal(artifactstate.Reservation{Version: 1, Owner: "owner", Token: strings.Repeat("a", 32), Manifest: strings.Repeat("b", 64), Phase: "Active"})
					if err := os.WriteFile(filepath.Join(reservation, "reservation.json"), raw, 0600); err != nil {
						t.Fatal(err)
					}
				}
				calls := 0
				n := &Native{journalDir: journal, BaseMAC: func(context.Context) (string, error) { return base, nil }, BeforePublication: func(context.Context) error { return artifactstate.CheckPending(reservation) }, WithMutation: func(_ context.Context, fn func() error) error { return fn() }, Load: func(context.Context) (Database, error) { return db, nil }, ReadFile: func(path string) ([]byte, error) {
					b, ok := files[path]
					if !ok {
						return nil, os.ErrNotExist
					}
					return b, nil
				}}
				n.Run = func(_ context.Context, args []string, _ []byte) ([]byte, error) {
					if b, ok := fixtureRecoveryUnit(args); ok {
						return b, nil
					}
					if args[0] == helperPath || args[0] == "/usr/bin/python3" {
						want := helperPath
						if kind == "management-mac-python" {
							want = "/usr/bin/python3 " + helperPath + " boot"
						}
						if strings.Join(args, " ") != want {
							t.Fatal("non-boot helper dispatch", args)
						}
						calls++
						active = h.MAC
						return nil, nil
					}
					if args[0] == "systemctl" {
						if change == "bootstrap-environment" {
							if b, ok := fixtureImportedEnvironmentProperty(args); ok {
								return b, nil
							}
						}
						for _, a := range args {
							switch a {
							case "--property=DropInPaths":
								if change == "bootstrap-environment" {
									return []byte("/run/systemd/generator/interfaces-config.service.d/environment.conf " + hookPath), nil
								}
								return []byte(hookPath), nil
							case "--property=NeedDaemonReload":
								return []byte("no"), nil
							case "--property=ExecStartPost":
								if bootstrap {
									command := helperPath
									if kind == "management-mac-python" {
										command = "/usr/bin/python3 " + helperPath + " boot"
									}
									return []byte("{ path=" + strings.Fields(command)[0] + " ; argv[]=" + command + " ; }"), nil
								}
								return []byte("{ path=" + RecoveryBinaryFile + " ; argv[]=" + RecoveryBinaryFile + " --apply-imported-boot-mac=" + kind + " ; }"), nil
							}
						}
						if change == "rollback-unit" {
							return []byte("Id=unknown-rollback.service\nExecStart=/usr/local/sbin/rollback-management-mac"), nil
						}
						if bootstrap {
							b, err := os.ReadFile("testdata/imported-mac/loaded-interfaces.txt")
							if err != nil {
								t.Fatal(err)
							}
							text := strings.TrimSuffix(string(b), "\n")
							if kind == "management-mac-python" {
								text = strings.ReplaceAll(text, "path=/usr/local/sbin/set-management-mac", "path=/usr/bin/python3")
								text = strings.ReplaceAll(text, "argv[]=/usr/local/sbin/set-management-mac", "argv[]=/usr/bin/python3 "+helperPath+" boot")
							}
							return []byte(text), nil
						}
						return []byte("Id=interfaces-config.service\nExecStartPost=" + RecoveryBinaryFile), nil
					}
					if args[0] == "docker" {
						if args[1] == "inspect" {
							return []byte(`{"Id":"` + strings.Repeat("a", 64) + `","Image":"sha256:` + strings.Repeat("b", 64) + `","State":{"Running":true},"Config":{"Entrypoint":["/usr/bin/docker-snmp-init.sh"]}}`), nil
						}
						if args[1] == "cp" {
							_, path, _ := strings.Cut(args[3], ":")
							data := files[path]
							var buf bytes.Buffer
							w := tar.NewWriter(&buf)
							_ = w.WriteHeader(&tar.Header{Name: filepath.Base(path), Mode: 0644, Size: int64(len(data))})
							_, _ = w.Write(data)
							_ = w.Close()
							return buf.Bytes(), nil
						}
					}
					joined := strings.Join(args, " ")
					if strings.Contains(joined, "-j address") {
						return []byte(`[{"ifname":"eth0","address":"` + active + `","flags":["UP"],"addr_info":[{"local":"` + source + `","prefixlen":24,"scope":"global"}]}]`), nil
					}
					if strings.Contains(joined, "-j rule") {
						return []byte(`[{"priority":32765,"src":"` + source + `","table":"default"}]`), nil
					}
					if strings.Contains(joined, "-j route") {
						if args[1] == "-6" {
							return []byte(`[]`), nil
						}
						return []byte(`[{"dst":"10.0.0.0/24","table":"default"},{"dst":"default","gateway":"` + gateway + `","table":"default","metric":201}]`), nil
					}
					return nil, ErrNative
				}
				n.ReadUnitFile = func(path string) ([]byte, os.FileInfo, error) {
					b, err := os.ReadFile("testdata/imported-mac/" + filepath.Base(path))
					if path == hookPath {
						b, err = []byte("[Service]\nExecStartPost="+originalImportedCommand(kind)+"\n"), nil
					}
					return b, unitFixtureInfo{size: int64(len(b)), mode: 0644, stat: syscall.Stat_t{Uid: 0, Gid: 0, Nlink: 1}}, err
				}
				if bootstrap {
					if err = n.QualifyBootstrapProfile(t.Context(), files[profileFile], false); err != nil || calls != 0 {
						t.Fatalf("read-only bootstrap qualification failed: %v calls=%d", err, calls)
					}
					return
				}
				err = n.ApplyImportedBootMAC(t.Context(), kind)
				if change == "valid" {
					if err != nil || calls != 1 || active != h.MAC || base != h.BaseMAC {
						t.Fatalf("qualified fixed boot failed: %v calls=%d", err, calls)
					}
				} else if err == nil || calls != 0 {
					t.Fatalf("unqualified boot dispatched: %v calls=%d", err, calls)
				}
				if change == "pending" {
					*pendingClock = pendingClock.Add(61 * time.Second)
					if err := pendingEngine.RecoverExpired(t.Context()); err != nil {
						t.Fatal(err)
					}
					if err := n.ApplyImportedBootMAC(t.Context(), kind); err != nil || calls != 1 {
						t.Fatal("boot retry after recorded recovery failed", err, calls)
					}
				}
				if change == "valid" {
					calls = 0
					if err = n.QualifyImportedAdoption(t.Context(), p); err != nil || calls != 0 {
						t.Fatal("equal adoption invoked helper", err)
					}
				}
			})
		}
	}
}

func TestImportedIdentityHostname(t *testing.T) {
	for _, tc := range []struct {
		kind, hostname string
		ok             bool
	}{
		{ImportedKindPython, "leaf-01", true},
		{ImportedKindPython, "", false},
		{ImportedKindPython, "Leaf_01", false},
		{ImportedKindShell, "", true},
		{ImportedKindShell, "leaf-01", false},
	} {
		h := LegacyMACHook{Kind: tc.kind, Hostname: tc.hostname, HelperSHA256: ImportedHelperSHA256(tc.kind), HookSHA256: digestForTest(string(ImportedMACUnit(tc.kind))), Addresses: []Address{{Prefix: "10.0.0.21/24", Gateway: "10.0.0.1"}}}
		if err := validateImportedIdentity(h); (err == nil) != tc.ok {
			t.Errorf("%s/%q: got %v", tc.kind, tc.hostname, err)
		}
	}
}

type unitFixtureInfo struct {
	size int64
	mode os.FileMode
	stat syscall.Stat_t
}

func (i unitFixtureInfo) Name() string       { return "fixture" }
func (i unitFixtureInfo) Size() int64        { return i.size }
func (i unitFixtureInfo) Mode() os.FileMode  { return i.mode }
func (i unitFixtureInfo) ModTime() time.Time { return time.Time{} }
func (i unitFixtureInfo) IsDir() bool        { return false }
func (i unitFixtureInfo) Sys() any           { return &i.stat }

func fixtureImportedEnvironmentProperty(args []string) ([]byte, bool) {
	for _, a := range args {
		switch a {
		case "--property=FragmentPath":
			return []byte("/usr/lib/systemd/system/interfaces-config.service\n"), true
		case "--property=Environment":
			return []byte("NUM_DPU=0 IS_DPU_DEVICE=false\n"), true
		case "--property=Type":
			return []byte("oneshot\n"), true
		case "--property=RemainAfterExit":
			return []byte("yes\n"), true
		case "--property=DynamicUser":
			return []byte("no\n"), true
		case "--property=ExecStart":
			return []byte("{ path=/usr/bin/interfaces-config.sh ; argv[]=/usr/bin/interfaces-config.sh ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n"), true
		case "--property=EnvironmentFiles", "--property=PassEnvironment", "--property=UnsetEnvironment", "--property=User", "--property=Group", "--property=SupplementaryGroups", "--property=RootDirectory", "--property=RootImage", "--property=WorkingDirectory", "--property=ExecSearchPath", "--property=ExecStartPre", "--property=ExecReload", "--property=ExecStop", "--property=ExecStopPost":
			return []byte("\n"), true
		}
	}
	return nil, false
}
