// SPDX-License-Identifier: Apache-2.0
package host

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestFleetDistributionContracts(t *testing.T) {
	for name, data := range map[string][]byte{"service": RecoveryServiceUnit(), "timer": RecoveryTimerUnit()} {
		installed, err := os.ReadFile("../../../config/agent/sonic-operator-host-recovery." + name)
		if err != nil || !bytes.Equal(installed, data) {
			t.Fatalf("generated %s differs", name)
		}
	}
	cfg := FleetRecoveryConfig()
	if cfg.RedisAddress != "127.0.0.1:6379" || cfg.JournalDir != "/host/sonic-operator-host-journal" {
		t.Fatal(cfg)
	}
	if _, err := EncodeRecoveryConfig(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.RedisAddress = "remote:6379"
	if _, err := EncodeRecoveryConfig(cfg); err == nil {
		t.Fatal("arbitrary redis accepted")
	}
	for _, file := range []string{"202411.1216684-48c2d4c3e.json", "202511.1217682-4784cca11.json"} {
		b, err := os.ReadFile("../../../config/agent/profiles/" + file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ValidateNativeProfile(b); err != nil {
			t.Fatal(file, err)
		}
		if _, err := ValidateNativeProfile(bytes.Replace(b, []byte("interfaces-generator"), []byte("arbitrary-consumer"), 1)); err == nil {
			t.Fatal("unknown consumer accepted")
		}
	}
}

func installFixtureSuite(files map[string][]byte, p NativeProfile) {
	p.InterfacesSHA256 = digestForTest("interfaces")
	p.NTPBackend = "chrony"
	p.ChronySHA256 = digestForTest("chrony")
	for _, domain := range []string{"Management", "chrony"} {
		for _, c := range consumerPaths(domain) {
			p.ConsumerSHA256[c.key] = digestForTest(c.key)
		}
	}
	files[profileFile], _ = json.Marshal(p)
	files[RecoveryConfigFile], _ = EncodeRecoveryConfig(FleetRecoveryConfig())
	files[RecoveryBinaryFile] = []byte("qualified-fixture-binary")
	files[RecoveryServiceFile] = RecoveryServiceUnit()
	files[RecoveryTimerFile] = RecoveryTimerUnit()
	r := InstallationReceipt{Owner: "fixture", Target: "target", Baseline: "baseline", SuiteSHA256: digestForTest("suite"), Phase: "Confirmed", Files: map[string]string{}}
	for _, path := range []string{profileFile, RecoveryConfigFile, RecoveryBinaryFile, RecoveryServiceFile, RecoveryTimerFile} {
		r.Files[path] = digestForTest(string(files[path]))
	}
	files[RecoveryReceiptFile], _ = json.Marshal(r)
}
func fixtureRecoveryUnit(args []string) ([]byte, bool) {
	if len(args) < 3 || args[0] != "systemctl" || !strings.Contains(args[len(args)-1], "sonic-operator-host-recovery") {
		return nil, false
	}
	if args[1] == "is-enabled" {
		return []byte("enabled"), true
	}
	if args[1] == "is-active" {
		return []byte("active"), true
	}
	for _, a := range args {
		if a == "--property=TimersCalendar" {
			return nil, true
		}
		if a == "--property=After" {
			return []byte("database.service"), true
		}
		if value, ok := map[string]string{"--property=Type": "oneshot", "--property=User": "root", "--property=UMask": "0077", "--property=TimeoutStartUSec": "45s", "--property=RequiresMountsFor": "/host", "--property=Unit": "sonic-operator-host-recovery.service", "--property=AccuracyUSec": "1s", "--property=TimersMonotonic": "{ OnBootUSec=1s ; } { OnUnitActiveUSec=5s ; }"}[a]; ok {
			return []byte(value), true
		}
		switch a {
		case "--property=FragmentPath":
			return []byte("/etc/systemd/system/" + args[len(args)-1]), true
		case "--property=DropInPaths":
			return nil, true
		case "--property=NeedDaemonReload":
			return []byte("no"), true
		case "--property=ExecStart":
			return []byte("{ path=" + RecoveryBinaryFile + " ; argv[]=" + RecoveryBinaryFile + " ; }"), true
		}
	}
	return nil, false
}

func TestWatchdogTimerAloneIsNotInstallationAuthority(t *testing.T) {
	n := &Native{Run: func(_ context.Context, args []string, _ []byte) ([]byte, error) {
		if args[1] == "is-enabled" {
			return []byte("enabled"), nil
		}
		return []byte("active"), nil
	}, ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist }}
	if n.WatchdogReady(t.Context()) == nil {
		t.Fatal("timer alone authorized management")
	}
}

func TestWatchdogRejectsInstalledAndEffectiveDrift(t *testing.T) {
	for _, change := range []string{"valid", "binary", "config", "profile", "receipt", "executable", "drop-in", "reload", "timer-target", "interval"} {
		t.Run(change, func(t *testing.T) {
			files := map[string][]byte{}
			p := NativeProfile{ImageSHA256: digestForTest("image"), SNMPSHA256: digestForTest("snmp"), ConsumerSHA256: map[string]string{}}
			for _, c := range consumerPaths("snmp") {
				p.ConsumerSHA256[c.key] = digestForTest(c.key)
			}
			installFixtureSuite(files, p)
			switch change {
			case "binary":
				files[RecoveryBinaryFile] = []byte("changed")
			case "config":
				files[RecoveryConfigFile] = []byte(`{"redisAddress":"foreign"}`)
			case "profile":
				files[profileFile] = []byte("{}")
			case "receipt":
				delete(files, RecoveryReceiptFile)
			}
			n := &Native{ReadFile: func(path string) ([]byte, error) {
				b, ok := files[path]
				if !ok {
					return nil, os.ErrNotExist
				}
				return b, nil
			}, Run: func(_ context.Context, args []string, _ []byte) ([]byte, error) {
				for _, a := range args {
					if (change == "executable" && a == "--property=ExecStart") || (change == "drop-in" && a == "--property=DropInPaths") || (change == "reload" && a == "--property=NeedDaemonReload") || (change == "timer-target" && a == "--property=Unit") || (change == "interval" && a == "--property=TimersMonotonic") {
						return []byte("foreign"), nil
					}
				}
				if b, ok := fixtureRecoveryUnit(args); ok {
					return b, nil
				}
				return nil, ErrNative
			}}
			err := n.WatchdogReady(t.Context())
			if (err == nil) != (change == "valid") {
				t.Fatalf("drift %s readiness %v", change, err)
			}
		})
	}
}
