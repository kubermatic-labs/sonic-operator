// SPDX-License-Identifier: Apache-2.0
package host

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/ironcore-dev/sonic-operator/internal/agent/releaseinfo"
)

const (
	RecoveryBinaryFile   = "/usr/local/sbin/sonic-operator-host-recovery"
	RecoveryServiceFile  = "/etc/systemd/system/sonic-operator-host-recovery.service"
	RecoveryTimerFile    = "/etc/systemd/system/sonic-operator-host-recovery.timer"
	RecoveryProfileFile  = profileFile
	RecoveryBootstrapDir = "/host/sonic-operator-host-bootstrap"
	RecoveryReceiptFile  = RecoveryBootstrapDir + "/owner.json"
)

func FleetRecoveryConfig() RecoveryConfig {
	return RecoveryConfig{JournalDir: "/host/sonic-operator-host-journal", RedisAddress: "127.0.0.1:6379", VLANJournalDir: "/host/sonic-operator-vlan-journal", BreakoutJournalDir: "/host/sonic-operator-breakout-journal", NetworkJournalDir: "/host/sonic-operator-network-journal"}
}
func EncodeRecoveryConfig(cfg RecoveryConfig) ([]byte, error) {
	if cfg != FleetRecoveryConfig() {
		return nil, ErrInvalid
	}
	return json.Marshal(cfg)
}
func RecoveryServiceUnit() []byte {
	return []byte(`[Unit]
Description=Recover expired SONiC operator management transactions locally
After=database.service
RequiresMountsFor=/host

[Service]
Type=oneshot
User=root
ExecStart=/usr/local/sbin/sonic-operator-host-recovery
TimeoutStartSec=45
UMask=0077
`)
}
func RecoveryTimerUnit() []byte {
	return []byte(`[Unit]
Description=Independent SONiC management rollback watchdog

[Timer]
OnBootSec=1s
OnUnitActiveSec=5s
AccuracySec=1s
Unit=sonic-operator-host-recovery.service

[Install]
WantedBy=timers.target
`)
}

var nativeSHA = regexp.MustCompile(`^[a-f0-9]{64}$`)

// ValidateNativeProfile accepts strict JSON and canonical typed values; whitespace
// does not affect qualification, but the publication hash pins the exact bytes.
//
//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func ValidateNativeProfile(data []byte) (NativeProfile, error) {
	var p NativeProfile
	if strictDecodeLimit(data, &p, 256<<10) != nil {
		return p, ErrInvalid
	}
	for _, s := range []string{p.ImageSHA256, p.InterfacesSHA256, p.SNMPSHA256} {
		if !nativeSHA.MatchString(s) {
			return p, ErrInvalid
		}
	}
	if (p.NTPBackend == "chrony" && (!nativeSHA.MatchString(p.ChronySHA256) || p.NTPsecSHA256 != "")) || (p.NTPBackend == "ntpsec" && (!nativeSHA.MatchString(p.NTPsecSHA256) || p.ChronySHA256 != "")) || (p.NTPBackend != "chrony" && p.NTPBackend != "ntpsec") {
		return p, ErrInvalid
	}
	knownBackend := map[string]string{"31ccd7c70be24e278c746fc729f5cc9d8cf87bf5afe2472b34187090dfeb540e": "ntpsec", "0cd0ea6266506346ed0b456976bfa6ce6a6cca01f0494edf051cbe1d31a47906": "chrony"}
	if want, ok := knownBackend[p.ImageSHA256]; ok && p.NTPBackend != want {
		return p, ErrInvalid
	}
	expected := map[string]bool{}
	for _, domain := range []string{"Management", p.NTPBackend, "snmp"} {
		for _, c := range consumerPaths(domain) {
			expected[c.key] = true
		}
	}
	if len(p.LegacyMACHooks) > 1 {
		return p, ErrInvalid
	} // one eth0 MAC writer
	if p.ImportedMACEnvironment != "" && (p.ImportedMACEnvironment != ImportedMACEnvironmentNone || len(p.LegacyMACHooks) != 1) {
		return p, ErrInvalid
	}
	for _, h := range p.LegacyMACHooks {
		if h.Kind != ImportedKindPython && h.Kind != ImportedKindShell {
			return p, ErrInvalid
		}
		if !nativeSHA.MatchString(h.HookSHA256) || !nativeSHA.MatchString(h.HelperSHA256) || validateActiveMAC(h.MAC) != nil || validateActiveMAC(h.BaseMAC) != nil || ValidateManagement(Management{Interface: "eth0", MAC: h.MAC, Addresses: h.Addresses}) != nil {
			return p, ErrInvalid
		}
		if h.Kind == ImportedKindPython {
			expected["imported-python"] = true
		}
		if h.Kind == ImportedKindShell {
			expected["imported-shell"] = true
		}
		if validateImportedIdentity(h) != nil {
			return p, ErrInvalid
		}
	}
	if len(expected) != len(p.ConsumerSHA256) {
		return p, ErrInvalid
	}
	for key, hash := range p.ConsumerSHA256 {
		if !expected[key] || !nativeSHA.MatchString(hash) {
			return p, ErrInvalid
		}
	}
	return p, nil
}

// Qualification checks installed consumers without creating a daemon-runtime
// receipt or claiming that any running process loaded these bytes.
func (n *Native) QualifyInstalledProfile(ctx context.Context) (NativeProfile, error) {
	raw, err := n.read(profileFile)
	if err != nil {
		return NativeProfile{}, ErrNative
	}
	p, err := ValidateNativeProfile(raw)
	if err != nil {
		return p, err
	}
	if _, err = n.profile(ctx, "Management"); err != nil {
		return p, err
	}
	if _, err = n.ntpProfile(p); err != nil {
		return p, err
	}
	for _, domain := range []string{p.NTPBackend, "snmp"} {
		if err = n.verifyConsumers(ctx, p, domain); err != nil {
			return p, err
		}
	}
	b, err := n.containerFile(ctx, snmpTemplate)
	if err != nil || !hashMatches(b, p.SNMPSHA256) {
		return p, ErrNative
	}
	if p.ImportedMACEnvironment != "" {
		if err := n.qualifyImportedEnvironment(ctx, p); err != nil {
			return p, err
		}
	}
	return p, nil
}

// InstallationReceipt contains only immutable identities, never source bytes.
// All readers must understand its phase before enabling Host Manage.
type InstallationReceipt struct {
	Sources     map[string]string `json:"sources,omitempty"`
	Owner       string            `json:"owner"`
	Target      string            `json:"target"`
	Baseline    string            `json:"baseline"`
	SuiteSHA256 string            `json:"suiteSHA256"`
	Phase       string            `json:"phase"`
	Files       map[string]string `json:"files"`
}

type InstallationCheck struct {
	BinarySHA256  string   `json:"binarySHA256"`
	SourceCommit  string   `json:"sourceCommit"`
	Capabilities  []string `json:"capabilities"`
	SuiteSHA256   string   `json:"suiteSHA256"`
	ConfigSHA256  string   `json:"configSHA256"`
	ProfileSHA256 string   `json:"profileSHA256"`
}

func PublicInstallationCheck(r InstallationReceipt) InstallationCheck {
	i := releaseinfo.Current()
	return InstallationCheck{SourceCommit: i.SourceCommit, Capabilities: i.Capabilities, BinarySHA256: r.Files[RecoveryBinaryFile], SuiteSHA256: r.SuiteSHA256, ConfigSHA256: r.Files[RecoveryConfigFile], ProfileSHA256: r.Files[profileFile]}
}

func CheckInstallationReceipt(read func(string) ([]byte, error), confirmed bool) (InstallationReceipt, error) {
	var r InstallationReceipt
	raw, err := read(RecoveryReceiptFile)
	if err != nil || StrictDecode(raw, &r) != nil || r.Owner == "" || r.Target == "" || r.Baseline == "" || !nativeSHA.MatchString(r.SuiteSHA256) {
		return r, ErrStorage
	}
	if confirmed && r.Phase != "Confirmed" {
		return r, ErrStorage
	}
	if r.Phase != "Prepared" && r.Phase != "Installing" && r.Phase != "Verifying" && r.Phase != "Confirmed" {
		return r, ErrStorage
	}
	profile, err := read(profileFile)
	if err != nil {
		return r, ErrStorage
	}
	p, err := ValidateNativeProfile(profile)
	if err != nil {
		return r, err
	}
	cfg, _ := EncodeRecoveryConfig(FleetRecoveryConfig())
	required := map[string][]byte{RecoveryBinaryFile: nil, RecoveryServiceFile: RecoveryServiceUnit(), RecoveryTimerFile: RecoveryTimerUnit(), RecoveryConfigFile: cfg, profileFile: profile}
	for _, h := range p.LegacyMACHooks {
		hook, helper, err := ImportedMACPaths(h.Kind)
		if err != nil {
			return r, err
		}
		required[hook] = ImportedMACUnit(h.Kind)
		required[helper] = nil
		if r.Files[hook] != h.HookSHA256 || r.Files[helper] != h.HelperSHA256 {
			return r, ErrStorage
		}
		source := r.Sources[h.Kind]
		if !nativeSHA.MatchString(source) {
			return r, ErrStorage
		}
		original, err := read(RecoveryBootstrapDir + "/content/" + source)
		if err != nil || !hashMatches(original, source) {
			return r, ErrStorage
		}
	}
	if len(r.Sources) != len(p.LegacyMACHooks) {
		return r, ErrStorage
	}
	if len(r.Files) != len(required) {
		return r, ErrStorage
	}
	for path, want := range required {
		hash := r.Files[path]
		if !nativeSHA.MatchString(hash) {
			return r, ErrStorage
		}
		b, err := read(path)
		if err != nil || !hashMatches(b, hash) || (want != nil && !hashMatches(want, hash)) {
			return r, ErrStorage
		}
	}
	return r, nil
}

func (n *Native) VerifyRecoveryUnits(ctx context.Context) error {
	for _, unit := range []string{"sonic-operator-host-recovery.service", "sonic-operator-host-recovery.timer"} {
		for property, want := range map[string]string{"FragmentPath": "/etc/systemd/system/" + unit, "DropInPaths": "", "NeedDaemonReload": "no"} {
			b, err := n.run(ctx, "systemctl", "show", "--property="+property, "--value", unit)
			if err != nil || strings.TrimSpace(string(b)) != want {
				return ErrNative
			}
		}
	}
	for unit, props := range map[string]map[string]string{
		"sonic-operator-host-recovery.service": {"Type": "oneshot", "User": "root", "UMask": "0077", "TimeoutStartUSec": "45s", "RequiresMountsFor": "/host"},
		"sonic-operator-host-recovery.timer":   {"Unit": "sonic-operator-host-recovery.service", "AccuracyUSec": "1s", "TimersCalendar": ""},
	} {
		for property, want := range props {
			b, err := n.run(ctx, "systemctl", "show", "--property="+property, "--value", unit)
			if err != nil || strings.TrimSpace(string(b)) != want {
				return ErrNative
			}
		}
	}
	intervals, err := n.run(ctx, "systemctl", "show", "--property=TimersMonotonic", "--value", "sonic-operator-host-recovery.timer")
	if err != nil || strings.Count(string(intervals), "USec=") != 2 || !strings.Contains(string(intervals), "OnBootUSec=1s") || !strings.Contains(string(intervals), "OnUnitActiveUSec=5s") {
		return ErrNative
	}
	b, err := n.run(ctx, "systemctl", "show", "--property=ExecStart", "--value", "sonic-operator-host-recovery.service")
	if err != nil || strings.Count(string(b), "path=") != 1 || !strings.Contains(string(b), "path="+RecoveryBinaryFile+" ; argv[]="+RecoveryBinaryFile+" ;") {
		return ErrNative
	}
	after, err := n.run(ctx, "systemctl", "show", "--property=After", "--value", "sonic-operator-host-recovery.service")
	if err != nil || !strings.Contains(string(after), "database.service") || strings.Contains(string(after), "interfaces-config.service") {
		return ErrNative
	}
	return nil
}

// InstallationReceipt checks private-store and fixed-destination trust before
// interpreting any immutable authority. Injected IO is used by native fixtures.
//
//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func (n *Native) InstallationReceipt(confirmed bool) (InstallationReceipt, error) {
	if n.ReadFile == nil {
		dir, err := os.Open(RecoveryBootstrapDir)
		if err != nil {
			return InstallationReceipt{}, ErrStorage
		}
		err = dir.Sync()
		_ = dir.Close()
		if err != nil {
			return InstallationReceipt{}, ErrStorage
		}
		cfg := FleetRecoveryConfig()
		for _, dir := range []string{RecoveryBootstrapDir, cfg.JournalDir, cfg.VLANJournalDir, cfg.BreakoutJournalDir, cfg.NetworkJournalDir} {
			info, err := os.Lstat(dir)
			if err != nil || secureFile(info, true) != nil {
				return InstallationReceipt{}, ErrStorage
			}
			lock := ".lock"
			if dir == cfg.JournalDir {
				lock = "lock"
			}
			info, err = os.Lstat(filepath.Join(dir, lock))
			if err != nil || secureFile(info, false) != nil {
				return InstallationReceipt{}, ErrStorage
			}
		}
	}
	return CheckInstallationReceipt(func(path string) ([]byte, error) {
		if n.ReadFile == nil {
			for parent := filepath.Dir(path); parent != "/"; parent = filepath.Dir(parent) {
				info, err := os.Lstat(parent)
				if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
					return nil, ErrStorage
				}
				stat, ok := info.Sys().(*syscall.Stat_t)
				if !ok || stat.Uid != uint32(os.Geteuid()) {
					return nil, ErrStorage
				}
			}
			info, err := os.Lstat(path)
			if err != nil {
				return nil, err
			}
			mode := os.FileMode(0644)
			if path == RecoveryReceiptFile || path == RecoveryConfigFile || path == profileFile || strings.HasPrefix(path, RecoveryBootstrapDir+"/content/") {
				mode = 0600
			}
			if path == RecoveryBinaryFile || strings.HasPrefix(path, "/usr/local/sbin/") {
				mode = 0755
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != uint32(os.Geteuid()) || !info.Mode().IsRegular() || info.Mode().Perm() != mode {
				return nil, ErrStorage
			}
		}
		data, err := n.read(path)
		if err == nil && n.ReadFile == nil && path == RecoveryReceiptFile {
			f, e := os.Open(path)
			if e != nil {
				return nil, ErrStorage
			}
			e = f.Sync()
			_ = f.Close()
			if e != nil {
				return nil, ErrStorage
			}
			d, e := os.Open(filepath.Dir(path))
			if e != nil {
				return nil, ErrStorage
			}
			e = d.Sync()
			_ = d.Close()
			if e != nil {
				return nil, ErrStorage
			}
		}
		return data, err
	}, confirmed)
}
