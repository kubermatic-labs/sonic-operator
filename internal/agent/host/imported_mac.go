// SPDX-License-Identifier: Apache-2.0
package host

import (
	"context"
	"errors"
	"os"
	"regexp"
	"strings"
)

const (
	ImportedKindPython = "management-mac-python"
	ImportedKindShell  = "management-mac-shell"
)

var hostnamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func ImportedMACPaths(kind string) (string, string, error) {
	switch kind {
	case ImportedKindPython:
		return "/etc/systemd/system/interfaces-config.service.d/dc-management-mac.conf", "/usr/local/sbin/dc-management-only-mac.py", nil
	case ImportedKindShell:
		return "/etc/systemd/system/interfaces-config.service.d/management-mac.conf", "/usr/local/sbin/set-management-mac", nil
	default:
		return "", "", ErrInvalid
	}
}
func ImportedMACUnit(kind string) []byte {
	if _, _, err := ImportedMACPaths(kind); err != nil {
		return nil
	}
	return []byte("[Service]\nExecStartPost=" + RecoveryBinaryFile + " --apply-imported-boot-mac=" + kind + "\n")
}
func ImportedHelperSHA256(kind string) string {
	switch kind {
	case ImportedKindPython:
		return "5d020956ceea96e17c8691fea273018c990261daffe0323946820a4c396ddfbd"
	case ImportedKindShell:
		return "a4a14aa61e99f369426bf7e23514442bd38128686ef9aad1499c09ad9b847d7d"
	}
	return ""
}

// validateImportedIdentity checks only the pinned helper/adapter identity and
// the declaration shape. Site identity (MACs, addresses, hostname) is declared in
// the profile and verified against live switch state during qualification.
func validateImportedIdentity(h LegacyMACHook) error {
	if h.HelperSHA256 != ImportedHelperSHA256(h.Kind) || !hashMatches(ImportedMACUnit(h.Kind), h.HookSHA256) || len(h.Addresses) != 1 {
		return ErrInvalid
	}
	// The Python helper selects its MAC by hostname, so the profile must name the
	// switch it was qualified on; the shell helper has no hostname selector.
	if (h.Kind == ImportedKindPython) != (h.Hostname != "") || (h.Hostname != "" && !hostnamePattern.MatchString(h.Hostname)) {
		return ErrInvalid
	}
	return nil
}

func (n *Native) importedState(ctx context.Context, p NativeProfile, boot bool, adoption ...bool) (LegacyMACHook, error) {
	if len(p.LegacyMACHooks) != 1 || n.BaseMAC == nil {
		return LegacyMACHook{}, ErrNative
	}
	h := p.LegacyMACHooks[0]
	hook, helper, err := ImportedMACPaths(h.Kind)
	if err != nil {
		return h, err
	}
	if h.HelperSHA256 != ImportedHelperSHA256(h.Kind) {
		return h, ErrNative
	}
	b, err := n.read(helper)
	if err != nil || !hashMatches(b, h.HelperSHA256) {
		return h, ErrNative
	}
	b, err = n.read(hook)
	if err != nil || !hashMatches(b, h.HookSHA256) || !hashMatches(ImportedMACUnit(h.Kind), h.HookSHA256) {
		return h, ErrNative
	}
	if _, err = n.read(macDropIn); !errors.Is(err, os.ErrNotExist) {
		return h, ErrConflict
	}
	mac, err := n.bootMAC()
	if err != nil || mac != "" {
		return h, ErrConflict
	}
	base, err := n.BaseMAC(ctx)
	if err != nil || base != h.BaseMAC {
		return h, ErrConflict
	}
	interpreter, key := "/bin/sh", "imported-shell"
	if h.Kind == ImportedKindPython {
		interpreter, key = "/usr/bin/python3", "imported-python"
		name, err := n.read("/proc/sys/kernel/hostname")
		if err != nil || h.Hostname == "" || strings.TrimSpace(string(name)) != h.Hostname {
			return h, ErrConflict
		}
	}
	b, err = n.read(interpreter)
	if err != nil || !hashMatches(b, p.ConsumerSHA256[key]) {
		return h, ErrNative
	}
	db, err := n.Load(ctx)
	if err != nil {
		return h, err
	}
	// The pinned scripts are qualified for a single exact management interface
	// and the default policy table, not additional interfaces or management VRF.
	if len(db["MGMT_INTERFACE"]) != len(h.Addresses) || db["MGMT_VRF_CONFIG"]["vrf_global"]["mgmtVrfEnabled"] == "true" {
		return h, ErrConflict
	}
	desired := Management{Interface: "eth0", Addresses: h.Addresses}
	if err = n.validateLegacyMACHooks(desired, p, db); err != nil {
		return h, err
	}
	snapshot, err := n.Snapshot(ctx)
	if err != nil {
		return h, err
	}
	if snapshot.ActiveMAC != h.MAC && (!boot || snapshot.ActiveMAC != h.BaseMAC) {
		return h, ErrConflict
	}
	desired.MAC = snapshot.ActiveMAC
	addresses, err := n.run(ctx, "ip", "-j", "address", "show", "dev", "eth0")
	if err != nil {
		return h, err
	}
	routes, err := n.managementRoutes(ctx)
	if err != nil || !managementRuntimeMatches(desired, addresses, routes) {
		return h, ErrNative
	}
	for _, a := range h.Addresses {
		rules, err := n.run(ctx, "ip", family(a.Prefix), "-j", "rule", "show")
		if err != nil || !managementRuleMatches(a, rules) {
			return h, ErrNative
		}
	}
	if len(adoption) < 2 || !adoption[1] {
		for property, want := range map[string]string{"DropInPaths": hook, "NeedDaemonReload": "no"} {
			value, err := n.run(ctx, "systemctl", "show", "--property="+property, "--value", "interfaces-config.service")
			if err != nil || strings.TrimSpace(string(value)) != want {
				return h, ErrNative
			}
		}
		effective, err := n.run(ctx, "systemctl", "show", "--property=ExecStartPost", "--value", "interfaces-config.service")
		want := RecoveryBinaryFile + " --apply-imported-boot-mac=" + h.Kind
		if len(adoption) > 0 && adoption[0] {
			if h.Kind == ImportedKindPython {
				want = "/usr/bin/python3 " + helper + " boot"
			} else {
				want = helper
			}
		}
		if err != nil || strings.Count(string(effective), "path=") != 1 || (!strings.Contains(string(effective), "argv[]="+want+" ;") && !strings.Contains(string(effective), "argv[]="+RecoveryBinaryFile+" --apply-imported-boot-mac="+h.Kind+" ;")) {
			return h, ErrNative
		}
	}
	// Query loaded activation commands, including timers' service targets. Unknown
	// historical rollback activation is not retirement authority.
	units, err := n.run(ctx, "systemctl", "show", "--all", "--type=service", "--property=Id,ExecStart,ExecStartPre,ExecStartPost", "*.service")
	if err != nil || len(units) == 0 {
		return h, ErrNative
	}
	for _, block := range strings.Split(string(units), "\n\n") {
		if strings.Contains(block, "rollback-management-mac") || (strings.Contains(strings.ToLower(block), "rollback") && strings.Contains(strings.ToLower(block), "mac")) {
			return h, ErrConflict
		}
		originalAllowed := len(adoption) > 0 && adoption[0] && strings.Contains(block, "Id=interfaces-config.service\n")
		if (strings.Contains(block, "dc-management-only-mac.py") || strings.Contains(block, "/usr/local/sbin/set-management-mac")) && !originalAllowed {
			return h, ErrConflict
		}
	}
	return h, nil
}

// QualifyBootstrapProfile overlays only the declared profile and fixed generated
// adapter for read-only preinstallation qualification. Existing helper bytes,
// image, consumers, management state and other activation paths remain measured.
func (n *Native) QualifyBootstrapProfile(ctx context.Context, raw []byte, repair bool) error {
	p, err := ValidateNativeProfile(raw)
	if err != nil {
		return err
	}
	copy := *n
	copy.ReadFile = func(path string) ([]byte, error) {
		if path == profileFile {
			return raw, nil
		}
		for _, h := range p.LegacyMACHooks {
			hook, helper, _ := ImportedMACPaths(h.Kind)
			if path == hook {
				return ImportedMACUnit(h.Kind), nil
			}
			if repair && path == helper {
				return n.read(RecoveryBootstrapDir + "/content/" + h.HelperSHA256)
			}
		}
		return n.read(path)
	}
	if _, err = copy.QualifyInstalledProfile(ctx); err != nil {
		return err
	}
	if len(p.LegacyMACHooks) > 0 {
		_, err = copy.importedState(ctx, p, false, true, repair)
	}
	return err
}

// QualifyImportedAdoption is read-only. A differing active MAC requires a
// separately reviewed timed recovery, never a link flap during bootstrap.
func (n *Native) QualifyImportedAdoption(ctx context.Context, p NativeProfile) error {
	if len(p.LegacyMACHooks) == 0 {
		return nil
	}
	_, err := n.importedState(ctx, p, false)
	return err
}

func (n *Native) ApplyImportedBootMAC(ctx context.Context, kind string) error {
	_, helper, err := ImportedMACPaths(kind)
	if err != nil {
		return err
	}
	return n.Exclusive(ctx, func(locked context.Context) error {
		if err := n.CheckPublication(locked); err != nil {
			return err
		}
		return WithArtifactExclusion(locked, n.journalDir, func() error {
			if _, err := n.InstallationReceipt(true); err != nil {
				return err
			}
			p, err := n.QualifyInstalledProfile(locked)
			if err != nil {
				return err
			}
			h, err := n.importedState(locked, p, true)
			if err != nil || h.Kind != kind {
				return ErrConflict
			}
			args := []string{helper}
			if kind == ImportedKindPython {
				args = []string{"/usr/bin/python3", helper, "boot"}
			}
			if _, err = n.run(locked, args...); err != nil {
				return err
			}
			_, err = n.importedState(locked, p, false)
			return err
		})
	})
}
