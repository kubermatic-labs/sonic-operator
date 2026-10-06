// SPDX-License-Identifier: Apache-2.0
package host

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
)

// Transient native evidence only. It never enters public status or journals.
type daemonEvidence struct {
	PID              int        `json:"pid"`
	BootID           string     `json:"bootID"`
	File             daemonFile `json:"file"`
	Arguments        []string   `json:"arguments"`
	StartUptime      float64    `json:"startUptime"`
	ObservedWall     float64    `json:"observedWall"`
	ObservedUptime   float64    `json:"observedUptime"`
	ConfigModified   float64    `json:"configModified"`
	ConfigChanged    float64    `json:"configChanged"`
	ConfigDigest     string     `json:"configDigest"`
	EnvironmentClean bool       `json:"environmentClean"`
	AuxiliaryClean   bool       `json:"auxiliaryClean"`
}

func daemonConfigLoaded(mode string, v daemonEvidence, expected []byte, receipts ...*daemonReceipt) bool {
	if len(receipts) != 1 || receipts[0] == nil {
		return false
	}
	r := receipts[0]
	if r.BootID != v.BootID || r.PID != v.PID || r.StartUptime != v.StartUptime || r.File != v.File {
		return false
	}
	return daemonProcessMatches(mode, v, expected)
}
func daemonProcessMatches(mode string, v daemonEvidence, expected []byte) bool {
	if !v.EnvironmentClean || !v.AuxiliaryClean || !hashMatches(expected, v.ConfigDigest) || v.StartUptime <= 0 || v.ObservedUptime < v.StartUptime || v.BootID == "" || v.PID <= 0 || v.File.Inode == 0 {
		return false
	}
	args := slices.Clone(v.Arguments)
	switch mode {
	case "snmp":
		// Net-SNMP tokenizes its comma-separated -I argument in place; /proc
		// consequently exposes either one argument or multiple NUL-separated
		// fragments. Normalize only this known native argument.
		start, end := slices.Index(args, "-I"), slices.Index(args, "-p")
		if start < 0 || end <= start+1 {
			return false
		}
		args = append(append(slices.Clone(args[:start+1]), strings.Join(args[start+1:end], ",")), args[end:]...)
		return slices.Equal(args, []string{"/usr/sbin/snmpd", "-f", "-LS0-2d", "-u", "Debian-snmp", "-g", "Debian-snmp", "-I", "-smux,mteTrigger,mteTriggerConf,ifTable,ifXTable,inetCidrRouteTable,ipCidrRouteTable,ip,disk_hw", "-p", "/run/snmpd.pid"})
	case "ntpsec":
		return slices.Equal(args, []string{"/usr/sbin/ntpd", "-p", "/run/ntpd.pid", "-c", "/etc/ntpsec/ntp.conf", "-x", "-N", "-u", "ntpsec:ntpsec"})
	case "chrony":
		return slices.Equal(args, []string{"/usr/sbin/chronyd", "-F", "1"})
	default:
		return false
	}
}
func (n *Native) daemonEvidence(ctx context.Context, mode string) (daemonEvidence, error) {
	data, err := n.run(ctx, "python3", "-c", nativeDaemonProbe, mode)
	if err != nil {
		return daemonEvidence{}, err
	}
	var evidence daemonEvidence
	if json.Unmarshal(data, &evidence) != nil {
		return evidence, ErrNative
	}
	return evidence, nil
}
func (n *Native) daemonLoaded(ctx context.Context, mode string, expected []byte, q Request, p NativeProfile) bool {
	evidence, err := n.daemonEvidence(ctx, mode)
	if err != nil {
		return false
	}
	r, err := n.readDaemonReceipt(mode)
	if err != nil || r.Claim != *requestClaim(q) || r.Profile != profileIdentity(p) {
		return false
	}
	return daemonConfigLoaded(mode, evidence, expected, r)
}
