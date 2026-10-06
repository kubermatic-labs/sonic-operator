// SPDX-License-Identifier: Apache-2.0
package host

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// Explicit opt-in only. This test performs read-only SSH against operator-supplied
// switches. It cannot call CAS/save/activation/install. A locally declared profile
// is supplied in memory, never installed on a switch.
//
//	SONIC_HOST_READONLY_TARGETS   comma-separated host=profile pairs, e.g. leaf-01=202511.1217682-4784cca11
//	SONIC_HOST_SSH_ROOT           absolute directory the ssh command runs in
//	SONIC_HOST_SSH_CONFIG         ssh config file, relative to SONIC_HOST_SSH_ROOT
//	SONIC_HOST_READONLY_MAC_HOOKS optional JSON file mapping host to []LegacyMACHook
func TestNativeReadOnlyQualification(t *testing.T) {
	if os.Getenv("SONIC_HOST_READONLY_QUALIFY") != "1" {
		t.Skip("read-only fleet qualification is opt-in")
	}
	root := os.Getenv("SONIC_HOST_SSH_ROOT")
	if !filepath.IsAbs(root) {
		t.Fatal("absolute SSH root required")
	}
	sshConfig := os.Getenv("SONIC_HOST_SSH_CONFIG")
	if sshConfig == "" {
		t.Fatal("SONIC_HOST_SSH_CONFIG required")
	}
	hooks := map[string][]LegacyMACHook{}
	if path := os.Getenv("SONIC_HOST_READONLY_MAC_HOOKS"); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil || json.Unmarshal(raw, &hooks) != nil {
			t.Fatal("invalid MAC hook declarations")
		}
	}
	var targets []struct{ host, image string }
	for _, pair := range strings.Split(os.Getenv("SONIC_HOST_READONLY_TARGETS"), ",") {
		host, image, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok || host == "" || image == "" {
			t.Fatal("SONIC_HOST_READONLY_TARGETS must be host=profile pairs")
		}
		targets = append(targets, struct{ host, image string }{host, image})
	}
	for _, tc := range targets {
		t.Run(tc.host, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
			defer cancel()
			profileData, err := os.ReadFile("../../../config/agent/profiles/" + tc.image + ".json")
			if err != nil {
				t.Fatal("qualification profile unavailable")
			}
			var profile NativeProfile
			if StrictDecode(profileData, &profile) != nil {
				t.Fatal("invalid public profile")
			}
			profile.LegacyMACHooks = hooks[tc.host]
			profileData, _ = json.Marshal(profile)
			ssh := func(ctx context.Context, args []string, input []byte) ([]byte, error) {
				quoted := make([]string, len(args))
				for i, a := range args {
					quoted[i] = "'" + strings.ReplaceAll(a, "'", "'\\''") + "'"
				}
				cmd := exec.CommandContext(ctx, "ssh", "-F", sshConfig, tc.host, "sudo -n "+strings.Join(quoted, " "))
				cmd.Dir = root
				cmd.Stdin = bytes.NewReader(input)
				cmd.Stderr = io.Discard
				out, e := cmd.Output()
				if e != nil {
					var exit *exec.ExitError
					if e2, ok := e.(*exec.ExitError); ok {
						exit = e2
					}
					if exit != nil && exit.ExitCode() == 44 {
						return nil, os.ErrNotExist
					}
					return nil, ErrNative
				}
				return out, nil
			}
			n := &Native{}
			n.ReadFile = func(path string) ([]byte, error) {
				if path == profileFile {
					return profileData, nil
				}
				return ssh(ctx, []string{"python3", "-c", qualificationReadFile, path}, nil)
			}
			n.Run = func(ctx context.Context, args []string, input []byte) ([]byte, error) {
				if !qualificationReadOnlyCommand(args) {
					t.Fatal("native qualification attempted a non-read operation")
				}
				return ssh(ctx, args, input)
			}
			n.Load = func(ctx context.Context) (Database, error) {
				data, e := n.run(ctx, "sonic-cfggen", "-d", "--print-data")
				if e != nil {
					return nil, e
				}
				var raw map[string]json.RawMessage
				if json.Unmarshal(data, &raw) != nil {
					return nil, ErrNative
				}
				db := Database{}
				for _, table := range HostTables {
					if len(raw[table]) == 0 {
						continue
					}
					var rows map[string]map[string]string
					if json.Unmarshal(raw[table], &rows) != nil {
						return nil, ErrNative
					}
					for key, v := range rows {
						if len(v) == 0 {
							rows[key] = map[string]string{"NULL": "NULL"}
						}
					}
					db[table] = rows
				}
				return db, nil
			}
			n.SNMPExchange = func(ctx context.Context, packet []byte) ([]byte, error) {
				return ssh(ctx, []string{"python3", "-c", qualificationSNMPExchange}, packet)
			}
			n.CAS = func(context.Context, Database, Database) error {
				t.Fatal("CAS prohibited in read-only qualification")
				return ErrNative
			}
			n.Save = func(context.Context) error { t.Fatal("save prohibited in read-only qualification"); return ErrNative }
			n.WriteFile = func(string, []byte, os.FileMode) error {
				t.Fatal("file mutation prohibited in read-only qualification")
				return ErrNative
			}
			n.WithMutation = func(context.Context, func() error) error {
				t.Fatal("activation prohibited in read-only qualification")
				return ErrNative
			}
			db, err := n.Load(ctx)
			if err != nil {
				t.Fatal("read-only configuration snapshot unavailable")
			}
			management, err := managementFromDB(db, "")
			if err != nil {
				t.Fatal("management snapshot invalid")
			}
			system := System{NTP: &NTP{Servers: []string{}}, SNMP: &SNMP{Location: db["SNMP"]["LOCATION"]["Location"]}}
			for server := range db["NTP_SERVER"] {
				system.NTP.Servers = append(system.NTP.Servers, server)
			}
			if len(db["SNMP_COMMUNITY"]) > 1 {
				t.Fatal("qualification expects at most one declared community")
			}
			for community, fields := range db["SNMP_COMMUNITY"] {
				if fields["TYPE"] != "RO" {
					t.Fatal("qualification expects read-only community")
				}
				system.SNMP.Community = Credential(community)
			}
			for _, q := range []Request{{Kind: "Management", Owner: "readonly-qualification", Target: tc.host, Revision: "1", Management: &management, RollbackSeconds: 120}, {Kind: "System", Owner: "readonly-qualification", Target: tc.host, Revision: "1", System: &system}} {
				if err := n.Validate(ctx, q); err != nil {
					t.Fatalf("%s native candidate validation failed", q.Kind)
				}
				result, err := n.Observe(ctx, q)
				if err != nil || !result.ConfigurationVerified || !result.PersistenceVerified || !result.GatewayVerified || (q.Kind == "Management" && !result.RuntimeVerified) {
					t.Fatalf("%s native proof incomplete: config=%t runtime=%t persistence=%t gateway=%t error=%t", q.Kind, result.ConfigurationVerified, result.RuntimeVerified, result.PersistenceVerified, result.GatewayVerified, err != nil)
				}
				if q.Kind == "System" {
					if result.RuntimeVerified {
						t.Fatal("read-only adoption lacks a causal daemon activation receipt")
					}
					t.Log("System configuration/persistence verified; runtime adoption requires a causal activation receipt")
				} else {
					t.Log(q.Kind + " configuration/native-runtime/persistence verified using read-only actual consumers")
				}
			}
			changed := system
			snmp := *system.SNMP
			snmp.Location = "qualification-negative-fixture"
			changed.SNMP = &snmp
			negative, err := n.Observe(ctx, Request{Kind: "System", Owner: "readonly-qualification", Target: tc.host, Revision: "2", System: &changed})
			if err == nil && (negative.ConfigurationVerified || negative.RuntimeVerified || negative.PersistenceVerified) {
				t.Fatal("unapplied synthetic system change received readiness")
			}
		})
	}
}

const qualificationReadFile = `import os,stat,sys
try:
    fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as f:
        info=os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size>4194304: sys.exit(45)
        sys.stdout.buffer.write(f.read())
except FileNotFoundError:
    sys.exit(44)
except Exception:
    sys.exit(45)
`
const qualificationSNMPExchange = `import socket,sys
packet=sys.stdin.buffer.read(4097)
if len(packet)>4096: sys.exit(1)
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
    s.settimeout(2)
    s.connect(('127.0.0.1',161))
    s.send(packet)
    sys.stdout.buffer.write(s.recv(4096))
`

func qualificationReadOnlyCommand(args []string) bool {
	joined := strings.Join(args, " ")
	if joined == "docker inspect --format {{json .}} snmp" {
		return true
	}
	if len(args) == 5 && slices.Equal(args[:3], []string{"docker", "cp", "-L"}) && args[4] == "-" {
		id, path, ok := strings.Cut(args[3], ":")
		decoded, e := hex.DecodeString(id)
		if !ok || e != nil || len(decoded) != 32 {
			return false
		}
		if path == snmpTemplate {
			return true
		}
		for _, c := range consumerPaths("snmp") {
			if path == c.path {
				return true
			}
		}
		return false
	}
	if slices.Contains([]string{"sonic-cfggen -d --print-data", "chronyc -c -N sources", "ntpq -pn", "chronyd -p -f /dev/stdin", "systemctl is-active chrony.service", "systemctl is-active ntpsec.service", "ip -j address show dev eth0", "ip -4 -j rule show", "ip -6 -j rule show", "ip -4 -j route show table all dev eth0", "ip -6 -j route show table all dev eth0"}, joined) {
		return true
	}
	if len(args) == 4 && args[0] == "python3" && args[1] == "-c" && args[2] == nativeDaemonProbe && slices.Contains([]string{"snmp", "ntpsec", "chrony"}, args[3]) {
		return true
	}
	if len(args) == 5 && slices.Equal(args[:4], []string{"docker", "exec", "snmp", "cat"}) && slices.Contains([]string{snmpTemplate, "/etc/snmp/snmpd.conf", "/etc/supervisor/conf.d/supervisord.conf"}, args[4]) {
		return true
	}
	if len(args) == 5 && slices.Equal(args[:4], []string{"docker", "exec", "snmp", "sha256sum"}) {
		for _, c := range consumerPaths("snmp") {
			if args[4] == c.path {
				return true
			}
		}
	}
	command := args
	if len(args) > 4 && slices.Equal(args[:4], []string{"docker", "exec", "-i", "snmp"}) {
		command = args[4:]
	}
	if len(command) == 5 && slices.Equal(command[:4], []string{"sonic-cfggen", "-j", "/dev/stdin", "-t"}) && slices.Contains([]string{interfacesTemplate, chronyTemplate, "/usr/share/sonic/templates/ntp.conf.j2", snmpTemplate, "/usr/share/sonic/templates/supervisord.conf.j2"}, command[4]) {
		return true
	}
	// This exact gateway is the sole existing on-link gateway on both authorized hosts.
	return joined == "ping -4 -n -c 1 -W 2 -I eth0 10.0.0.1"
}
