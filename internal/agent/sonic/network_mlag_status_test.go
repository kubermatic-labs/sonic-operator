// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Source-shaped fixtures, not captured switch output. See mclagdctl.c's
// mclagdctl_parse_dump_{state,local_portlist,peer_portlist} at 4784cca11.
const mlagStateFixture = `The MCLAG's keepalive is: OK
MCLAG info sync is: completed
Domain id: 1
Local Ip: 192.0.2.1
Peer Ip: 192.0.2.2
Peer Link Interface: PortChannel100
Keepalive time: 1
sesssion Timeout : 30
Peer Link Mac: 02:00:00:00:00:01` + " " + `
Role: Active
MCLAG Interface: PortChannel10
Loglevel: NOTICE
`

const mlagLocalFixture = `------------------------------------------------------------
Ifindex: 100
Type: PortChannel
PortName: PortChannel100
MAC: 02:00:00:00:00:01` + " " + `
IPv4Address: 192.0.2.1
Prefixlen: 30
State: Up
IsL3Interface: Yes
MemberPorts: Ethernet0
PortchannelIsUp: 1
IsIsolateWithPeerlink: No
IsTrafficDisable: No
VlanList:` + " " + `
------------------------------------------------------------

------------------------------------------------------------
Ifindex: 10
Type: PortChannel
PortName: PortChannel10
MAC: 02:00:00:00:00:01` + " " + `
IPv4Address: 0.0.0.0
Prefixlen: 0
State: Up
IsL3Interface: No
MemberPorts: Ethernet4
PortchannelIsUp: 1
IsIsolateWithPeerlink: Yes
IsTrafficDisable: No
VlanList: 100 - 102` + " " + `
------------------------------------------------------------

`

const mlagPeerFixture = `------------------------------------------------------------
Ifindex: 10
Type: PortChannel
PortName: PortChannel10
MAC: 02:00:00:00:00:02` + " " + `
State: Up
------------------------------------------------------------

`

const mlagLinksFixture = `[{"ifname":"PortChannel100","flags":["BROADCAST","MULTICAST","MASTER","UP","LOWER_UP"],"operstate":"UP","mtu":9100},{"ifname":"PortChannel10","flags":["UP","LOWER_UP"],"operstate":"UP"}]`

func mlagStatusRunner(cmd *exec.Cmd) ([]byte, error) {
	if reflect.DeepEqual(cmd.Args, []string{"ip", "-j", "link", "show"}) {
		return []byte(mlagLinksFixture), nil
	}
	for _, name := range []string{"PortChannel100", "PortChannel10"} {
		if reflect.DeepEqual(cmd.Args, []string{"ip", "-j", "link", "show", "dev", name}) {
			return []byte(`[{"ifname":"` + name + `","flags":["UP","LOWER_UP"],"operstate":"UP"}]`), nil
		}
	}
	prefix := []string{"docker", "exec", "iccpd", "timeout", "4", "/usr/bin/mclagdctl", "-i", "1", "dump"}
	for _, fixture := range []struct {
		args []string
		data string
	}{
		{[]string{"state"}, mlagStateFixture},
		{[]string{"portlist", "local"}, mlagLocalFixture},
		{[]string{"portlist", "peer"}, mlagPeerFixture},
	} {
		if reflect.DeepEqual(cmd.Args, append(append([]string{}, prefix...), fixture.args...)) {
			return []byte(fixture.data), nil
		}
	}
	return mlagTestRunner(cmd)
}

func TestNetworkMLAGStatusUnrelatedPIMInterface(t *testing.T) {
	t.Parallel()
	// leaf-03 emits link:null for pimreg. Unrelated interfaces must not
	// invalidate MLAG health; query each required LAG instead of every link.
	ctx := context.WithValue(t.Context(), mlagRunnerKey{}, mlagRunner(func(cmd *exec.Cmd) ([]byte, error) {
		if reflect.DeepEqual(cmd.Args, []string{"ip", "-j", "link", "show"}) {
			return []byte(strings.TrimSuffix(mlagLinksFixture, "]") + `,{"ifname":"pimreg","link":null,"flags":["UP","LOWER_UP"],"operstate":"UNKNOWN"}]`), nil
		}
		return mlagStatusRunner(cmd)
	}))
	s, _, state := mlagStatusFixture(t)
	e, err := mlagNativeStatus(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	if err := mlagVerifyNative(s, e, state); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkMLAGStatusRejectsInvalidRequiredLink(t *testing.T) {
	t.Parallel()
	for _, text := range []string{
		`[]`,
		`[{"ifname":"other","flags":["UP","LOWER_UP"],"operstate":"UP"}]`,
		`[{"ifname":"PortChannel100","flags":null,"operstate":"UP"}]`,
		`[{"ifname":"PortChannel100","flags":["UP",null],"operstate":"UP"}]`,
		`[{"ifname":"PortChannel100","flags":["UP","LOWER_UP"],"operstate":null}]`,
		`[{"ifname":"PortChannel100","flags":["UP"],"operstate":"UP","operstate":"DOWN"}]`,
		mlagLinksFixture,
	} {
		t.Run(text, func(t *testing.T) {
			ctx := context.WithValue(t.Context(), mlagRunnerKey{}, mlagRunner(func(cmd *exec.Cmd) ([]byte, error) {
				if reflect.DeepEqual(cmd.Args, []string{"ip", "-j", "link", "show", "dev", "PortChannel100"}) {
					return []byte(text), nil
				}
				return mlagStatusRunner(cmd)
			}))
			s, _, _ := mlagStatusFixture(t)
			if _, err := mlagNativeStatus(ctx, s); err == nil {
				t.Fatal("invalid required-link evidence accepted")
			}
		})
	}
}

func mlagStatusFixture(t *testing.T) (mlagSpec, *mlagNativeEvidence, vlanChangeDB) {
	t.Helper()
	var s mlagSpec
	if err := mlagJSON([]byte(mlagTestSpec), &s, true); err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(t.Context(), mlagRunnerKey{}, mlagRunner(mlagStatusRunner))
	e, err := mlagNativeStatus(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	state := vlanChangeDB{
		"MCLAG_TABLE|1": {"oper_status": "up", "role": "active"},
		"MCLAG_REMOTE_INTF_TABLE|1|PortChannel10": {"oper_status": "up"},
	}
	return s, e, state
}

func TestNetworkMLAGNativeStatus(t *testing.T) {
	t.Parallel()
	s, e, state := mlagStatusFixture(t)
	if err := mlagVerifyNative(s, e, state); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*mlagNativeEvidence, vlanChangeDB)
	}{
		{"wrong domain", func(e *mlagNativeEvidence, _ vlanChangeDB) { e.Domain["Domain id"] = "2" }},
		{"wrong local IP", func(e *mlagNativeEvidence, _ vlanChangeDB) { e.Domain["Local Ip"] = "192.0.2.3" }},
		{"wrong peer IP", func(e *mlagNativeEvidence, _ vlanChangeDB) { e.Domain["Peer Ip"] = "192.0.2.3" }},
		{"wrong peerlink", func(e *mlagNativeEvidence, _ vlanChangeDB) { e.Domain["Peer Link Interface"] = "PortChannel200" }},
		{"wrong keepalive", func(e *mlagNativeEvidence, _ vlanChangeDB) { e.Domain["Keepalive time"] = "2" }},
		{"wrong timeout", func(e *mlagNativeEvidence, _ vlanChangeDB) { e.Domain["sesssion Timeout"] = "60" }},
		{"no session", func(e *mlagNativeEvidence, _ vlanChangeDB) { e.Domain["The MCLAG's keepalive is"] = "ERROR" }},
		{"not exchanged", func(e *mlagNativeEvidence, _ vlanChangeDB) { e.Domain["MCLAG info sync is"] = "incomplete" }},
		{"unknown sync", func(e *mlagNativeEvidence, _ vlanChangeDB) { e.Domain["MCLAG info sync is"] = "unknown" }},
		{"unknown role", func(e *mlagNativeEvidence, _ vlanChangeDB) { e.Domain["Role"] = "Unknown" }},
		{"CLI role differs", func(e *mlagNativeEvidence, _ vlanChangeDB) { e.Domain["Role"] = "Standby" }},
		{"missing daemon role", func(_ *mlagNativeEvidence, db vlanChangeDB) { delete(db["MCLAG_TABLE|1"], "role") }},
		{"daemon session down", func(_ *mlagNativeEvidence, db vlanChangeDB) { db["MCLAG_TABLE|1"]["oper_status"] = "down" }},
		{"member missing", func(e *mlagNativeEvidence, _ vlanChangeDB) { e.Domain["MCLAG Interface"] = "" }},
		{"extra member", func(e *mlagNativeEvidence, _ vlanChangeDB) { e.Domain["MCLAG Interface"] += ",PortChannel20" }},
		{"duplicate member", func(e *mlagNativeEvidence, _ vlanChangeDB) { e.Domain["MCLAG Interface"] += ",PortChannel10" }},
		{"local missing", func(e *mlagNativeEvidence, _ vlanChangeDB) { delete(e.Local, "PortChannel10") }},
		{"peer missing", func(e *mlagNativeEvidence, _ vlanChangeDB) { delete(e.Peer, "PortChannel10") }},
		{"peer down", func(e *mlagNativeEvidence, _ vlanChangeDB) { e.Peer["PortChannel10"]["State"] = "Down" }},
		{"peer admin down", func(e *mlagNativeEvidence, _ vlanChangeDB) { e.Peer["PortChannel10"]["State"] = "Admin-down" }},
		{"peerlink down", func(e *mlagNativeEvidence, _ vlanChangeDB) { e.Local["PortChannel100"]["State"] = "Down" }},
		{"member admin down", func(e *mlagNativeEvidence, _ vlanChangeDB) { e.Local["PortChannel10"]["State"] = "Admin-down" }},
		{"member inactive", func(e *mlagNativeEvidence, _ vlanChangeDB) { e.Local["PortChannel10"]["PortchannelIsUp"] = "0" }},
		{"traffic disabled", func(e *mlagNativeEvidence, _ vlanChangeDB) { e.Local["PortChannel10"]["IsTrafficDisable"] = "Yes" }},
		{"remote state missing", func(_ *mlagNativeEvidence, db vlanChangeDB) { delete(db, "MCLAG_REMOTE_INTF_TABLE|1|PortChannel10") }},
		{"kernel missing", func(e *mlagNativeEvidence, _ vlanChangeDB) { delete(e.Links, "PortChannel10") }},
		{"kernel admin down", func(e *mlagNativeEvidence, _ vlanChangeDB) {
			v := e.Links["PortChannel10"]
			v.Flags = []string{"LOWER_UP"}
			e.Links[v.Name] = v
		}},
		{"kernel no carrier", func(e *mlagNativeEvidence, _ vlanChangeDB) {
			v := e.Links["PortChannel10"]
			v.Flags = []string{"UP"}
			e.Links[v.Name] = v
		}},
		{"kernel unknown", func(e *mlagNativeEvidence, _ vlanChangeDB) {
			v := e.Links["PortChannel10"]
			v.OperState = "UNKNOWN"
			e.Links[v.Name] = v
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, e, state := mlagStatusFixture(t)
			tc.edit(e, state)
			if err := mlagVerifyNative(s, e, state); err == nil {
				t.Fatal("unhealthy evidence accepted")
			}
		})
	}
}

func TestNetworkMLAGTextRejectsUnknownEvidence(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, text string
		port, peer bool
	}{
		{"empty state", "", false, false},
		{"missing state field", strings.ReplaceAll(mlagStateFixture, "Domain id: 1\n", ""), false, false},
		{"duplicate domain", mlagStateFixture + "Domain id: 1\n", false, false},
		{"multiple domains", mlagStateFixture + mlagStateFixture, false, false},
		{"invented sync", mlagStateFixture + "info_sync_done: true\n", false, false},
		{"changed label", strings.ReplaceAll(mlagStateFixture, "sesssion Timeout", "Session Timeout"), false, false},
		{"truncated port", strings.TrimSuffix(mlagPeerFixture, strings.Repeat("-", 60)+"\n\n"), true, true},
		{"duplicate peer", mlagPeerFixture + mlagPeerFixture, true, true},
		{"missing state", strings.ReplaceAll(mlagPeerFixture, "State: Up\n", ""), true, true},
		{"error output", "No exist sys in iccpd!", true, true},
		{"unknown local field", strings.ReplaceAll(mlagLocalFixture, "State: Up", "Healthy: yes"), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if tc.port {
				_, err = mlagPortRecords(tc.text, tc.peer)
			} else {
				_, err = mlagTextFields(tc.text, mlagStateLabels)
			}
			if err == nil {
				t.Fatal("invalid text accepted")
			}
		})
	}
}

func TestNetworkMLAGStatusTransportAndTransition(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, fail string
		transition bool
	}{
		{"state error", "state", false}, {"local error", "local", false}, {"peer error", "peer", false}, {"kernel error", "PortChannel100", false}, {"session transitions", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads := 0
			ctx := context.WithValue(t.Context(), mlagRunnerKey{}, mlagRunner(func(cmd *exec.Cmd) ([]byte, error) {
				last := cmd.Args[len(cmd.Args)-1]
				if last == tc.fail {
					return nil, errors.New("unavailable")
				}
				if last == "state" {
					reads++
					if tc.transition && reads == 2 {
						return []byte(strings.ReplaceAll(mlagStateFixture, "completed", "incomplete")), nil
					}
				}
				return mlagStatusRunner(cmd)
			}))
			var s mlagSpec
			_ = json.Unmarshal([]byte(mlagTestSpec), &s)
			if _, err := mlagNativeStatus(ctx, s); err == nil {
				t.Fatal("failed/transitioning probe accepted")
			}
		})
	}
}

func TestNetworkMLAGTrustedManifest(t *testing.T) {
	t.Parallel()
	// Deliberately synthetic digests test validation, never production trust.
	hashes := map[string]string{}
	for _, path := range mlagFingerprintPaths {
		hashes[path] = strings.Repeat("a", 64)
	}
	data, err := json.Marshal(map[string]any{"version": 1, "source": "sonic-net/sonic-buildimage@4784cca11:src/iccpd", "sha256": hashes})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = mlagParseManifest(data); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, old, new string }{
		{"wrong source", "4784cca11", "main"}, {"short hash", strings.Repeat("a", 64), "a"}, {"invalid hex", strings.Repeat("a", 64), strings.Repeat("x", 64)},
		{"wrong path", "/usr/bin/iccpd", "/tmp/iccpd"}, {"unknown field", `"version":1`, `"version":1,"supported":true`},
		{"duplicate version", `"version":1`, `"version":1,"version":1`}, {"null hash", `"sha256":{`, `"sha256":null,"other":{`},
		{"case alias", `"version":1`, `"Version":1`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := mlagParseManifest([]byte(strings.ReplaceAll(string(data), tc.old, tc.new))); err == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}
}

func TestNetworkMLAGManifestDeploymentPath(t *testing.T) {
	for _, path := range []string{"relative.json", "/etc/../etc/manifest.json", "/definitely-absent-mlag-manifest.json"} {
		t.Run(path, func(t *testing.T) {
			t.Setenv("SONIC_MLAG_CONSUMER_MANIFEST", path)
			if _, err := mlagTrustedHashes(); err == nil {
				t.Fatal("unsafe or absent manifest accepted")
			}
		})
	}
	t.Setenv("SONIC_MLAG_CONSUMER_MANIFEST", "")
	hashes, err := mlagTrustedHashes()
	if err != nil || len(hashes) != 0 {
		t.Fatalf("unconfigured trust=%v %v", hashes, err)
	}
}

func TestNetworkMLAGCommandCancellation(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	_, err := mlagCommand(ctx, "python3", "-c", "import time; time.sleep(30)")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline not propagated: %v", err)
	}
}
