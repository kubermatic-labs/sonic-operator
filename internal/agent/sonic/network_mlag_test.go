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

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

const mlagTestSpec = `{"switchRef":{"name":"local"},"peerSwitchRef":{"name":"peer"},"domainID":1,"localAddress":"192.0.2.1","peerAddress":"192.0.2.2","peerLink":"PortChannel100","members":["PortChannel10"]}`

func mlagTestDB() vlanChangeDB {
	return vlanChangeDB{
		"PORT|Ethernet0": {"lanes": "0"}, "PORT|Ethernet4": {"lanes": "4"},
		"PORTCHANNEL|PortChannel100": {"admin_status": "up"}, "PORTCHANNEL|PortChannel10": {"admin_status": "up"},
		"PORTCHANNEL_MEMBER|PortChannel100|Ethernet0": {"NULL": "NULL"}, "PORTCHANNEL_MEMBER|PortChannel10|Ethernet4": {"NULL": "NULL"},
		"PORTCHANNEL_INTERFACE|PortChannel100": {"NULL": "NULL"}, "PORTCHANNEL_INTERFACE|PortChannel100|192.0.2.1/30": {"NULL": "NULL"},
	}
}

func mlagTestRequest() *agent.NetworkRequest {
	return &agent.NetworkRequest{Kind: "MLAG", OwnerID: "mlag-uid", Spec: json.RawMessage(mlagTestSpec)}
}

func mlagTestRunner(cmd *exec.Cmd) ([]byte, error) {
	switch cmd.Args[0] {
	case "docker":
		if !reflect.DeepEqual(cmd.Args, []string{"docker", "exec", "iccpd", "timeout", "4", "python3", "-c", mlagSupportScript, "{}"}) {
			return nil, errors.New("unexpected docker command")
		}
		return []byte(`{"supported":true,"iccpd":true,"mclagsyncd":true}`), nil
	case "ip":
		if reflect.DeepEqual(cmd.Args, []string{"ip", "-j", "-4", "address", "show", "dev", "PortChannel100"}) {
			return []byte(`[{"ifname":"PortChannel100","addr_info":[{"family":"inet","local":"192.0.2.1","prefixlen":30}]}]`), nil
		}
		if reflect.DeepEqual(cmd.Args, []string{"ip", "-j", "-4", "route", "get", "192.0.2.2", "from", "192.0.2.1"}) {
			return []byte(`[{"dst":"192.0.2.2","from":"192.0.2.1","dev":"PortChannel100","flags":[],"uid":0,"cache":[]}]`), nil
		}
	}
	return nil, errors.New("unexpected native command")
}

func TestNetworkMLAGPlan(t *testing.T) {
	t.Parallel()
	r := mlagTestRequest()
	db := mlagTestDB()
	p, err := planNetworkMLAG(db, r)
	if err != nil {
		t.Fatal(err)
	}
	want := vlanChangeDB{
		"MCLAG_DOMAIN|1":                  {"source_ip": "192.0.2.1", "peer_ip": "192.0.2.2", "peer_link": "PortChannel100", "keepalive_interval": "1", "session_timeout": "30"},
		"MCLAG_INTERFACE|1|PortChannel10": {"if_type": "PortChannel"},
	}
	if p.Identity != "MLAG|1" || !reflect.DeepEqual(p.Desired, want) || p.Preflight == nil || p.Runtime == nil || p.Activate != nil {
		t.Fatalf("plan=%+v", p)
	}
	if !reflect.DeepEqual(db, mlagTestDB()) {
		t.Fatal("planner mutated snapshot")
	}
	if err := validateNetworkFields("MLAG", p.Desired); err != nil {
		t.Fatal(err)
	}
	if id, err := networkIdentity(r); err != nil || id != p.Identity {
		t.Fatalf("core identity=%s err=%v", id, err)
	}
	// Domain-only stage and Observe without dependencies are representable.
	r.Spec = json.RawMessage(strings.Replace(mlagTestSpec, `["PortChannel10"]`, `[]`, 1))
	p, err = planNetworkMLAG(nil, r)
	if err != nil || len(p.Desired) != 1 {
		t.Fatalf("domain-only plan=%+v err=%v", p, err)
	}
}

func TestNetworkMLAGRejectSpec(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, old, replacement string }{
		{"zero domain", `"domainID":1`, `"domainID":0`},
		{"domain overflow", `"domainID":1`, `"domainID":4096`},
		{"fraction domain", `"domainID":1`, `"domainID":1.0`},
		{"string domain", `"domainID":1`, `"domainID":"1"`},
		{"null", `"domainID":1`, `"domainID":null`},
		{"duplicate", `"domainID":1`, `"domainID":1,"domainID":2`},
		{"case alias", `"domainID":1`, `"DomainID":1`},
		{"nested duplicate", `"name":"peer"`, `"name":"peer","name":"other"`},
		{"nested unknown", `"name":"peer"`, `"Name":"peer"`},
		{"unknown field", `"domainID":1`, `"domainID":1,"enable":true`},
		{"null reference", `{"name":"peer"}`, `null`},
		{"self peer", `"name":"peer"`, `"name":"local"`},
		{"empty peer", `"name":"peer"`, `"name":""`},
		{"IPv6", `192.0.2.2`, `2001:db8::2`},
		{"same address", `192.0.2.2`, `192.0.2.1`},
		{"multicast", `192.0.2.2`, `224.0.0.1`},
		{"unspecified", `192.0.2.1`, `0.0.0.0`},
		{"loopback", `192.0.2.1`, `127.0.0.1`},
		{"management peerlink", `PortChannel100`, `eth0`},
		{"noncanonical", `PortChannel100`, `PortChannel0100`},
		{"peerlink member", `["PortChannel10"]`, `["PortChannel100"]`},
		{"duplicate member", `["PortChannel10"]`, `["PortChannel10","PortChannel10"]`},
		{"management member", `["PortChannel10"]`, `["eth0"]`},
		{"null members", `["PortChannel10"]`, `null`},
		{"zero keepalive", `"domainID":1`, `"domainID":1,"keepaliveInterval":0`},
		{"keepalive max", `"domainID":1`, `"domainID":1,"keepaliveInterval":61`},
		{"timeout max", `"domainID":1`, `"domainID":1,"sessionTimeout":3601`},
		{"timer ratio", `"domainID":1`, `"domainID":1,"keepaliveInterval":11`},
		{"timer null", `"domainID":1`, `"domainID":1,"sessionTimeout":null`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := mlagTestRequest()
			r.Spec = json.RawMessage(strings.Replace(mlagTestSpec, tc.old, tc.replacement, 1))
			if _, err := planNetworkMLAG(nil, r); err == nil {
				t.Fatal("accepted invalid spec")
			}
		})
	}
	for _, data := range []string{mlagTestSpec + ` {}`, `[]`, `null`, `"text"`} {
		if _, err := planNetworkMLAG(nil, &agent.NetworkRequest{Kind: "MLAG", Spec: json.RawMessage(data)}); err == nil {
			t.Fatalf("accepted %s", data)
		}
	}
}

func TestNetworkMLAGDependencies(t *testing.T) {
	t.Parallel()
	var s mlagSpec
	if err := mlagJSON([]byte(mlagTestSpec), &s, true); err != nil {
		t.Fatal(err)
	}
	if err := mlagDependencies(mlagTestDB(), s); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(vlanChangeDB)
	}{
		{"missing peerlink", func(db vlanChangeDB) { delete(db, "PORTCHANNEL|PortChannel100") }},
		{"missing member", func(db vlanChangeDB) { delete(db, "PORTCHANNEL|PortChannel10") }},
		{"empty lag", func(db vlanChangeDB) { delete(db, "PORTCHANNEL_MEMBER|PortChannel10|Ethernet4") }},
		{"mgmt physical", func(db vlanChangeDB) { db["PORTCHANNEL_MEMBER|PortChannel10|eth0"] = map[string]string{"NULL": "NULL"} }},
		{"shared physical", func(db vlanChangeDB) {
			db["PORTCHANNEL_MEMBER|PortChannel10|Ethernet0"] = map[string]string{"NULL": "NULL"}
		}},
		{"missing source", func(db vlanChangeDB) { delete(db, "PORTCHANNEL_INTERFACE|PortChannel100|192.0.2.1/30") }},
		{"source vrf", func(db vlanChangeDB) { db["PORTCHANNEL_INTERFACE|PortChannel100"]["vrf_name"] = "VrfBlue" }},
		{"local peer", func(db vlanChangeDB) {
			db["LOOPBACK_INTERFACE|Loopback0|192.0.2.2/32"] = map[string]string{"NULL": "NULL"}
		}},
		{"multiple source", func(db vlanChangeDB) {
			db["LOOPBACK_INTERFACE|Loopback0|192.0.2.1/32"] = map[string]string{"NULL": "NULL"}
		}},
		{"second domain", func(db vlanChangeDB) { db["MCLAG_DOMAIN|2"] = map[string]string{"source_ip": "198.51.100.1"} }},
		{"foreign domain member", func(db vlanChangeDB) {
			db["MCLAG_INTERFACE|2|PortChannel10"] = map[string]string{"if_type": "PortChannel"}
		}},
		{"native peerlink member", func(db vlanChangeDB) {
			db["MCLAG_INTERFACE|1|PortChannel100"] = map[string]string{"if_type": "PortChannel"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := mlagTestDB()
			tc.edit(db)
			if err := mlagDependencies(db, s); err == nil {
				t.Fatal("accepted missing/conflicting dependency")
			}
		})
	}
}

func TestNetworkMLAGNativeProbes(t *testing.T) {
	t.Parallel()
	var s mlagSpec
	if err := mlagJSON([]byte(mlagTestSpec), &s, true); err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(t.Context(), mlagRunnerKey{}, mlagRunner(mlagTestRunner))
	if err := mlagNativeSupport(ctx); err != nil {
		t.Fatal(err)
	}
	if err := mlagReachability(ctx, mlagTestDB(), s); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, command, output string
		fail                  bool
	}{
		{"absent daemon", "docker", `{"supported":true,"iccpd":false,"mclagsyncd":true}`, false},
		{"absent syncd", "docker", `{"supported":true,"iccpd":true,"mclagsyncd":false}`, false},
		{"unsupported", "docker", `{"supported":false,"iccpd":true,"mclagsyncd":true}`, false},
		{"duplicate proof", "docker", `{"supported":false,"supported":true,"iccpd":true,"mclagsyncd":true}`, false},
		{"null proof", "docker", `{"supported":true,"iccpd":null,"mclagsyncd":true}`, false},
		{"unknown proof", "docker", `{"supported":true,"iccpd":true,"mclagsyncd":true,"healthy":true}`, false},
		{"case alias proof", "docker", `{"Supported":true,"iccpd":true,"mclagsyncd":true}`, false},
		{"trailing proof", "docker", `{"supported":true,"iccpd":true,"mclagsyncd":true}{}`, false},
		{"missing container", "docker", "", true},
		{"no kernel source", "address", `[]`, false},
		{"unreachable", "route", "", true},
		{"empty route", "route", `[]`, false},
		{"mgmt route", "route", `[{"dst":"192.0.2.2","from":"192.0.2.1","dev":"eth0","flags":[]}]`, false},
		{"blackhole", "route", `[{"dst":"192.0.2.2","from":"192.0.2.1","dev":"PortChannel100","type":"blackhole","flags":[]}]`, false},
		{"wrong route type", "route", `[{"dst":"192.0.2.2","from":"192.0.2.1","dev":"PortChannel100","type":false,"flags":[]}]`, false},
		{"wrong source", "route", `[{"dst":"192.0.2.2","from":"192.0.2.3","dev":"PortChannel100","flags":[]}]`, false},
		{"wrong table", "route", `[{"dst":"192.0.2.2","from":"192.0.2.1","dev":"PortChannel100","table":"default","flags":[]}]`, false},
		{"link down", "route", `[{"dst":"192.0.2.2","from":"192.0.2.1","dev":"PortChannel100","flags":["linkdown"]}]`, false},
		{"duplicate route", "route", `[{"dst":"192.0.2.2","from":"192.0.2.1","dev":"eth0","dev":"PortChannel100","flags":[]}]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.WithValue(t.Context(), mlagRunnerKey{}, mlagRunner(func(cmd *exec.Cmd) ([]byte, error) {
				if cmd.Args[0] == tc.command || (cmd.Args[0] == "ip" && cmd.Args[3] == tc.command) {
					if tc.fail {
						return nil, errors.New("native unavailable")
					}
					return []byte(tc.output), nil
				}
				return mlagTestRunner(cmd)
			}))
			var err error
			if tc.command == "docker" {
				err = mlagNativeSupport(ctx)
			} else {
				err = mlagReachability(ctx, mlagTestDB(), s)
			}
			if err == nil {
				t.Fatal("accepted invalid native proof")
			}
		})
	}
}
