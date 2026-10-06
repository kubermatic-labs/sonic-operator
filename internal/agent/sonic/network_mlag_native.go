// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"
)

// Private command seam replaces only native read-only probes in tests. CONFIG,
// STATE reads, planning, CAS and journal recovery remain real code.
type mlagRunnerKey struct{}
type mlagRunner func(*exec.Cmd) ([]byte, error)

type mlagOutput struct{ bytes.Buffer }

func (b *mlagOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 4<<20 {
		return 0, fmt.Errorf("MLAG native output exceeds 4 MiB")
	}
	return b.Buffer.Write(p)
}

func mlagCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = time.Second
	if run, ok := ctx.Value(mlagRunnerKey{}).(mlagRunner); ok {
		return run(cmd)
	}
	var output mlagOutput
	cmd.Stdout = &output
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return output.Bytes(), err
}

// Pinned to the inspected 202511 build's native consumer and schema. An
// installed binary alone is insufficient: iccpd.sh starts BOTH processes in
// the iccpd container. Never start them or install an image from this planner.
const mlagSupportScript = `
import hashlib, json, sys
from pathlib import Path
def digest(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def running(name):
    binary = Path('/usr/bin/'+name).read_bytes()
    for p in Path('/proc').glob('[0-9]*/exe'):
        try:
            if p.resolve().name == name and p.read_bytes() == binary:
                status = (p.parent/'status').read_text()
                if 'State:\tZ' not in status and 'State:\tT' not in status: return True
        except FileNotFoundError: pass
    return False
try:
    # The whitelist comes from trusted agent deployment configuration, never
    # from a manifest supplied by the container being measured.
    expected = json.loads(sys.argv[1])
    paths = ('/usr/bin/iccpd', '/usr/bin/mclagdctl', '/usr/bin/mclagsyncd', '/usr/local/yang-models/sonic-mclag.yang')
    supported = set(expected) == set(paths) and all(digest(p) == expected[p] for p in paths)
    print(json.dumps({'supported': supported, 'iccpd': running('iccpd'), 'mclagsyncd': running('mclagsyncd')}))
except FileNotFoundError:
    print(json.dumps({'supported': False, 'iccpd': False, 'mclagsyncd': False}))
`

func mlagNativeSupport(ctx context.Context) error {
	hashes, err := mlagTrustedHashes()
	if err != nil {
		return fmt.Errorf("MLAG trusted consumer manifest: %w", err)
	}
	expected, err := json.Marshal(hashes)
	if err != nil {
		return err
	}
	data, err := mlagCommand(ctx, "docker", "exec", "iccpd", "timeout", "4", "python3", "-c", mlagSupportScript, string(expected))
	if err != nil {
		return fmt.Errorf("MLAG running iccpd container/consumer unavailable: %w", err)
	}
	var proof struct {
		Supported bool `json:"supported"`
		ICCPD     bool `json:"iccpd"`
		Syncd     bool `json:"mclagsyncd"`
	}
	var fields map[string]json.RawMessage
	if err := mlagJSON(data, &fields, false); err != nil {
		return fmt.Errorf("invalid MLAG consumer proof: %w", err)
	}
	for key := range fields {
		if key != "supported" && key != "iccpd" && key != "mclagsyncd" {
			return fmt.Errorf("unknown MLAG consumer proof field %q", key)
		}
	}
	if err := mlagJSON(data, &proof, false); err != nil {
		return fmt.Errorf("invalid MLAG consumer proof: %w", err)
	}
	if !proof.Supported || !proof.ICCPD || !proof.Syncd {
		return fmt.Errorf("MLAG requires supported schema/consumer and running iccpd plus mclagsyncd; inert configuration forbidden")
	}
	return nil
}

func mlagReachability(ctx context.Context, db vlanChangeDB, s mlagSpec) error {
	sources := mlagSources(db, s.LocalAddress)
	if len(sources) != 1 {
		return fmt.Errorf("MLAG source unavailable")
	}
	data, err := mlagCommand(ctx, "ip", "-j", "-4", "address", "show", "dev", sources[0])
	if err != nil {
		return fmt.Errorf("MLAG kernel source probe: %w", err)
	}
	// iproute2 adds unrelated fields between versions. Decode an open object but
	// strictly type every field used as evidence and reject duplicate/null JSON.
	var interfaces []map[string]json.RawMessage
	if err := mlagJSON(data, &interfaces, false); err != nil {
		return err
	}
	assigned := false
	for _, iface := range interfaces {
		var name string
		if json.Unmarshal(iface["ifname"], &name) != nil || name != sources[0] {
			continue
		}
		var addresses []map[string]json.RawMessage
		if err := json.Unmarshal(iface["addr_info"], &addresses); err != nil {
			return err
		}
		for _, address := range addresses {
			var local, family string
			if json.Unmarshal(address["local"], &local) == nil && json.Unmarshal(address["family"], &family) == nil && family == "inet" && local == s.LocalAddress {
				assigned = true
			}
		}
	}
	if !assigned {
		return fmt.Errorf("MLAG localAddress is not assigned in kernel")
	}
	data, err = mlagCommand(ctx, "ip", "-j", "-4", "route", "get", s.PeerAddress, "from", s.LocalAddress)
	if err != nil {
		return fmt.Errorf("MLAG peer route unavailable: %w", err)
	}
	var routes []map[string]json.RawMessage
	if err := mlagJSON(data, &routes, false); err != nil {
		return err
	}
	if len(routes) != 1 {
		return fmt.Errorf("MLAG peer route must resolve unambiguously")
	}
	route := routes[0]
	for _, key := range []string{"dst", "from", "dev", "type", "gateway", "prefsrc"} {
		if raw, exists := route[key]; exists {
			var value string
			if err := json.Unmarshal(raw, &value); err != nil {
				return fmt.Errorf("MLAG peer route %s must be a string", key)
			}
		}
	}
	text := func(key string) string { var s string; _ = json.Unmarshal(route[key], &s); return s }
	if text("dst") != s.PeerAddress || text("from") != s.LocalAddress {
		return fmt.Errorf("MLAG peer route destination/source mismatch")
	}
	if typ := text("type"); typ != "" && typ != "unicast" {
		return fmt.Errorf("MLAG peer route is not unicast")
	}
	if table, exists := route["table"]; exists && string(table) != `"main"` && string(table) != `254` {
		return fmt.Errorf("MLAG peer route must use main data-plane table")
	}
	dev := text("dev")
	if err := lagL3InterfaceExists(db, dev); err != nil {
		return fmt.Errorf("MLAG peer route requires existing data-plane interface: %w", err)
	}
	if vrf := db[lagL3InterfaceTable(dev)+"|"+dev]["vrf_name"]; vrf != "" && vrf != "default" {
		return fmt.Errorf("MLAG peer route uses non-default VRF")
	}
	var flags []string
	if err := json.Unmarshal(route["flags"], &flags); err != nil {
		return fmt.Errorf("MLAG peer route flags unavailable")
	}
	for _, flag := range flags {
		if flag == "linkdown" || flag == "dead" {
			return fmt.Errorf("MLAG peer route link unavailable")
		}
	}
	return nil
}

func mlagRuntime(ctx context.Context, m *SonicAgent, s mlagSpec) (bool, json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	observed := struct {
		DomainID          uint32              `json:"domainID"`
		ConsumerReady     bool                `json:"consumerReady"`
		PreflightEligible bool                `json:"preflightEligible"`
		State             vlanChangeDB        `json:"state"`
		Native            *mlagNativeEvidence `json:"native,omitempty"`
		Reason            string              `json:"reason"`
	}{DomainID: s.DomainID, State: vlanChangeDB{}, Reason: "exact domain configuration and MLACP sync completion runtime proof unavailable; pair health unverified"}
	consumerReady, preflightErr := mlagPreflight(ctx, m, s)
	observed.ConsumerReady = consumerReady
	observed.PreflightEligible = preflightErr == nil
	if preflightErr != nil {
		if ctx.Err() != nil {
			return false, nil, ctx.Err()
		}
		observed.Reason = preflightErr.Error()
	}
	state, err := m.Connect("STATE_DB")
	if err != nil {
		return false, nil, err
	}
	read := func(key string, fields ...string) error {
		row, err := state.HGetAll(ctx, key).Result()
		if err != nil {
			return err
		}
		for _, field := range fields {
			if value, ok := row[field]; ok {
				if observed.State[key] == nil {
					observed.State[key] = map[string]string{}
				}
				observed.State[key][field] = value
			}
		}
		return nil
	}
	if err := read("MCLAG_TABLE|"+mlagID(s.DomainID), "oper_status", "role", "system_mac", "peer_mac"); err != nil {
		return false, nil, err
	}
	for _, member := range s.Members {
		if err := read("MCLAG_REMOTE_INTF_TABLE|"+mlagID(s.DomainID)+"|"+member, "oper_status"); err != nil {
			return false, nil, err
		}
		if err := read("MCLAG_LOCAL_INTF_TABLE|"+member, "port_isolate_peer_link"); err != nil {
			return false, nil, err
		}
	}
	ready := false
	if preflightErr == nil {
		observed.Native, err = mlagNativeStatus(ctx, s)
		if err == nil {
			err = mlagVerifyNative(s, observed.Native, observed.State)
		}
		if err != nil {
			observed.Reason = "pair health unverified: " + err.Error()
		} else {
			ready = true
			observed.Reason = "native domain, session, exchange and member state verified"
		}
	}
	if ctx.Err() != nil {
		return false, nil, ctx.Err()
	}
	data, marshalErr := json.Marshal(observed)
	return ready, data, marshalErr
}
