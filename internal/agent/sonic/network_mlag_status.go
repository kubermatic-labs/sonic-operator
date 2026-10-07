// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// Text labels and semantics audited against sonic-buildimage@4784cca11:
// src/iccpd/src/mclagdctl/mclagdctl.c and src/iccpd/src/iccp_cmd_show.c.
// There is no JSON mode or "dump mclag" command in this revision.
type mlagNativeEvidence struct {
	Domain map[string]string            `json:"domain"`
	Local  map[string]map[string]string `json:"local"`
	Peer   map[string]map[string]string `json:"peer"`
	Links  map[string]mlagKernelLink    `json:"links"`
}

type mlagKernelLink struct {
	Name      string   `json:"ifname"`
	Flags     []string `json:"flags"`
	OperState string   `json:"operstate"`
}

const mlagStateLabels = "The MCLAG's keepalive is|MCLAG info sync is|Domain id|Local Ip|Peer Ip|Peer Link Interface|Keepalive time|sesssion Timeout|Peer Link Mac|Role|MCLAG Interface|Loglevel"
const mlagLocalLabels = "Ifindex|Type|PortName|MAC|IPv4Address|Prefixlen|State|IsL3Interface|MemberPorts|PortchannelIsUp|IsIsolateWithPeerlink|IsTrafficDisable|VlanList"
const mlagEthernetLabels = "Ifindex|Type|PortName|State|VlanList"
const mlagPeerLabels = "Ifindex|Type|PortName|MAC|State"

func mlagTextFields(text, labels string) (map[string]string, error) {
	if len(text) > 4<<20 || strings.ContainsAny(text, "\x00\r") {
		return nil, fmt.Errorf("invalid MLAG text size/encoding")
	}
	allowed := map[string]bool{}
	for _, key := range strings.Split(labels, "|") {
		allowed[key] = true
	}
	fields := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if _, duplicate := fields[key]; !ok || !allowed[key] || duplicate {
			return nil, fmt.Errorf("unknown, duplicate or malformed MLAG field %q", key)
		}
		fields[key] = value
	}
	if len(fields) != len(allowed) {
		return nil, fmt.Errorf("incomplete MLAG text record")
	}
	return fields, nil
}

func mlagPortRecords(text string, peer bool) (map[string]map[string]string, error) {
	if len(text) > 4<<20 {
		return nil, fmt.Errorf("MLAG port output exceeds limit")
	}
	ports := map[string]map[string]string{}
	separator := strings.Repeat("-", 60)
	var record []string
	inside := false
	for _, line := range strings.Split(text, "\n") {
		if line == separator {
			if !inside {
				inside = true
				continue
			}
			labels := mlagLocalLabels
			if peer {
				labels = mlagPeerLabels
			} else if strings.Contains("\n"+strings.Join(record, "\n")+"\n", "\nType: Ethernet\n") {
				labels = mlagEthernetLabels
			}
			fields, err := mlagTextFields(strings.Join(record, "\n"), labels)
			if err != nil {
				return nil, err
			}
			name := fields["PortName"]
			if name == "" || ports[name] != nil || (fields["Type"] != "PortChannel" && fields["Type"] != "Ethernet") {
				return nil, fmt.Errorf("invalid/duplicate MLAG port %q", name)
			}
			ports[name] = fields
			inside, record = false, nil
		} else if inside {
			record = append(record, line)
		} else if strings.TrimSpace(line) != "" {
			return nil, fmt.Errorf("unexpected MLAG port output")
		}
	}
	if inside {
		return nil, fmt.Errorf("truncated MLAG port record")
	}
	return ports, nil
}

func mlagNativeStatus(ctx context.Context, s mlagSpec) (*mlagNativeEvidence, error) {
	e := &mlagNativeEvidence{Links: map[string]mlagKernelLink{}}
	dump := func(args ...string) ([]byte, error) {
		argv := append([]string{"exec", "iccpd", "timeout", "4", "/usr/bin/mclagdctl", "-i", mlagID(s.DomainID), "dump"}, args...)
		return mlagCommand(ctx, "docker", argv...)
	}
	data, err := dump("state")
	if err != nil {
		return e, fmt.Errorf("native domain unavailable: %w", err)
	}
	if e.Domain, err = mlagTextFields(string(data), mlagStateLabels); err != nil {
		return e, err
	}
	for _, side := range []string{"local", "peer"} {
		data, err = dump("portlist", side)
		if err != nil {
			return e, fmt.Errorf("native %s portlist: %w", side, err)
		}
		ports, err := mlagPortRecords(string(data), side == "peer")
		if err != nil {
			return e, err
		}
		if side == "local" {
			e.Local = ports
		} else {
			e.Peer = ports
		}
	}
	// Probe only required LAGs: unrelated interfaces such as pimreg can emit
	// null fields. Keep strict evidence validation for every queried LAG.
	for _, name := range append([]string{s.PeerLink}, s.Members...) {
		data, err = mlagCommand(ctx, "ip", "-j", "link", "show", "dev", name)
		if err != nil {
			return e, fmt.Errorf("MLAG kernel link probe: %w", err)
		}
		var links []map[string]json.RawMessage
		if err := mlagJSON(data, &links, false); err != nil {
			return e, err
		}
		if len(links) != 1 {
			return e, fmt.Errorf("MLAG kernel probe requires exactly one link for %s", name)
		}
		row := links[0]
		var link mlagKernelLink
		if json.Unmarshal(row["ifname"], &link.Name) != nil || json.Unmarshal(row["flags"], &link.Flags) != nil || json.Unmarshal(row["operstate"], &link.OperState) != nil || link.Name != name {
			return e, fmt.Errorf("incomplete kernel link evidence")
		}
		if _, duplicate := e.Links[link.Name]; duplicate {
			return e, fmt.Errorf("duplicate kernel link %s", link.Name)
		}
		e.Links[link.Name] = link
	}
	// Bracket the member probes with domain reads: a session/config transition
	// observed during sampling invalidates the result. This is not an atomic
	// cross-switch snapshot.
	data, err = dump("state")
	if err != nil {
		return e, err
	}
	after, err := mlagTextFields(string(data), mlagStateLabels)
	if err != nil {
		return e, err
	}
	if !reflect.DeepEqual(e.Domain, after) {
		return e, fmt.Errorf("MLAG domain changed during observation")
	}
	return e, nil
}

//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func mlagVerifyNative(s mlagSpec, e *mlagNativeEvidence, state vlanChangeDB) error {
	if e == nil {
		return fmt.Errorf("missing native evidence")
	}
	keepalive, timeout := uint32(1), uint32(30)
	if s.KeepaliveInterval != nil {
		keepalive = *s.KeepaliveInterval
	}
	if s.SessionTimeout != nil {
		timeout = *s.SessionTimeout
	}
	for key, want := range map[string]string{
		"Domain id": mlagID(s.DomainID), "Local Ip": s.LocalAddress, "Peer Ip": s.PeerAddress,
		"Peer Link Interface": s.PeerLink, "Keepalive time": mlagID(keepalive), "sesssion Timeout": mlagID(timeout),
		"The MCLAG's keepalive is": "OK", "MCLAG info sync is": "completed",
	} {
		if e.Domain[key] != want {
			return fmt.Errorf("native %s: got %q, need %q", key, e.Domain[key], want)
		}
	}
	// mclagdctl overwrites the wire role using inet_addr ordering. STATE_DB is
	// the independent daemon role, so a CLI role alone is insufficient.
	role := e.Domain["Role"]
	domain := state["MCLAG_TABLE|"+mlagID(s.DomainID)]
	if (role != "Active" && role != "Standby") || domain["role"] != strings.ToLower(role) || domain["oper_status"] != "up" {
		return fmt.Errorf("native session/daemon role mismatch or unavailable")
	}
	members := map[string]bool{}
	if list := e.Domain["MCLAG Interface"]; list != "" {
		for _, name := range strings.Split(list, ",") {
			if !lagL3PortChannelName.MatchString(name) || members[name] {
				return fmt.Errorf("invalid native member list")
			}
			members[name] = true
		}
	}
	if len(members) != len(s.Members) {
		return fmt.Errorf("native member set differs from intent")
	}
	for _, name := range s.Members {
		if !members[name] {
			return fmt.Errorf("native member %s missing", name)
		}
		peer := e.Peer[name]
		if peer["Type"] != "PortChannel" || peer["State"] != "Up" || state["MCLAG_REMOTE_INTF_TABLE|"+mlagID(s.DomainID)+"|"+name]["oper_status"] != "up" {
			return fmt.Errorf("MLAG peer member %s is unavailable/down", name)
		}
	}
	for _, name := range append([]string{s.PeerLink}, s.Members...) {
		local := e.Local[name]
		if local["Type"] != "PortChannel" || local["State"] != "Up" || local["PortchannelIsUp"] != "1" || local["IsTrafficDisable"] != "No" || local["MemberPorts"] == "" {
			return fmt.Errorf("MLAG local LAG %s is unavailable/down/disabled", name)
		}
		link := e.Links[name]
		admin, carrier := false, false
		for _, flag := range link.Flags {
			admin = admin || flag == "UP"
			carrier = carrier || flag == "LOWER_UP"
		}
		if !admin || !carrier || link.OperState != "UP" {
			return fmt.Errorf("MLAG kernel LAG %s admin/oper not up", name)
		}
	}
	return nil
}
