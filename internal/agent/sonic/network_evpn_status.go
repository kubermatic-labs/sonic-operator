// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

func evpnSessionSummary(raw []byte, s evpnPeerSpec) (bool, error) {
	var fields map[string]json.RawMessage
	if err := mlagJSON(raw, &fields, false); err != nil {
		return false, err
	}
	if fields["peers"] == nil {
		return false, nil
	}
	var peers map[string]map[string]json.RawMessage
	if err := json.Unmarshal(fields["peers"], &peers); err != nil {
		return false, err
	}
	peer := peers[s.Address]
	if peer == nil {
		return false, nil
	}
	var asn uint32
	var state string
	if err := json.Unmarshal(peer["remoteAs"], &asn); err != nil {
		return false, fmt.Errorf("EVPN peer ASN evidence missing")
	}
	if err := json.Unmarshal(peer["state"], &state); err != nil {
		return false, fmt.Errorf("EVPN peer session state missing")
	}
	return asn == s.RemoteASN && state == "Established", nil
}

func evpnPeerEstablished(ctx context.Context, s evpnPeerSpec) (bool, json.RawMessage, error) {
	raw, err := evpnRead(ctx, "docker", "exec", "bgp", "vtysh", "-c", "show bgp l2vpn evpn summary json")
	if err != nil {
		return evpnObservation(false, "EVPN session probe failed", nil, err)
	}
	ok, err := evpnSessionSummary(raw, s)
	if err == nil && ok {
		detail, e := evpnRead(ctx, "docker", "exec", "bgp", "vtysh", "-c", "show bgp neighbors "+s.Address+" json")
		if e != nil {
			return evpnObservation(false, "EVPN capability probe failed", nil, e)
		}
		ok, err = evpnNegotiated(detail, s)
	}
	evidence := map[string]any{"peer": s.Address, "established": ok}
	if err == nil && ok {
		routes, e := evpnRead(ctx, "docker", "exec", "bgp", "vtysh", "-c", "show bgp l2vpn evpn route json")
		if e != nil {
			return evpnObservation(false, "EVPN route observation failed", evidence, e)
		}
		two, three, e := evpnRouteCounts(routes)
		if e != nil {
			return evpnObservation(false, "EVPN route decoding failed", evidence, e)
		}
		evidence["localEVPNRIBType2"], evidence["localEVPNRIBType3"] = two, three
	}
	return evpnObservation(ok, "EVPN AF session observation", evidence, err)
}

// FRR 10.4.1 route JSON groups prefixes by RD. Count prefixes, not paths;
// these local-RIB diagnostics do not assert a particular peer originated them.
func evpnRouteCounts(raw []byte) (int, int, error) {
	var groups map[string]json.RawMessage
	if err := mlagJSON(raw, &groups, false); err != nil {
		return 0, 0, err
	}
	two, three := 0, 0
	for rd, value := range groups {
		if evpnRD(rd) != nil {
			continue
		}
		var routes map[string]json.RawMessage
		if err := json.Unmarshal(value, &routes); err != nil {
			return 0, 0, err
		}
		for prefix, entry := range routes {
			if !strings.HasPrefix(prefix, "[2]:") && !strings.HasPrefix(prefix, "[3]:") {
				continue
			}
			var object map[string]json.RawMessage
			if err := json.Unmarshal(entry, &object); err != nil {
				return 0, 0, err
			}
			if object["paths"] == nil {
				return 0, 0, fmt.Errorf("EVPN prefix lacks paths")
			}
			if strings.HasPrefix(prefix, "[2]:") {
				two++
			} else {
				three++
			}
		}
	}
	return two, three, nil
}

func evpnNegotiated(raw []byte, s evpnPeerSpec) (bool, error) {
	var neighbors map[string]map[string]json.RawMessage
	if err := mlagJSON(raw, &neighbors, false); err != nil {
		return false, err
	}
	n := neighbors[s.Address]
	if n == nil {
		return false, nil
	}
	var asn uint32
	var local, state string
	if json.Unmarshal(n["remoteAs"], &asn) != nil || json.Unmarshal(n["hostLocal"], &local) != nil || json.Unmarshal(n["bgpState"], &state) != nil {
		return false, fmt.Errorf("EVPN neighbor identity evidence incomplete")
	}
	var capabilities struct {
		Multiprotocol map[string]struct {
			Both bool `json:"advertisedAndReceived"`
		} `json:"multiprotocolExtensions"`
	}
	if err := json.Unmarshal(n["neighborCapabilities"], &capabilities); err != nil {
		return false, fmt.Errorf("EVPN neighbor capabilities unavailable")
	}
	return asn == s.RemoteASN && local == s.LocalAddress && state == "Established" && capabilities.Multiprotocol["l2VpnEvpn"].Both, nil
}
