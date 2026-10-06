// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"fmt"
	"maps"
	"strconv"
	"strings"
)

// Validate exact definitions and attachments, including the unconditional deny.
// Unknown commands in an owned map are rejected, rather than treated as harmless
// formatting differences. Policy evidence must come from the target BGP AF.
func evpnVerifyPeerPolicy(raw []byte, asn, peer string, p *evpnPeerPolicy) error {
	if p == nil || len(raw) > 1<<20 {
		return fmt.Errorf("missing or oversized EVPN policy evidence")
	}
	wantCommunities := map[string]bool{}
	for _, direction := range []struct {
		name    string
		targets []string
	}{{p.In, p.Import}, {p.Out, p.Export}} {
		for _, rt := range direction.targets {
			wantCommunities["bgp extcommunity-list standard "+direction.name+" permit rt "+rt] = true
		}
	}
	communities, definitions, matches, attachments := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	sequences := map[string]bool{}
	instance, af, activeMap := false, false, ""
	vni := false
	for _, line := range strings.Split(string(raw), "\n") {
		s := strings.Join(strings.Fields(line), " ")
		if s == "" || s == "!" {
			continue
		}
		if s == "exit" && activeMap != "" {
			activeMap = ""
			continue
		}
		if strings.HasPrefix(s, "router bgp ") {
			instance, af, activeMap = s == "router bgp "+asn || s == "router bgp "+asn+" vrf default", false, ""
			vni = false
			continue
		}
		if strings.HasPrefix(s, "address-family ") {
			af = instance && s == "address-family l2vpn evpn"
			vni = false
			continue
		}
		if s == "exit-address-family" {
			af = false
			vni = false
			continue
		}
		if instance && (strings.Contains(s, " peer-group") || strings.HasPrefix(s, "bgp listen ")) {
			return fmt.Errorf("inherited/dynamic EVPN peer policy unsupported")
		}
		if af && !vni && strings.HasPrefix(s, "no neighbor "+peer+" send-community") {
			if s == "no neighbor "+peer+" send-community extended" || s == "no neighbor "+peer+" send-community all" || s == "no neighbor "+peer+" send-community both" {
				return fmt.Errorf("EVPN extended communities disabled")
			}
		}
		if af && strings.HasPrefix(s, "vni ") {
			vni = true
			continue
		}
		if af && s == "exit-vni" {
			vni = false
			continue
		}
		if strings.HasPrefix(s, "route-map ") {
			instance, af, activeMap = false, false, ""
			f := strings.Fields(s)
			if len(f) >= 2 && (f[1] == p.In || f[1] == p.Out) {
				if len(f) != 4 || !((f[2] == "permit" && f[3] == "10") || (f[2] == "deny" && f[3] == "65535")) || definitions[s] {
					return fmt.Errorf("unexpected owned EVPN route-map definition")
				}
				definitions[s], activeMap = true, s
			}
			continue
		}
		if activeMap != "" && line[0] != ' ' && line[0] != '\t' {
			activeMap = ""
		}
		if activeMap != "" {
			f := strings.Fields(activeMap)
			if s != "match extcommunity "+f[1] || f[2] != "permit" || matches[activeMap] {
				return fmt.Errorf("unexpected owned EVPN route-map action")
			}
			matches[activeMap] = true
			continue
		}
		if strings.HasPrefix(s, "bgp extcommunity-list ") {
			f := strings.Fields(s)
			if len(f) >= 4 && (f[3] == p.In || f[3] == p.Out) {
				if len(f) > 4 && f[4] == "seq" {
					if len(f) != 9 {
						return fmt.Errorf("malformed EVPN RT sequence")
					}
					n, err := strconv.ParseUint(f[5], 10, 32)
					id := f[3] + "|" + f[5]
					if err != nil || n == 0 || strconv.FormatUint(n, 10) != f[5] || sequences[id] {
						return fmt.Errorf("invalid or duplicate EVPN RT sequence")
					}
					sequences[id] = true
					s = strings.Join(append(append([]string{}, f[:4]...), f[6:]...), " ")
				}
				if !wantCommunities[s] || communities[s] {
					return fmt.Errorf("unexpected EVPN RT list entry")
				}
				communities[s] = true
			}
			continue
		}
		if af && !vni && strings.HasPrefix(s, "neighbor "+peer+" ") {
			if strings.Contains(s, " route-map ") || strings.Contains(s, " send-community") || strings.Contains(s, " attribute-unchanged") {
				if attachments[s] {
					return fmt.Errorf("duplicate EVPN policy attachment")
				}
				attachments[s] = true
			}
		}
		if line[0] != ' ' && line[0] != '\t' {
			instance, af = false, false
		}
	}
	if !maps.Equal(communities, wantCommunities) {
		return fmt.Errorf("EVPN RT list not fully applied")
	}
	for _, name := range []string{p.In, p.Out} {
		if !definitions["route-map "+name+" permit 10"] || !matches["route-map "+name+" permit 10"] || !definitions["route-map "+name+" deny 65535"] {
			return fmt.Errorf("EVPN route-map permit/match/default-deny not fully applied")
		}
	}
	// In the pinned FRR release, absence of a send-community statement means
	// extended communities are enabled. Explicit disabling was rejected above.
	wantAttachments := map[string]bool{"neighbor " + peer + " route-map " + p.In + " in": true, "neighbor " + peer + " route-map " + p.Out + " out": true}
	if attachments["neighbor "+peer+" send-community extended"] {
		wantAttachments["neighbor "+peer+" send-community extended"] = true
	}
	if p.Transit {
		wantAttachments["neighbor "+peer+" attribute-unchanged next-hop"] = true
	}
	if !maps.Equal(attachments, wantAttachments) {
		return fmt.Errorf("EVPN policy attachment or community mode not applied")
	}
	return nil
}
