// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

type mlagSpec struct {
	lagL3Selectors
	DomainID      uint32 `json:"domainID"`
	PeerSwitchRef struct {
		Name string `json:"name"`
	} `json:"peerSwitchRef"`
	LocalAddress      string   `json:"localAddress"`
	PeerAddress       string   `json:"peerAddress"`
	PeerLink          string   `json:"peerLink"`
	Members           []string `json:"members"`
	KeepaliveInterval *uint32  `json:"keepaliveInterval,omitempty"`
	SessionTimeout    *uint32  `json:"sessionTimeout,omitempty"`
}

// Reject duplicates and null at every depth before decoding. Native JSON uses
// this too: neither last-key-wins nor a null scalar is trustworthy evidence.
func mlagJSON(data []byte, out any, spec bool) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 32 {
			return fmt.Errorf("MLAG JSON nesting limit exceeded")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		if t == nil {
			return fmt.Errorf("null MLAG JSON value")
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		seen := map[string]bool{}
		for d.More() {
			if delim == '{' {
				t, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := t.(string)
				if !ok || seen[key] {
					return fmt.Errorf("duplicate MLAG JSON field")
				}
				seen[key] = true
				if spec {
					allowed := " switchRef managementPolicy domainID peerSwitchRef localAddress peerAddress peerLink members keepaliveInterval sessionTimeout "
					if depth > 0 {
						allowed = " name "
					}
					if !strings.Contains(allowed, " "+key+" ") {
						return fmt.Errorf("unknown MLAG spec field %q", key)
					}
				}
			}
			if err := walk(depth + 1); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("trailing MLAG JSON")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(out)
}

func mlagID(id uint32) string { return strconv.FormatUint(uint64(id), 10) }

func planNetworkMLAG(db vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
	if err := agent.ValidateNetworkRequest(r, false); err != nil {
		return nil, err
	}
	if r.Kind != "MLAG" {
		return nil, fmt.Errorf("expected MLAG request")
	}
	var s mlagSpec
	if err := mlagJSON(r.Spec, &s, true); err != nil {
		return nil, err
	}
	if s.DomainID < 1 || s.DomainID > 4095 {
		return nil, fmt.Errorf("MLAG domainID must be 1..4095")
	}
	if s.PeerSwitchRef.Name == "" || (s.SwitchRef.Name != "" && s.PeerSwitchRef.Name == s.SwitchRef.Name) {
		return nil, fmt.Errorf("MLAG requires a distinct peerSwitchRef")
	}
	if s.ManagementPolicy != "" && s.ManagementPolicy != "Observe" && s.ManagementPolicy != "Manage" {
		return nil, fmt.Errorf("invalid MLAG managementPolicy")
	}
	local, err := netip.ParseAddr(s.LocalAddress)
	if err != nil || !local.Is4() || !local.IsGlobalUnicast() {
		return nil, fmt.Errorf("MLAG localAddress must be unicast IPv4")
	}
	peer, err := netip.ParseAddr(s.PeerAddress)
	if err != nil || !peer.Is4() || !peer.IsGlobalUnicast() || local == peer {
		return nil, fmt.Errorf("MLAG peerAddress must be distinct unicast IPv4")
	}
	keepalive, timeout := uint32(1), uint32(30)
	if s.KeepaliveInterval != nil {
		keepalive = *s.KeepaliveInterval
	}
	if s.SessionTimeout != nil {
		timeout = *s.SessionTimeout
	}
	if keepalive < 1 || keepalive > 60 || timeout < 1 || timeout > 3600 || timeout < 3*keepalive {
		return nil, fmt.Errorf("MLAG timers require keepalive 1..60, timeout 1..3600 and timeout >= 3*keepalive")
	}
	if !lagL3PortChannelName.MatchString(s.PeerLink) {
		return nil, fmt.Errorf("MLAG peerLink must be a canonical PortChannel")
	}
	if len(s.Members) > 4096 {
		return nil, fmt.Errorf("MLAG member limit exceeded")
	}
	seen := map[string]bool{s.PeerLink: true}
	desired := vlanChangeDB{"MCLAG_DOMAIN|" + mlagID(s.DomainID): {
		"source_ip": s.LocalAddress, "peer_ip": s.PeerAddress, "peer_link": s.PeerLink,
		"keepalive_interval": mlagID(keepalive), "session_timeout": mlagID(timeout),
	}}
	for _, member := range s.Members {
		if !lagL3PortChannelName.MatchString(member) || seen[member] {
			return nil, fmt.Errorf("invalid/duplicate MLAG member or member is peerLink")
		}
		seen[member] = true
		desired["MCLAG_INTERFACE|"+mlagID(s.DomainID)+"|"+member] = map[string]string{"if_type": "PortChannel"}
	}
	// Keep dependency checks in Preflight so Observe can describe missing local
	// dependencies. Repeat against a fresh snapshot before every attempted CAS.
	p := &networkPlan{Identity: "MLAG|" + mlagID(s.DomainID), Desired: desired}
	p.Preflight = func(ctx context.Context, m *SonicAgent) error {
		_, err := mlagPreflight(ctx, m, s)
		return err
	}
	p.Runtime = func(ctx context.Context, m *SonicAgent) (bool, json.RawMessage, error) { return mlagRuntime(ctx, m, s) }
	return p, nil
}

// Shared by write preflight and observation: eligibility requires all local
// checks, whereas consumerReady describes only the audited running consumers.
func mlagPreflight(ctx context.Context, m *SonicAgent, s mlagSpec) (consumerReady bool, err error) {
	if err := mlagNativeSupport(ctx); err != nil {
		return false, err
	}
	current, _, err := m.vlanChangeSnapshot(ctx)
	if err != nil {
		return true, err
	}
	if err := mlagDependencies(current, s); err != nil {
		return true, err
	}
	return true, mlagReachability(ctx, current, s)
}

func mlagDependencies(db vlanChangeDB, s mlagSpec) error {
	domain := mlagID(s.DomainID)
	members := map[string]bool{}
	for _, member := range s.Members {
		members[member] = true
	}
	for key := range db {
		if strings.HasPrefix(key, "MCLAG_DOMAIN|") && key != "MCLAG_DOMAIN|"+domain {
			return fmt.Errorf("native MLAG supports only one domain")
		}
		if strings.HasPrefix(key, "MCLAG_INTERFACE|") {
			parts := strings.Split(key, "|")
			if len(parts) != 3 || parts[1] != domain || !members[parts[2]] || parts[2] == s.PeerLink {
				return fmt.Errorf("conflicting native MLAG member %s", key)
			}
		}
		parts := strings.Split(key, "|")
		if len(parts) == 3 && (parts[0] == "INTERFACE" || parts[0] == "PORTCHANNEL_INTERFACE" || parts[0] == "VLAN_INTERFACE" || parts[0] == "LOOPBACK_INTERFACE" || parts[0] == "MGMT_INTERFACE") {
			if prefix, err := netip.ParsePrefix(parts[2]); err == nil && prefix.Addr().String() == s.PeerAddress {
				return fmt.Errorf("MLAG peerAddress is configured locally")
			}
		}
	}
	lags := append([]string{s.PeerLink}, s.Members...)
	physical := map[string]string{}
	for _, lag := range lags {
		if len(db["PORTCHANNEL|"+lag]) == 0 {
			return fmt.Errorf("MLAG LAG %s does not exist", lag)
		}
		count := 0
		for key := range db {
			if !strings.HasPrefix(key, "PORTCHANNEL_MEMBER|"+lag+"|") {
				continue
			}
			port := strings.TrimPrefix(key, "PORTCHANNEL_MEMBER|"+lag+"|")
			if _, ok := ethernetNumber(port); !ok || len(db["PORT|"+port]) == 0 {
				return fmt.Errorf("MLAG LAG %s has invalid/non-data member %s", lag, port)
			}
			if other, ok := physical[port]; ok && other != lag {
				return fmt.Errorf("MLAG LAGs share physical member %s", port)
			}
			physical[port] = lag
			count++
		}
		if count == 0 {
			return fmt.Errorf("MLAG LAG %s has no physical members", lag)
		}
	}
	sources := mlagSources(db, s.LocalAddress)
	if len(sources) != 1 {
		return fmt.Errorf("MLAG localAddress requires exactly one configured default-VRF data L3 source")
	}
	return nil
}

// Only explicitly configured data-plane L3 addresses qualify; MGMT_INTERFACE
// and non-default VRFs cannot accidentally provide the ICCP source/path.
func mlagSources(db vlanChangeDB, address string) []string {
	var sources []string
	for key := range db {
		parts := strings.Split(key, "|")
		if len(parts) != 3 {
			continue
		}
		if parts[0] != "INTERFACE" && parts[0] != "PORTCHANNEL_INTERFACE" && parts[0] != "VLAN_INTERFACE" && parts[0] != "LOOPBACK_INTERFACE" {
			continue
		}
		if parts[0] == "LOOPBACK_INTERFACE" {
			n, err := strconv.ParseUint(strings.TrimPrefix(parts[1], "Loopback"), 10, 32)
			if err != nil || parts[1] != "Loopback"+strconv.FormatUint(n, 10) {
				continue
			}
		} else if lagL3InterfaceTable(parts[1]) != parts[0] || lagL3InterfaceExists(db, parts[1]) != nil {
			continue
		}
		if vrf := db[parts[0]+"|"+parts[1]]["vrf_name"]; vrf != "" && vrf != "default" {
			continue
		}
		prefix, err := netip.ParsePrefix(parts[2])
		if err == nil && prefix.Addr().String() == address {
			sources = append(sources, parts[1])
		}
	}
	return sources
}
