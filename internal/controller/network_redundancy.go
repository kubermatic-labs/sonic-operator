// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	"k8s.io/apimachinery/pkg/util/validation"
)

func isRedundancyKind(kind string) bool {
	switch kind {
	case "MLAG", "VXLANTunnel", "VLANVNI", "EVPNPeer", "EVPN":
		return true
	}
	return false
}

var redundancyName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,31}$`)

func redundancyIP(s string, ipv4 bool) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" || a.Is4In6() || (ipv4 && !a.Is4()) {
		return netip.Addr{}, fmt.Errorf("invalid redundancy IP %q", s)
	}
	return a, nil
}

func validRouteIdentifier(value api.RouteIdentifier) bool {
	s := string(value)
	a, b, ok := strings.Cut(s, ":")
	if !ok || len(s) > 21 {
		return false
	}
	n, err := strconv.ParseUint(b, 10, 32)
	if err != nil || strconv.FormatUint(n, 10) != b {
		return false
	}
	if strings.Contains(a, ".") {
		ip, err := redundancyIP(a, true)
		return err == nil && ip.String() == a && n <= 65535
	}
	asn, err := strconv.ParseUint(a, 10, 32)
	return err == nil && strconv.FormatUint(asn, 10) == a && (asn <= 65535 || n <= 65535)
}

//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func redundancyDesired(spec any) (string, error) {
	switch s := spec.(type) {
	case *api.SwitchMLAGSpec:
		if s.DomainID < 1 || s.DomainID > 4095 || len(validation.IsDNS1123Subdomain(s.PeerSwitchRef.Name)) != 0 || s.PeerSwitchRef.Name == s.SwitchRef.Name {
			return "", fmt.Errorf("MLAG requires domainID 1..4095 and a distinct peerSwitchRef")
		}
		local, err := redundancyIP(string(s.LocalAddress), true)
		if err != nil {
			return "", err
		}
		peer, err := redundancyIP(string(s.PeerAddress), true)
		if err != nil || local == peer || !local.IsGlobalUnicast() || !peer.IsGlobalUnicast() {
			return "", fmt.Errorf("MLAG requires distinct unicast IPv4 addresses")
		}
		if !networkPortChannel.MatchString(string(s.PeerLink)) || len(s.Members) == 0 || len(s.Members) > 256 {
			return "", fmt.Errorf("MLAG requires a peerLink and members PortChannels")
		}
		seen := map[api.MLAGPortChannel]bool{s.PeerLink: true}
		for _, m := range s.Members {
			if !networkPortChannel.MatchString(string(m)) || seen[m] {
				return "", fmt.Errorf("invalid, duplicate or peerLink MLAG member")
			}
			seen[m] = true
		}
		if s.KeepaliveInterval == 0 {
			s.KeepaliveInterval = 1
		}
		if s.SessionTimeout == 0 {
			s.SessionTimeout = 30
		}
		if s.KeepaliveInterval > 60 || s.SessionTimeout > 3600 || s.SessionTimeout < 3*s.KeepaliveInterval {
			return "", fmt.Errorf("invalid MLAG timers")
		}
		return strconv.FormatUint(uint64(s.DomainID), 10), nil
	case *api.SwitchVXLANTunnelSpec:
		if !redundancyName.MatchString(string(s.Name)) || !redundancyName.MatchString(string(s.EVPNNVO)) {
			return "", fmt.Errorf("invalid tunnel or NVO name")
		}
		if _, err := redundancyIP(string(s.SourceAddress), true); err != nil {
			return "", err
		}
		return string(s.Name), nil
	case *api.SwitchVLANVNISpec:
		if !redundancyName.MatchString(string(s.Tunnel)) || s.VLANID < 1 || s.VLANID > 4094 || s.VNI < 1 || s.VNI > 16777215 || !validRouteIdentifier(s.RouteDistinguisher) {
			return "", fmt.Errorf("invalid VLAN/VNI mapping or route distinguisher")
		}
		for _, targets := range [][]api.RouteIdentifier{s.ImportRouteTargets, s.ExportRouteTargets} {
			if len(targets) == 0 || len(targets) > 64 {
				return "", fmt.Errorf("nonempty import and export route targets required (maximum 64)")
			}
			seen := map[api.RouteIdentifier]bool{}
			for _, rt := range targets {
				if !validRouteIdentifier(rt) || seen[rt] {
					return "", fmt.Errorf("invalid or duplicate route target")
				}
				seen[rt] = true
			}
		}
		return string(s.Tunnel) + "|" + strconv.FormatUint(uint64(s.VLANID), 10), nil
	case *api.SwitchEVPNPeerSpec:
		if s.Role == "" {
			s.Role = "Leaf"
		}
		if s.Role != "Leaf" && s.Role != "Transit" {
			return "", fmt.Errorf("invalid EVPN peer role")
		}
		if s.Role == "Transit" {
			if len(s.MappingRefs) != 0 {
				return "", fmt.Errorf("transit peers cannot reference local mappings")
			}
			for _, targets := range [][]api.RouteIdentifier{s.ImportRouteTargets, s.ExportRouteTargets} {
				if len(targets) == 0 || len(targets) > 64 {
					return "", fmt.Errorf("transit peers require bounded explicit RT sets")
				}
				seen := map[api.RouteIdentifier]bool{}
				for _, rt := range targets {
					if !validRouteIdentifier(rt) || seen[rt] {
						return "", fmt.Errorf("invalid or duplicate transit RT")
					}
					seen[rt] = true
				}
			}
		} else if len(s.ImportRouteTargets) != 0 || len(s.ExportRouteTargets) != 0 {
			return "", fmt.Errorf("leaf policy derives RTs from mappings")
		}
		if len(s.MappingRefs) > 64 {
			return "", fmt.Errorf("EVPN permits at most 64 mapping references")
		}
		seen := map[string]bool{}
		for _, ref := range s.MappingRefs {
			if seen[ref.Name] || len(validation.IsDNS1123Subdomain(ref.Name)) != 0 {
				return "", fmt.Errorf("invalid or duplicate EVPN mapping reference")
			}
			seen[ref.Name] = true
		}
		if s.VRF == "" {
			s.VRF = "default"
		}
		if s.AdminState == "" {
			s.AdminState = api.AdminStateDown
		}
		if s.VRF != "default" || s.RemoteASN == 0 || (s.AdminState != api.AdminStateDown && s.AdminState != api.AdminStateUp) {
			return "", fmt.Errorf("EVPN requires default VRF, nonzero remoteASN and Up/Down adminState")
		}
		peer, err := redundancyIP(string(s.Address), false)
		if err != nil {
			return "", err
		}
		local, err := redundancyIP(string(s.LocalAddress), false)
		if err != nil || peer.Is4() != local.Is4() {
			return "", fmt.Errorf("EVPN localAddress must match peer family")
		}
		s.Address, s.LocalAddress = api.NetworkIP(peer.String()), api.NetworkIP(local.String())
		return "default|" + peer.String(), nil
	default:
		return "", fmt.Errorf("unsupported redundancy spec")
	}
}
