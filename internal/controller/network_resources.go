// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Explicit dispatch keeps the shared safety loop restricted to known APIs.
func networkObjects(kind string) (client.Object, client.ObjectList, error) {
	switch kind {
	case "PortChannel":
		return &api.SwitchPortChannel{}, &api.SwitchPortChannelList{}, nil
	case "VRF":
		return &api.SwitchVRF{}, &api.SwitchVRFList{}, nil
	case "L3Interface":
		return &api.SwitchL3Interface{}, &api.SwitchL3InterfaceList{}, nil
	case "StaticRoute":
		return &api.SwitchStaticRoute{}, &api.SwitchStaticRouteList{}, nil
	case "BGP":
		return &api.SwitchBGP{}, &api.SwitchBGPList{}, nil
	case "BGPPeer":
		return &api.SwitchBGPPeer{}, &api.SwitchBGPPeerList{}, nil
	case "DHCPRelay":
		return &api.SwitchDHCPRelay{}, &api.SwitchDHCPRelayList{}, nil
	case "FRRMigration":
		return &api.SwitchFRRMigration{}, &api.SwitchFRRMigrationList{}, nil
	default:
		return nil, nil, fmt.Errorf("unsupported network kind %q", kind)
	}
}

func networkFields(obj client.Object) (any, *api.NetworkResourceStatus, *api.NetworkResourceSpec) {
	switch o := obj.(type) {
	case *api.SwitchPortChannel:
		return &o.Spec, &o.Status, &o.Spec.NetworkResourceSpec
	case *api.SwitchVRF:
		return &o.Spec, &o.Status, &o.Spec.NetworkResourceSpec
	case *api.SwitchL3Interface:
		return &o.Spec, &o.Status, &o.Spec.NetworkResourceSpec
	case *api.SwitchStaticRoute:
		return &o.Spec, &o.Status, &o.Spec.NetworkResourceSpec
	case *api.SwitchBGP:
		return &o.Spec, &o.Status, &o.Spec.NetworkResourceSpec
	case *api.SwitchBGPPeer:
		return &o.Spec, &o.Status, &o.Spec.NetworkResourceSpec
	case *api.SwitchDHCPRelay:
		return &o.Spec, &o.Status, &o.Spec.NetworkResourceSpec
	case *api.SwitchFRRMigration:
		return &o.Spec, &o.Status, &o.Spec.NetworkResourceSpec
	default:
		panic("networkFields called with a non-network object")
	}
}

var (
	networkPortChannel = regexp.MustCompile(`^PortChannel(0|[1-9][0-9]{0,3})$`)
	networkEthernet    = regexp.MustCompile(`^Ethernet(0|[1-9][0-9]*)$`)
	networkInterface   = regexp.MustCompile(`^(Ethernet|PortChannel|Vlan)(0|[1-9][0-9]*)$`)
	networkVRF         = regexp.MustCompile(`^Vrf[A-Za-z0-9_-]{1,12}$`)
	networkDigest      = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

// networkDesired validates even fake/admission-bypassing objects, and fills only
// documented defaults on a copy. Never use a normalized copy for freshness CAS.
func networkDesired(kind string, obj client.Object) (*agent.NetworkRequest, string, error) {
	copy := obj.DeepCopyObject().(client.Object)
	spec, _, common := networkFields(copy)
	if obj.GetUID() == "" || len(validation.IsDNS1123Subdomain(common.SwitchRef.Name)) != 0 {
		return nil, "", fmt.Errorf("a CR UID and valid switchRef are required")
	}
	if common.ManagementPolicy == "" {
		common.ManagementPolicy = api.NetworkManagementPolicyObserve
	}
	if common.ManagementPolicy != api.NetworkManagementPolicyObserve && common.ManagementPolicy != api.NetworkManagementPolicyManage {
		return nil, "", fmt.Errorf("invalid managementPolicy")
	}
	vrf := func(v *api.NetworkVRFName) error {
		if *v == "" {
			*v = "default"
		}
		if *v != "default" && !networkVRF.MatchString(string(*v)) {
			return fmt.Errorf("invalid vrf")
		}
		return nil
	}
	ip := func(s string) (netip.Addr, error) {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" || a.Is4In6() {
			return netip.Addr{}, fmt.Errorf("invalid IP address %q", s)
		}
		return a, nil
	}
	prefix := func(s string, canonical bool) (netip.Prefix, error) {
		p, err := netip.ParsePrefix(s)
		if err != nil || p.Addr().Is4In6() || (canonical && p.Masked().String() != s) {
			return netip.Prefix{}, fmt.Errorf("invalid IPv4/IPv6 prefix %q", s)
		}
		return p, nil
	}
	validInterface := func(s string) bool {
		if len(s) > 32 || !networkInterface.MatchString(s) {
			return false
		}
		if strings.HasPrefix(s, "PortChannel") {
			return networkPortChannel.MatchString(s)
		}
		if strings.HasPrefix(s, "Vlan") {
			n, err := strconv.Atoi(s[4:])
			return err == nil && n >= 1 && n <= 4094
		}
		return true
	}
	target := ""
	switch s := spec.(type) {
	case *api.SwitchFRRMigrationSpec:
		if s.Mode != "Unified" && s.Mode != "Traditional" {
			return nil, "", fmt.Errorf("FRR migration mode must be Traditional or Unified")
		}
		if s.ApprovedDigest != "" && !networkDigest.MatchString(s.ApprovedDigest) {
			return nil, "", fmt.Errorf("approvedDigest must be a lowercase SHA256 digest")
		}
		// Legacy opaque device-wide identity, independent of desired direction.
		// Preserve forward bindings and reject competing claims across modes.
		target = "unified"
	case *api.SwitchPortChannelSpec:
		if !networkPortChannel.MatchString(s.Name) || len(s.Name) > 32 || len(s.Members) == 0 || len(s.Members) > 256 {
			return nil, "", fmt.Errorf("invalid port channel name or members")
		}
		seen := map[string]bool{}
		for _, m := range s.Members {
			if len(m) > 32 || !networkEthernet.MatchString(m) || seen[m] {
				return nil, "", fmt.Errorf("invalid or duplicate member %q", m)
			}
			seen[m] = true
		}
		if s.MinLinks == 0 {
			s.MinLinks = 1
		}
		if s.MinLinks > uint32(len(s.Members)) {
			return nil, "", fmt.Errorf("minLinks exceeds member count")
		}
		if s.LACPMode == "" {
			s.LACPMode = "active"
		}
		if s.LACPMode != "active" {
			return nil, "", fmt.Errorf("invalid lacpMode")
		}
		if s.MTU == 0 {
			s.MTU = 9100
		}
		if s.MTU < 1280 || s.MTU > 9216 {
			return nil, "", fmt.Errorf("invalid mtu")
		}
		if s.AdminState == "" {
			s.AdminState = api.AdminStateUp
		}
		if s.AdminState != api.AdminStateUp && s.AdminState != api.AdminStateDown {
			return nil, "", fmt.Errorf("invalid adminState")
		}
		target = s.Name
	case *api.SwitchVRFSpec:
		if !networkVRF.MatchString(s.Name) {
			return nil, "", fmt.Errorf("invalid VRF name")
		}
		target = s.Name
	case *api.SwitchL3InterfaceSpec:
		if err := vrf(&s.VRF); err != nil {
			return nil, "", err
		}
		if !validInterface(s.Name) || len(s.Addresses) == 0 || len(s.Addresses) > 64 {
			return nil, "", fmt.Errorf("invalid L3 interface or addresses")
		}
		seen := map[netip.Prefix]bool{}
		for _, address := range s.Addresses {
			p, err := prefix(string(address), false)
			if err != nil {
				return nil, "", err
			}
			if seen[p] {
				return nil, "", fmt.Errorf("duplicate interface address")
			}
			seen[p] = true
		}
		// A native interface can have only one VRF binding, so VRF is not part of its claim key.
		target = s.Name
	case *api.SwitchStaticRouteSpec:
		if err := vrf(&s.VRF); err != nil {
			return nil, "", err
		}
		p, err := prefix(string(s.Prefix), true)
		if err != nil {
			return nil, "", err
		}
		if len(s.NextHops) == 0 || len(s.NextHops) > 64 {
			return nil, "", fmt.Errorf("invalid nextHops count")
		}
		seen := map[netip.Addr]bool{}
		for i := range s.NextHops {
			n := &s.NextHops[i]
			a, err := ip(string(n.Address))
			if err != nil {
				return nil, "", err
			}
			if seen[a] || a.Is4() != p.Addr().Is4() || (n.InterfaceName != "" && !validInterface(n.InterfaceName)) {
				return nil, "", fmt.Errorf("duplicate, wrong-family or invalid next hop")
			}
			seen[a] = true
			if n.Distance == 0 {
				n.Distance = 1
			}
			if n.Distance > 255 {
				return nil, "", fmt.Errorf("invalid next hop distance")
			}
		}
		target = string(s.VRF) + "/" + string(s.Prefix)
	case *api.SwitchBGPSpec:
		if err := vrf(&s.VRF); err != nil {
			return nil, "", err
		}
		a, err := ip(s.RouterID)
		if err != nil || !a.Is4() || s.LocalASN == 0 {
			return nil, "", fmt.Errorf("BGP requires nonzero localASN and IPv4 routerID")
		}
		if len(s.Prefixes) > 256 {
			return nil, "", fmt.Errorf("too many BGP prefixes")
		}
		seen := map[netip.Prefix]bool{}
		for _, value := range s.Prefixes {
			p, err := prefix(string(value), true)
			if err != nil {
				return nil, "", err
			}
			if seen[p] {
				return nil, "", fmt.Errorf("duplicate BGP prefix")
			}
			seen[p] = true
		}
		if s.Prefixes == nil {
			s.Prefixes = []api.NetworkPrefix{}
		}
		target = string(s.VRF)
	case *api.SwitchBGPPeerSpec:
		if err := vrf(&s.VRF); err != nil {
			return nil, "", err
		}
		a, err := ip(string(s.Address))
		if err != nil || s.RemoteASN == 0 {
			return nil, "", fmt.Errorf("peer requires an IP address and nonzero remoteASN")
		}
		if s.LocalAddress != "" {
			local, err := ip(string(s.LocalAddress))
			if err != nil || local.Is4() != a.Is4() {
				return nil, "", fmt.Errorf("localAddress must match peer family")
			}
		}
		if len(s.AddressFamilies) == 0 || len(s.AddressFamilies) > 2 {
			return nil, "", fmt.Errorf("invalid addressFamilies")
		}
		seen := map[string]bool{}
		for _, af := range s.AddressFamilies {
			if (af != "ipv4Unicast" && af != "ipv6Unicast") || seen[af] {
				return nil, "", fmt.Errorf("invalid or duplicate address family")
			}
			seen[af] = true
		}
		if s.AdminState == "" {
			s.AdminState = api.AdminStateDown
		}
		if s.AdminState != api.AdminStateUp && s.AdminState != api.AdminStateDown {
			return nil, "", fmt.Errorf("invalid adminState")
		}
		if s.MaxPrefixes == 0 {
			s.MaxPrefixes = 1000
		}
		target = string(s.VRF) + "/" + a.String()
	case *api.SwitchDHCPRelaySpec:
		if err := vrf(&s.VRF); err != nil {
			return nil, "", err
		}
		if s.VLANID < 1 || s.VLANID > 4094 {
			return nil, "", fmt.Errorf("invalid vlanID")
		}
		if len(s.IPv4Servers)+len(s.IPv6Servers) == 0 {
			return nil, "", fmt.Errorf("at least one relay server is required; discovery and removal are unsupported")
		}
		for i, servers := range [][]string{s.IPv4Servers, s.IPv6Servers} {
			if len(servers) > 16 {
				return nil, "", fmt.Errorf("too many relay servers")
			}
			seen := map[netip.Addr]bool{}
			for _, server := range servers {
				a, err := ip(server)
				if err != nil || a.Is4() != (i == 0) || seen[a] {
					return nil, "", fmt.Errorf("invalid, duplicate or wrong-family relay server")
				}
				seen[a] = true
			}
		}
		// A VLAN's relay cannot be claimed twice using different VRFs.
		target = strconv.FormatUint(uint64(s.VLANID), 10)
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		return nil, "", err
	}
	return &agent.NetworkRequest{Kind: kind, OwnerID: string(obj.GetUID()), Spec: raw}, target, nil
}
