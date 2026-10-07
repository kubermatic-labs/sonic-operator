// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"strings"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

type evpnGlobalSpec struct {
	routingSpecMeta
	Tunnel      string `json:"tunnel"`
	AdminState  string `json:"adminState"`
	MappingRefs []struct {
		Name string `json:"name"`
	} `json:"mappingRefs,omitempty"`
	Mappings []agent.EVPNMappingSnapshot `json:"mappings,omitempty"`
}

const evpnGlobalKey = "BGP_GLOBALS_AF|default|l2vpn_evpn"

func evpnGlobalFields(up bool) map[string]string {
	value := "false"
	if up {
		value = "true"
	}
	return map[string]string{"advertise-all-vni": value, "advertise-svi-ip": "false", "advertise-default-gw": "false", "advertise-ipv4-unicast": "false", "advertise-ipv6-unicast": "false"}
}

//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func planNetworkEVPN(db vlanChangeDB, r *agent.NetworkRequest) (*networkPlan, error) {
	var s evpnGlobalSpec
	if r == nil {
		return nil, fmt.Errorf("EVPN request required")
	}
	if err := mlagJSON(r.Spec, &s, false); err != nil {
		return nil, err
	}
	if err := routingDecode(r, "EVPN", &s, "tunnel adminState mappingRefs mappings"); err != nil {
		return nil, err
	}
	if !evpnName.MatchString(s.Tunnel) || db["VXLAN_TUNNEL|"+s.Tunnel]["src_ip"] == "" {
		return nil, fmt.Errorf("EVPN requires existing source tunnel")
	}
	if s.AdminState == "" {
		s.AdminState = "Down"
	}
	if s.AdminState != "Down" && s.AdminState != "Up" {
		return nil, fmt.Errorf("invalid EVPN admin state")
	}
	if s.AdminState == "Up" {
		if len(s.MappingRefs) != len(s.Mappings) || len(s.Mappings) == 0 {
			return nil, fmt.Errorf("EVPN Up requires resolved mapping references")
		}
		for i, ref := range s.MappingRefs {
			if ref.Name != s.Mappings[i].Name || s.Mappings[i].Tunnel != s.Tunnel {
				return nil, fmt.Errorf("EVPN mapping reference/tunnel mismatch")
			}
		}
		if err := evpnInitializationMappings(db, s.Mappings); err != nil {
			return nil, err
		}
	}
	clean := maps.Clone(db)
	delete(clean, evpnGlobalKey)
	if err := evpnSafeConfig(clean); err != nil {
		return nil, err
	}
	desired := vlanChangeDB{evpnGlobalKey: evpnGlobalFields(s.AdminState == "Up")}
	if row := db[evpnGlobalKey]; row != nil && !evpnGlobalConfigValid(row) {
		return nil, fmt.Errorf("foreign global EVPN policy")
	}
	p := &networkPlan{Identity: "EVPN|default", Desired: desired}
	p.Preflight = func(ctx context.Context, m *SonicAgent) error {
		if err := evpnNative(ctx); err != nil {
			return err
		}
		current, _, err := m.vlanChangeSnapshot(ctx)
		if err != nil {
			return err
		}
		if _, err := planNetworkEVPN(current, r); err != nil {
			return err
		}
		if s.AdminState != "Up" {
			return nil
		}
		config, err := runRoutingRead(ctx, routingBGPConfig)
		if err != nil {
			return err
		}
		if _, err := evpnFRRParse(config, current); err != nil {
			return err
		}
		if current[evpnGlobalKey]["advertise-all-vni"] != "true" {
			return evpnInitializationShutdown(config, current)
		}
		// Local initialization can be saved before RD/RT and hardware exist.
		// Once any peer is live, the full operational prerequisites apply.
		if err := evpnInitializationShutdown(config, current); err == nil {
			return nil
		}
		if err := evpnOwnedMappings(m, current, s.Mappings); err != nil {
			return err
		}
		for _, ref := range s.Mappings {
			ok, err := evpnMapASIC(ctx, qosRedisRead{m}, ref.Tunnel, current["VXLAN_TUNNEL|"+ref.Tunnel]["src_ip"], ref.VLANID, ref.VNI)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("EVPN mapping hardware not applied")
			}
			spec := evpnMapSpec{Tunnel: ref.Tunnel, VLANID: ref.VLANID, VNI: ref.VNI, RouteDistinguisher: ref.RouteDistinguisher, ImportRouteTargets: ref.ImportRouteTargets, ExportRouteTargets: ref.ExportRouteTargets}
			if err := evpnFRRVNI(config, current["BGP_GLOBALS|default"]["local_asn"], spec, true); err != nil {
				return err
			}
		}
		for key := range current {
			if strings.HasPrefix(key, "BGP_NEIGHBOR|default|") {
				peer := strings.TrimPrefix(key, "BGP_NEIGHBOR|default|")
				policy, err := evpnConfiguredPeerPolicy(current, peer)
				if err != nil {
					return err
				}
				if err := evpnOwnedPolicy(m, current, peer); err != nil {
					return err
				}
				if err := evpnVerifyPeerPolicy(config, current["BGP_GLOBALS|default"]["local_asn"], peer, policy); err != nil {
					return err
				}
			}
		}
		return nil
	}
	p.Runtime = func(ctx context.Context, m *SonicAgent) (bool, json.RawMessage, error) {
		raw, err := runRoutingRead(ctx, routingBGPConfig)
		if err != nil {
			return evpnObservation(false, "global EVPN read failed", nil, err)
		}
		view := maps.Clone(db)
		view[evpnGlobalKey] = desired[evpnGlobalKey]
		parsed, err := evpnFRRParse(raw, view)
		if err != nil {
			return evpnObservation(false, err.Error(), nil, nil)
		}
		if parsed.af["advertise-all-vni"] != (s.AdminState == "Up") {
			return evpnObservation(false, "global EVPN advertisement not applied", nil, nil)
		}
		if s.AdminState == "Up" {
			for _, ref := range s.Mappings {
				spec := evpnMapSpec{Tunnel: ref.Tunnel, VLANID: ref.VLANID, VNI: ref.VNI, RouteDistinguisher: ref.RouteDistinguisher, ImportRouteTargets: ref.ImportRouteTargets, ExportRouteTargets: ref.ExportRouteTargets}
				if err := evpnFRRVNI(raw, db["BGP_GLOBALS|default"]["local_asn"], spec, true); err != nil {
					return evpnObservation(false, err.Error(), nil, nil)
				}
				ok, err := evpnMapASIC(ctx, qosRedisRead{m}, ref.Tunnel, db["VXLAN_TUNNEL|"+ref.Tunnel]["src_ip"], ref.VLANID, ref.VNI)
				if err != nil || !ok {
					return evpnObservation(false, "global EVPN mapping hardware not verified", nil, err)
				}
			}
		}
		return evpnObservation(true, "global L2 EVPN advertisement verified", nil, nil)
	}
	return p, nil
}
