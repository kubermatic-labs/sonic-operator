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

// Policy staging remains separate from activation. Only this peer's exact
// disabled AF may be normalized while validating its existing mapping inputs.
//
//nolint:gocyclo // Existing safety-check sequence; split only with dedicated tests.
func planNetworkEVPNPolicyPeer(db vlanChangeDB, r *agent.NetworkRequest, s evpnPeerSpec) (*networkPlan, error) {
	if s.AdminState == "" {
		s.AdminState = "Down"
	}
	if s.AdminState != "Down" && s.AdminState != "Up" {
		return nil, fmt.Errorf("invalid EVPN admin state")
	}
	transit := s.Role == "Transit"
	if transit && (len(s.MappingRefs) != 0 || len(s.Mappings) != 0) {
		return nil, fmt.Errorf("transit peers cannot reference local mappings")
	}
	if !transit && (len(s.MappingRefs) != len(s.Mappings) || len(s.Mappings) == 0) {
		return nil, fmt.Errorf("resolved EVPN mappings required")
	}
	for i, ref := range s.MappingRefs {
		if ref.Name != s.Mappings[i].Name {
			return nil, fmt.Errorf("EVPN reference/snapshot mismatch")
		}
	}
	key := "BGP_NEIGHBOR_AF|default|" + s.Address + "|" + evpnAF
	clean := maps.Clone(db)
	imports, exports := s.ImportRouteTargets, s.ExportRouteTargets
	var err error
	if !transit {
		imports, exports, err = evpnMappingTargets(clean, s.Mappings)
		if err != nil {
			return nil, err
		}
	}
	policy, err := evpnBuildPeerPolicy(r.OwnerID, s.Address, imports, exports)
	if err != nil {
		return nil, err
	}
	desired := maps.Clone(policy.Rows)
	desired[key] = map[string]string{"admin_status": strings.ToLower(s.AdminState), "route_map_in@": policy.In, "route_map_out@": policy.Out, "send_community": "extended"}
	policy.Transit = transit
	if transit {
		desired[key]["unchanged_nexthop"] = "true"
	}
	if err := evpnPolicyExisting(db, desired, key); err != nil {
		return nil, err
	}
	for k := range db {
		if (strings.HasPrefix(k, "ROUTE_MAP|"+policy.In+"|") || strings.HasPrefix(k, "ROUTE_MAP|"+policy.Out+"|")) && desired[k] == nil {
			return nil, fmt.Errorf("extra owned EVPN route-map sequence")
		}
	}
	if err := evpnSafeConfig(clean); err != nil {
		return nil, err
	}
	neighbor := db["BGP_NEIGHBOR|default|"+s.Address]
	if neighbor["asn"] != fmt.Sprint(s.RemoteASN) || neighbor["local_addr"] != s.LocalAddress || (neighbor["admin_status"] != "down" && neighbor["admin_status"] != "up") {
		return nil, fmt.Errorf("matching parent required")
	}
	if !transit && s.AdminState == "Up" && db[evpnGlobalKey]["advertise-all-vni"] != "true" {
		return nil, fmt.Errorf("global advertisement must be staged before AF Up")
	}
	plan := &networkPlan{Identity: "EVPNPeer|default|" + s.Address, Desired: desired}
	plan.Preflight = func(ctx context.Context, m *SonicAgent) error {
		if err := evpnNative(ctx); err != nil {
			return err
		}
		current, _, err := m.vlanChangeSnapshot(ctx)
		if err != nil {
			return err
		}
		if err := evpnPolicyExisting(current, desired, key); err != nil {
			return err
		}
		if err := evpnOwnedPeer(m, current, "BGP_NEIGHBOR|default|"+s.Address); err != nil {
			return err
		}
		if !transit {
			if err := evpnOwnedMappings(m, current, s.Mappings); err != nil {
				return err
			}
		}
		config, err := runRoutingRead(ctx, routingBGPConfig)
		if err != nil {
			return err
		}
		if s.AdminState == "Up" {
			if !transit {
				if err := evpnOwnedGlobal(m, current, s.Mappings); err != nil {
					return err
				}
				if err := evpnMappingActivationReady(ctx, m, current, config, s.Mappings); err != nil {
					return err
				}
			}
			if err := evpnVerifyPeerPolicy(config, current["BGP_GLOBALS|default"]["local_asn"], s.Address, policy); err != nil {
				return err
			}
			if current[key]["admin_status"] == "down" && !strings.Contains(string(config), " neighbor "+s.Address+" shutdown\n") {
				return fmt.Errorf("native parent must remain shutdown until EVPN AF is staged Up")
			}
		}
		if !networkSubset(current, desired) && current[key]["admin_status"] == "up" && s.AdminState == "Up" {
			return fmt.Errorf("disable EVPN AF before policy changes")
		}
		if !networkSubset(current, policy.Rows) && !strings.Contains(string(config), " neighbor "+s.Address+" shutdown\n") {
			return fmt.Errorf("native parent must be shutdown before policy staging")
		}
		return evpnUnderlay(ctx, current, s.LocalAddress, s.Address)
	}
	plan.Runtime = func(ctx context.Context, m *SonicAgent) (bool, json.RawMessage, error) {
		config, err := runRoutingRead(ctx, routingBGPConfig)
		if err != nil {
			return evpnObservation(false, "EVPN policy read failed", nil, err)
		}
		if err := evpnVerifyPeerPolicy(config, db["BGP_GLOBALS|default"]["local_asn"], s.Address, policy); err != nil {
			return evpnObservation(false, err.Error(), nil, nil)
		}
		view := maps.Clone(db)
		view[key] = desired[key]
		parsed, err := evpnFRRParse(config, view)
		if err != nil {
			return evpnObservation(false, err.Error(), nil, nil)
		}
		active := parsed.af["neighbor "+s.Address+" activate"]
		if active != (s.AdminState == "Up") {
			return evpnObservation(false, "EVPN AF not applied", nil, nil)
		}
		if s.AdminState == "Up" {
			return evpnPeerEstablished(ctx, s)
		}
		return evpnObservation(true, "EVPN filters attached; AF disabled", nil, nil)
	}
	return plan, nil
}

func evpnPolicyExisting(db, desired vlanChangeDB, afKey string) error {
	copy := maps.Clone(db)
	if row := db[afKey]; row != nil {
		copy[afKey] = maps.Clone(row)
		if row["admin_status"] != "up" && row["admin_status"] != "down" {
			return fmt.Errorf("invalid existing EVPN admin state")
		}
		copy[afKey]["admin_status"] = desired[afKey]["admin_status"]
	}
	return evpnExactExisting(copy, desired)
}
