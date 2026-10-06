// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

func traditionalDesired(s routingBGPSpec) vlanChangeDB {
	return vlanChangeDB{"DEVICE_METADATA|localhost": {"bgp_asn": strconv.FormatUint(uint64(s.LocalASN), 10), "type": "LeafRouter"}}
}

func traditionalInputs(db vlanChangeDB, s routingBGPSpec) error {
	if s.VRF != "default" || len(s.Prefixes) != 1 || s.Prefixes[0] != s.RouterID+"/32" {
		return fmt.Errorf("traditional BGP requires default VRF and the router-ID /32")
	}
	meta := db["DEVICE_METADATA|localhost"]
	if meta == nil || meta["frr_mgmt_framework_config"] != "" && meta["frr_mgmt_framework_config"] != "false" || meta["docker_routing_config_mode"] != "" && meta["docker_routing_config_mode"] != "separated" {
		return fmt.Errorf("native separated traditional startup required; mode changes are unsupported")
	}
	for _, field := range []string{"bgp_router_id", "sub_role", "subtype", "switch_type", "bgp_adv_lo_prefix_as_128", "nexthop_group"} {
		if _, exists := meta[field]; exists {
			return fmt.Errorf("unsupported traditional metadata source selector")
		}
	}
	loopback := "LOOPBACK_INTERFACE|Loopback0"
	if db[loopback] == nil || db[loopback+"|"+s.Prefixes[0]] == nil || db[loopback]["vrf_name"] != "" || db[loopback]["vnet_name"] != "" {
		return fmt.Errorf("traditional BGP requires the declared default-VRF Loopback0 /32")
	}
	for key, fields := range db {
		if key == "BGP_DEVICE_GLOBAL|STATE" {
			if !reflect.DeepEqual(fields, map[string]string{"idf_isolation_state": "unisolated", "tsa_enabled": "false", "wcmp_enabled": "false"}) {
				return fmt.Errorf("unsupported traditional global routing policy")
			}
			continue
		}
		if key == loopback || key == loopback+"|"+s.Prefixes[0] {
			continue
		}
		table, _, _ := strings.Cut(key, "|")
		for _, prefix := range []string{"BGP", "BFD", "OSPF", "ISIS", "PIM", "STATIC_ROUTE", "ROUTE", "PREFIX", "AS_PATH", "COMMUNITY", "EXTENDED_COMMUNITY", "VNET", "VRF", "VXLAN", "EVPN", "LOOPBACK_INTERFACE", "VLAN_INTERFACE", "PORTCHANNEL_INTERFACE", "INTERFACE"} {
			if strings.HasPrefix(table, prefix) {
				return fmt.Errorf("traditional peerless backend conflicts with existing routing inputs")
			}
		}
	}
	return nil
}

func planTraditionalBGP(db vlanChangeDB, s routingBGPSpec) (*networkPlan, error) {
	if err := traditionalInputs(db, s); err != nil {
		return nil, err
	}
	desired := traditionalDesired(s)
	return &networkPlan{Identity: "BGP|default", Desired: desired,
		Runtime: func(ctx context.Context, m *SonicAgent) (bool, json.RawMessage, error) {
			return traditionalRuntime(ctx, m, s)
		},
		Persisted: func(ctx context.Context, _ *SonicAgent) (bool, error) { return traditionalPersistence(ctx, s) },
		Preflight: func(ctx context.Context, m *SonicAgent) error {
			if err := traditionalQualified(ctx); err != nil {
				return err
			}
			if err := traditionalPreservation(ctx, s); err != nil {
				return err
			}
			if err := traditionalRequireLoopbackState(ctx, m, s); err != nil {
				return err
			}
			// Reject unmanaged peer/policy before a service restart can erase it.
			_, _, err := traditionalRuntime(ctx, m, s)
			return err
		},
		Activate: func(ctx context.Context, m *SonicAgent) error {
			// Re-read immediately after durable dispatch and before mutation.
			if err := traditionalQualified(ctx); err != nil {
				return err
			}
			if err := traditionalPreservation(ctx, s); err != nil {
				return err
			}
			if err := traditionalRequireLoopbackState(ctx, m, s); err != nil {
				return err
			}
			_, err := runFRRMigration(ctx, frrMigrationRestart)
			return err
		},
	}, nil
}

func traditionalPlan(p *networkPlan) bool {
	return p != nil && p.Identity == "BGP|default" && len(p.Desired) == 1 && p.Desired["DEVICE_METADATA|localhost"] != nil
}

func traditionalOwnership(db vlanChangeDB, p *networkPlan, r *networkRecord) error {
	if r == nil {
		if !networkSubset(db, p.Desired) {
			return fmt.Errorf("traditional BGP adoption requires matching existing native metadata")
		}
	} else if !reflect.DeepEqual(r.Fields, p.Desired) {
		return fmt.Errorf("adopted traditional metadata is immutable; only recorded-value repair is supported")
	}
	return nil
}
