// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"strconv"
	"strings"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

type evpnCoexistVerifiedKey struct{}

// Validate the *complete* staged L2 contract before allowing the unicast owner
// to coexist with EVPN. Merely skipping BGP_GLOBALS_EVPN_VNI would permit inert
// or unsafe foreign fields, missing RTs, orphan RTs, and active AFs. Reuse the
// mapping planner's dependency/uniqueness validation without claiming its fields.
func evpnIsolatedConfig(db vlanChangeDB) (bool, []evpnMapSpec, error) {
	present := false
	for key := range db {
		if strings.HasPrefix(key, "BGP_GLOBALS_EVPN_") || strings.HasPrefix(key, "VXLAN_TUNNEL_MAP|") ||
			((strings.HasPrefix(key, "BGP_NEIGHBOR_AF|") || strings.HasPrefix(key, "BGP_GLOBALS_AF|")) && strings.HasSuffix(strings.ToLower(key), "|"+evpnAF)) {
			present = true
		}
	}
	if !present {
		return false, nil, nil
	}
	if err := evpnSafeConfig(db); err != nil {
		return true, nil, err
	}
	expected := vlanChangeDB{}
	var specs []evpnMapSpec
	for key, row := range db {
		if !strings.HasPrefix(key, "VXLAN_TUNNEL_MAP|") {
			continue
		}
		parts := strings.Split(key, "|")
		if len(parts) != 3 {
			return true, nil, fmt.Errorf("invalid staged VXLAN mapping identity")
		}
		vlan, e1 := strconv.ParseUint(strings.TrimPrefix(row["vlan"], "Vlan"), 10, 32)
		vni, e2 := strconv.ParseUint(row["vni"], 10, 32)
		if e1 != nil || e2 != nil || row["vlan"] != fmt.Sprintf("Vlan%d", vlan) || row["vni"] != strconv.FormatUint(vni, 10) {
			return true, nil, fmt.Errorf("noncanonical staged VLAN/VNI")
		}
		s := evpnMapSpec{Tunnel: parts[1], VLANID: uint32(vlan), VNI: uint32(vni)}
		vniKey := "BGP_GLOBALS_EVPN_VNI|default|" + evpnAF + "|" + row["vni"]
		s.RouteDistinguisher = db[vniKey]["route-distinguisher"]
		rtPrefix := "BGP_GLOBALS_EVPN_VNI_RT|default|" + evpnAF + "|" + row["vni"] + "|"
		for rtKey, rtRow := range db {
			if !strings.HasPrefix(rtKey, rtPrefix) {
				continue
			}
			rt := strings.TrimPrefix(rtKey, rtPrefix)
			switch rtRow["route-target-type"] {
			case "import":
				s.ImportRouteTargets = append(s.ImportRouteTargets, rt)
			case "export":
				s.ExportRouteTargets = append(s.ExportRouteTargets, rt)
			case "both":
				s.ImportRouteTargets = append(s.ImportRouteTargets, rt)
				s.ExportRouteTargets = append(s.ExportRouteTargets, rt)
			default:
				return true, nil, fmt.Errorf("unsupported staged route-target type")
			}
		}
		raw, err := json.Marshal(s)
		if err != nil {
			return true, nil, err
		}
		p, err := planNetworkVLANVNI(db, &agent.NetworkRequest{Kind: "VLANVNI", Spec: raw})
		if err != nil {
			return true, nil, fmt.Errorf("isolated staged VNI required: %w", err)
		}
		if p.Desired[key] == nil || !networkSubset(db, p.Desired) {
			return true, nil, fmt.Errorf("incomplete or noncanonical staged VNI mapping")
		}
		maps.Copy(expected, p.Desired)
		specs = append(specs, s)
	}
	for key, row := range db {
		if strings.HasPrefix(key, "BGP_GLOBALS_EVPN_") || strings.HasPrefix(key, "VXLAN_TUNNEL_MAP|") {
			if !maps.Equal(row, expected[key]) || expected[key] == nil {
				return true, nil, fmt.Errorf("unsupported, orphaned or incomplete staged EVPN row")
			}
		}
		if strings.HasPrefix(key, "BGP_NEIGHBOR_AF|") && strings.HasSuffix(strings.ToLower(key), "|"+evpnAF) {
			parts := strings.Split(key, "|")
			if len(parts) == 4 && parts[1] == "default" && row["route_map_in@"] != "" {
				if _, err := evpnConfiguredPeerPolicy(db, parts[2]); err != nil {
					return true, nil, err
				}
				continue
			}
			if len(parts) != 4 || parts[1] != "default" || parts[3] != evpnAF || !maps.Equal(row, map[string]string{"admin_status": "down"}) {
				return true, nil, fmt.Errorf("only exact disabled default-VRF EVPN neighbor AF can coexist")
			}
			address, err := routingAddress(parts[2], nil)
			neighbor := db["BGP_NEIGHBOR|default|"+parts[2]]
			if err != nil || address.String() != parts[2] || neighbor["admin_status"] != "down" || neighbor["peer_group_name"] != "" || neighbor["peer_group"] != "" {
				return true, nil, fmt.Errorf("disabled EVPN AF requires an existing shutdown non-inherited neighbor")
			}
			asn, err := strconv.ParseUint(neighbor["asn"], 10, 32)
			v4 := address.Is4()
			local, localErr := routingAddress(neighbor["local_addr"], &v4)
			if err != nil || asn == 0 || localErr != nil || local == address {
				return true, nil, fmt.Errorf("disabled EVPN AF requires valid neighbor ASN and distinct local source")
			}
			if _, err := evpnLocalInterface(db, local); err != nil {
				return true, nil, err
			}
		}
	}
	return true, specs, nil
}

// The BGP owner validates runtime EVPN isolation but never includes EVPN fields
// in Desired or ownership. Every runtime VNI must match an exact configured L2
// mapping, and every configured VNI must be applied before runtime is verified.
func evpnCoexistRuntime(ctx context.Context, run routingRead, db vlanChangeDB) error {
	present, specs, err := evpnIsolatedConfig(db)
	if err != nil {
		return err
	}
	config, err := run(ctx, routingBGPConfig)
	if err != nil {
		return err
	}
	if !present && !strings.Contains(string(config), "address-family l2vpn evpn") {
		return nil
	}
	r, err := evpnFRRParse(config, db)
	if err != nil {
		return err
	}
	if len(r.vnis) != len(specs) {
		return fmt.Errorf("runtime EVPN VNIs differ from isolated configured mappings")
	}
	for _, s := range specs {
		if err := evpnFRRVNI(config, db["BGP_GLOBALS|default"]["local_asn"], s, true); err != nil {
			return err
		}
	}
	for line := range r.af {
		if evpnOperationalAFLine(db, line) {
			continue
		}
		parts := strings.Fields(line) // evpnFRRParse only accepts no neighbor IP activate.
		key := "BGP_NEIGHBOR_AF|default|" + parts[2] + "|" + evpnAF
		if db[key]["admin_status"] != "down" {
			return fmt.Errorf("unconfigured runtime EVPN neighbor AF")
		}
	}
	return nil
}

func evpnGuardUnicastPlan(p *networkPlan, db vlanChangeDB) *networkPlan {
	runtime, preflight := p.Runtime, p.Preflight
	p.Runtime = func(ctx context.Context, m *SonicAgent) (bool, json.RawMessage, error) {
		if err := evpnCoexistRuntime(ctx, runRoutingRead, db); err != nil {
			return evpnObservation(false, "BGP/EVPN coexistence not verified: "+err.Error(), nil, err)
		}
		return runtime(context.WithValue(ctx, evpnCoexistVerifiedKey{}, true), m)
	}
	p.Preflight = func(ctx context.Context, m *SonicAgent) error {
		if err := evpnCoexistRuntime(ctx, runRoutingRead, db); err != nil {
			return err
		}
		if preflight != nil {
			return preflight(context.WithValue(ctx, evpnCoexistVerifiedKey{}, true), m)
		}
		return nil
	}
	return p
}
