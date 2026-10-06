// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"reflect"
	"strings"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

// Validate declared mapping intent even before native objects exist. Build a
// private prospective view for grammar/collision checks, never for readiness.
func evpnInitializationMappings(db vlanChangeDB, refs []agent.EVPNMappingSnapshot) error {
	view := maps.Clone(db)
	delete(view, evpnGlobalKey)
	wanted := vlanChangeDB{}
	for _, ref := range refs {
		spec := evpnMapSpec{Tunnel: ref.Tunnel, VLANID: ref.VLANID, VNI: ref.VNI, RouteDistinguisher: ref.RouteDistinguisher, ImportRouteTargets: ref.ImportRouteTargets, ExportRouteTargets: ref.ExportRouteTargets}
		raw, err := json.Marshal(spec)
		if err != nil {
			return err
		}
		plan, err := planNetworkVLANVNI(view, &agent.NetworkRequest{Kind: "VLANVNI", OwnerID: ref.UID, Spec: raw})
		if err != nil {
			return err
		}
		for key, row := range plan.Desired {
			view[key] = maps.Clone(row)
			wanted[key] = row
		}
	}
	if _, _, err := evpnMappingTargets(view, refs); err != nil {
		return err
	}
	for key, row := range db {
		if strings.HasPrefix(key, "VXLAN_TUNNEL_MAP|") || strings.HasPrefix(key, "BGP_GLOBALS_EVPN_") {
			if wanted[key] == nil || !maps.Equal(row, wanted[key]) {
				return fmt.Errorf("undeclared or conflicting local EVPN mapping")
			}
		}
	}
	return nil
}

// Local advertise-all-vni initialization is safe only with CONFIG and actual
// FRR shutdown, including native-only neighbors. It never authorizes a session.
func evpnInitializationShutdown(config []byte, db vlanChangeDB) error {
	view := maps.Clone(db)
	for _, line := range strings.Split(string(config), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "router bgp ") && line != "router bgp "+db["BGP_GLOBALS|default"]["local_asn"] && line != "router bgp "+db["BGP_GLOBALS|default"]["local_asn"]+" vrf default" {
			return fmt.Errorf("other native BGP instance blocks EVPN initialization")
		}
	}
	for key, row := range db {
		if strings.HasPrefix(key, "BGP_NEIGHBOR|") && row["admin_status"] != "down" {
			return fmt.Errorf("EVPN initialization requires every neighbor shutdown")
		}
		if strings.HasPrefix(key, "BGP_NEIGHBOR_AF|") && strings.HasSuffix(key, "|"+evpnAF) && row["admin_status"] != "down" {
			return fmt.Errorf("EVPN initialization requires every EVPN AF disabled")
		}
	}
	// The strict parser rejects native-only live neighbors and conflicting AFs.
	parsed, err := evpnFRRParse(config, view)
	if err != nil {
		return err
	}
	for vni, lines := range parsed.vnis {
		key := "BGP_GLOBALS_EVPN_VNI|default|" + evpnAF + "|" + vni
		if db[key] == nil {
			return fmt.Errorf("unconfigured native VNI blocks EVPN initialization")
		}
		for _, line := range lines {
			if strings.HasPrefix(line, "rd ") && line != "rd "+db[key]["route-distinguisher"] {
				return fmt.Errorf("native VNI RD conflicts with initialization")
			}
			if strings.HasPrefix(line, "route-target ") {
				f := strings.Fields(line)
				if len(f) != 3 {
					return fmt.Errorf("invalid native VNI RT")
				}
				want := db["BGP_GLOBALS_EVPN_VNI_RT|default|"+evpnAF+"|"+vni+"|"+f[2]]["route-target-type"]
				if want != f[1] && !(want == "both" && (f[1] == "import" || f[1] == "export")) {
					return fmt.Errorf("native VNI RT conflicts with initialization")
				}
			}
		}
	}
	for line := range parsed.global {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == "neighbor" && !parsed.global["neighbor "+f[1]+" shutdown"] {
			return fmt.Errorf("native neighbor not shutdown during EVPN initialization")
		}
		if len(f) >= 4 && f[0] == "no" && f[1] == "neighbor" && f[3] == "shutdown" {
			return fmt.Errorf("native neighbor enabled during EVPN initialization")
		}
	}
	return nil
}

// Mapping creation after local initialization requires the global owner's
// recorded allowlist and every session shutdown. This is read-only, under the
// engine's existing network lock. No RPC-provided flag bypasses this check.
func evpnInitializedMappingPreflight(ctx context.Context, m *SonicAgent, r *agent.NetworkRequest, s evpnMapSpec, desired vlanChangeDB) error {
	db, _, err := m.vlanChangeSnapshot(ctx)
	if err != nil {
		return err
	}
	if db[evpnGlobalKey]["advertise-all-vni"] != "true" || networkSubset(db, desired) {
		return nil
	}
	root, err := os.OpenRoot(m.networkJournalDir)
	if err != nil {
		return err
	}
	defer root.Close()
	state, err := loadNetworkJournal(&vlanAuthorityJournal{root: root})
	if err != nil {
		return err
	}
	global := state.Records["EVPN|default"]
	if global == nil || global.Kind != "EVPN" || global.Pending != nil || !reflect.DeepEqual(global.Fields, vlanChangeDB{evpnGlobalKey: evpnGlobalFields(true)}) || !networkSubset(db, global.Fields) {
		return fmt.Errorf("global EVPN initialization must be durably recorded")
	}
	matched := false
	for _, ref := range global.EVPNMappings {
		if ref.UID != r.OwnerID || ref.Tunnel != s.Tunnel || ref.VLANID != s.VLANID || ref.VNI != s.VNI || ref.RouteDistinguisher != s.RouteDistinguisher {
			continue
		}
		imports, err := evpnRTs(ref.ImportRouteTargets)
		if err != nil {
			return err
		}
		exports, err := evpnRTs(ref.ExportRouteTargets)
		if err != nil {
			return err
		}
		matched = reflect.DeepEqual(imports, s.ImportRouteTargets) && reflect.DeepEqual(exports, s.ExportRouteTargets)
	}
	if !matched {
		return fmt.Errorf("mapping is outside the initialized EVPN owner's declared set")
	}
	config, err := runRoutingRead(ctx, routingBGPConfig)
	if err != nil {
		return err
	}
	return evpnInitializationShutdown(config, db)
}

func evpnMappingActivationReady(ctx context.Context, m *SonicAgent, db vlanChangeDB, config []byte, refs []agent.EVPNMappingSnapshot) error {
	if err := evpnOwnedMappings(m, db, refs); err != nil {
		return err
	}
	for _, ref := range refs {
		spec := evpnMapSpec{Tunnel: ref.Tunnel, VLANID: ref.VLANID, VNI: ref.VNI, RouteDistinguisher: ref.RouteDistinguisher, ImportRouteTargets: ref.ImportRouteTargets, ExportRouteTargets: ref.ExportRouteTargets}
		if err := evpnFRRVNI(config, db["BGP_GLOBALS|default"]["local_asn"], spec, true); err != nil {
			return err
		}
		ok, err := evpnMapASIC(ctx, qosRedisRead{m}, ref.Tunnel, db["VXLAN_TUNNEL|"+ref.Tunnel]["src_ip"], ref.VLANID, ref.VNI)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("EVPN mapping hardware must be applied before session activation")
		}
	}
	return nil
}
