// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"slices"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
	"k8s.io/apimachinery/pkg/util/validation"
)

func evpnMappingTargets(db vlanChangeDB, refs []agent.EVPNMappingSnapshot) ([]string, []string, error) {
	if len(refs) == 0 || len(refs) > 64 {
		return nil, nil, fmt.Errorf("EVPN policy requires 1..64 mapping snapshots")
	}
	names, uids, vnis, vlans := map[string]bool{}, map[string]bool{}, map[uint32]bool{}, map[uint32]bool{}
	imports, exports := map[string]bool{}, map[string]bool{}
	tunnel := refs[0].Tunnel
	for _, ref := range refs {
		if len(validation.IsDNS1123Subdomain(ref.Name)) != 0 || ref.UID == "" || len(ref.UID) > 256 || ref.Generation < 1 || names[ref.Name] || uids[ref.UID] || vnis[ref.VNI] || vlans[ref.VLANID] || ref.Tunnel != tunnel {
			return nil, nil, fmt.Errorf("invalid, duplicate or cross-tunnel EVPN mapping snapshot")
		}
		names[ref.Name], uids[ref.UID], vnis[ref.VNI], vlans[ref.VLANID] = true, true, true, true
		spec := evpnMapSpec{Tunnel: ref.Tunnel, VLANID: ref.VLANID, VNI: ref.VNI, RouteDistinguisher: ref.RouteDistinguisher, ImportRouteTargets: ref.ImportRouteTargets, ExportRouteTargets: ref.ExportRouteTargets}
		raw, err := json.Marshal(spec)
		if err != nil {
			return nil, nil, err
		}
		plan, err := planNetworkVLANVNI(db, &agent.NetworkRequest{Kind: "VLANVNI", OwnerID: ref.UID, Spec: raw})
		if err != nil {
			return nil, nil, err
		}
		if !networkSubset(db, plan.Desired) {
			return nil, nil, fmt.Errorf("referenced EVPN mapping differs from snapshot")
		}
		for _, rt := range ref.ImportRouteTargets {
			imports[rt] = true
		}
		for _, rt := range ref.ExportRouteTargets {
			exports[rt] = true
		}
	}
	list := func(set map[string]bool) []string {
		out := make([]string, 0, len(set))
		for value := range set {
			out = append(out, value)
		}
		slices.Sort(out)
		return out
	}
	return list(imports), list(exports), nil
}

// Caller holds the shared network lock. A matching CONFIG_DB mapping without
// the reference UID's completed journal record cannot authorize advertisement.
func evpnOwnedMappings(m *SonicAgent, db vlanChangeDB, refs []agent.EVPNMappingSnapshot) error {
	if _, _, err := evpnMappingTargets(db, refs); err != nil {
		return err
	}
	root, err := os.OpenRoot(m.networkJournalDir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	state, err := loadNetworkJournal(&vlanAuthorityJournal{root: root})
	if err != nil {
		return err
	}
	for _, ref := range refs {
		spec := evpnMapSpec{Tunnel: ref.Tunnel, VLANID: ref.VLANID, VNI: ref.VNI, RouteDistinguisher: ref.RouteDistinguisher, ImportRouteTargets: ref.ImportRouteTargets, ExportRouteTargets: ref.ExportRouteTargets}
		raw, err := json.Marshal(spec)
		if err != nil {
			return err
		}
		plan, err := planNetworkVLANVNI(db, &agent.NetworkRequest{Kind: "VLANVNI", OwnerID: ref.UID, Spec: raw})
		if err != nil {
			return err
		}
		record := state.Records[plan.Identity]
		if record == nil || record.Kind != "VLANVNI" || record.OwnerID != ref.UID || record.Pending != nil || !reflect.DeepEqual(record.Fields, plan.Desired) || !networkSubset(db, record.Fields) || record.Fingerprint != vlanAuthorityHash(db) {
			return fmt.Errorf("EVPN mapping requires matching durable reference ownership and persistence")
		}
	}
	return nil
}
