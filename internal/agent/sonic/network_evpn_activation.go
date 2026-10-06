// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"fmt"
	"os"
	"reflect"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

func evpnParentActivation(ctx context.Context, m *SonicAgent, db vlanChangeDB, peer string) error {
	if err := evpnOwnedPolicy(m, db, peer); err != nil {
		return err
	}
	policy, err := evpnConfiguredPeerPolicy(db, peer)
	if err != nil {
		return err
	}
	if db["BGP_NEIGHBOR_AF|default|"+peer+"|"+evpnAF]["admin_status"] != "up" {
		return fmt.Errorf("EVPN AF must be applied Up before parent activation")
	}
	root, err := os.OpenRoot(m.networkJournalDir)
	if err != nil {
		return err
	}
	state, err := loadNetworkJournal(&vlanAuthorityJournal{root: root})
	root.Close()
	if err != nil {
		return err
	}
	r := state.Records["EVPNPeer|default|"+peer]
	if r == nil || r.Kind != "EVPNPeer" || r.OwnerID == "" || r.Pending != nil || !networkSubset(db, r.Fields) || r.Fields["BGP_NEIGHBOR_AF|default|"+peer+"|"+evpnAF]["admin_status"] != "up" {
		return fmt.Errorf("EVPN AF must have durable policy ownership")
	}
	if !policy.Transit {
		if err := evpnOwnedGlobal(m, db, nil); err != nil {
			return err
		}
	}
	raw, err := runRoutingRead(ctx, routingBGPConfig)
	if err != nil {
		return err
	}
	if !policy.Transit {
		global := state.Records["EVPN|default"]
		if global == nil {
			return fmt.Errorf("global EVPN declaration unavailable")
		}
		if err := evpnMappingActivationReady(ctx, m, db, raw, global.EVPNMappings); err != nil {
			return err
		}
	}
	if err := evpnVerifyPeerPolicy(raw, db["BGP_GLOBALS|default"]["local_asn"], peer, policy); err != nil {
		return err
	}
	parsed, err := evpnFRRParse(raw, db)
	if err != nil {
		return err
	}
	if !parsed.af["neighbor "+peer+" activate"] || (!policy.Transit && !parsed.af["advertise-all-vni"]) {
		return fmt.Errorf("EVPN AF/global advertisement not applied")
	}
	return nil
}

func evpnOwnedGlobal(m *SonicAgent, db vlanChangeDB, mappings []agent.EVPNMappingSnapshot) error {
	root, err := os.OpenRoot(m.networkJournalDir)
	if err != nil {
		return err
	}
	defer root.Close()
	state, err := loadNetworkJournal(&vlanAuthorityJournal{root: root})
	if err != nil {
		return err
	}
	r := state.Records["EVPN|default"]
	if r == nil || r.Kind != "EVPN" || r.OwnerID == "" || r.Pending != nil || !reflect.DeepEqual(r.Fields, vlanChangeDB{evpnGlobalKey: evpnGlobalFields(true)}) || !networkSubset(db, r.Fields) {
		return fmt.Errorf("global EVPN must be durably configured Up")
	}
	if len(r.EVPNMappings) == 0 {
		return fmt.Errorf("global EVPN mapping declaration unavailable")
	}
	if err := evpnOwnedMappings(m, db, r.EVPNMappings); err != nil {
		return err
	}
	if err := evpnInitializationMappings(db, r.EVPNMappings); err != nil {
		return err
	}
	for _, ref := range mappings {
		key := fmt.Sprintf("VXLAN_TUNNEL_MAP|%s|map_%d_Vlan%d", ref.Tunnel, ref.VNI, ref.VLANID)
		if db[key]["vni"] != fmt.Sprint(ref.VNI) {
			return fmt.Errorf("EVPN global mapping dependency changed")
		}
	}
	return nil
}

func evpnOwnedPolicy(m *SonicAgent, db vlanChangeDB, peer string) error {
	policy, err := evpnConfiguredPeerPolicy(db, peer)
	if err != nil {
		return err
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
	r := state.Records["EVPNPeer|default|"+peer]
	if r == nil || r.Kind != "EVPNPeer" || r.OwnerID == "" || r.Pending != nil || !networkSubset(db, r.Fields) {
		return fmt.Errorf("EVPN policy requires completed durable peer ownership")
	}
	expected, err := evpnBuildPeerPolicy(r.OwnerID, peer, policy.Import, policy.Export)
	if err != nil {
		return err
	}
	if expected.In != policy.In || expected.Out != policy.Out {
		return fmt.Errorf("EVPN policy name does not match durable owner")
	}
	for key, fields := range expected.Rows {
		if !reflect.DeepEqual(r.Fields[key], fields) {
			return fmt.Errorf("EVPN filter is not durably recorded")
		}
	}
	af := "BGP_NEIGHBOR_AF|default|" + peer + "|" + evpnAF
	if !reflect.DeepEqual(r.Fields[af], db[af]) {
		return fmt.Errorf("EVPN attachment is not durably recorded")
	}
	return nil
}
