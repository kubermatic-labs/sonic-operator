// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Correlate a learned remote MAC through its VLAN bridge port and VTEP. This is
// programmed-state evidence; only endpoint packet capture proves delivery.
func evpnRemoteFDBASIC(ctx context.Context, read qosRead, tunnel, source string, vlan, vni uint32, mac, remote string) (bool, error) {
	address, err := net.ParseMAC(mac)
	if err != nil || len(address) != 6 {
		return false, fmt.Errorf("invalid remote MAC")
	}
	ip, err := routingAddress(remote, nil)
	if err != nil || !ip.Is4() {
		return false, fmt.Errorf("invalid remote VTEP")
	}
	mac = address.String()
	app, err := read.hash(ctx, "APPL_DB", fmt.Sprintf("VXLAN_FDB_TABLE:Vlan%d:%s", vlan, mac))
	if err != nil {
		return false, err
	}
	if app["remote_vtep"] != remote || app["vni"] != fmt.Sprint(vni) {
		return false, nil
	}
	ok, err := evpnMapASIC(ctx, read, tunnel, source, vlan, vni)
	if err != nil || !ok {
		return false, err
	}
	local, localAttrs, err := evpnTunnelASIC(ctx, read, tunnel, source)
	if err != nil || local == "" {
		return false, err
	}
	keys, err := read.keys(ctx, "ASIC_DB", evpnASICPrefix+"FDB_ENTRY:*")
	if err != nil {
		return false, err
	}
	for _, key := range keys {
		var identity struct {
			BVID   string `json:"bvid"`
			MAC    string `json:"mac"`
			Switch string `json:"switch_id"`
		}
		if json.Unmarshal([]byte(strings.TrimPrefix(key, evpnASICPrefix+"FDB_ENTRY:")), &identity) != nil || !strings.EqualFold(identity.MAC, mac) {
			continue
		}
		row, err := read.hash(ctx, "ASIC_DB", evpnASICPrefix+"VLAN:"+identity.BVID)
		if err != nil {
			return false, err
		}
		if row["SAI_VLAN_ATTR_VLAN_ID"] != strconv.FormatUint(uint64(vlan), 10) {
			continue
		}
		if ok, err := qosTranslated(ctx, read, identity.BVID); err != nil || !ok {
			return false, err
		}
		fdb, err := read.hash(ctx, "ASIC_DB", key)
		if err != nil {
			return false, err
		}
		bridge := fdb["SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID"]
		if ok, err := qosTranslated(ctx, read, bridge); err != nil || !ok {
			return false, err
		}
		port, err := read.hash(ctx, "ASIC_DB", evpnASICPrefix+"BRIDGE_PORT:"+bridge)
		if err != nil {
			return false, err
		}
		if port["SAI_BRIDGE_PORT_ATTR_TYPE"] != "SAI_BRIDGE_PORT_TYPE_TUNNEL" {
			return false, nil
		}
		tid := port["SAI_BRIDGE_PORT_ATTR_TUNNEL_ID"]
		if tid == local {
			return fdb["SAI_FDB_ENTRY_ATTR_ENDPOINT_IP"] == remote, nil
		}
		// P2P implementations use a dynamic destination tunnel derived from
		// this source VTEP. Match its shared mapper/underlay and actual DIP.
		if ok, err := qosTranslated(ctx, read, tid); err != nil || !ok {
			return false, err
		}
		attrs, err := read.hash(ctx, "ASIC_DB", evpnASICPrefix+"TUNNEL:"+tid)
		if err != nil {
			return false, err
		}
		return attrs["SAI_TUNNEL_ATTR_TYPE"] == "SAI_TUNNEL_TYPE_VXLAN" && attrs["SAI_TUNNEL_ATTR_ENCAP_SRC_IP"] == source && attrs["SAI_TUNNEL_ATTR_ENCAP_DST_IP"] == remote && attrs["SAI_TUNNEL_ATTR_UNDERLAY_INTERFACE"] == localAttrs["SAI_TUNNEL_ATTR_UNDERLAY_INTERFACE"] && attrs["SAI_TUNNEL_ATTR_DECAP_MAPPERS"] == localAttrs["SAI_TUNNEL_ATTR_DECAP_MAPPERS"], nil
	}
	return false, nil
}

func evpnForwardingObservation(ctx context.Context, m *SonicAgent, refs []evpnMapSpec) (map[string]any, error) {
	read := qosRedisRead{m}
	entries := []map[string]any{}
	imet := []map[string]any{}
	for _, ref := range refs {
		keys, err := read.keys(ctx, "APPL_DB", fmt.Sprintf("VXLAN_FDB_TABLE:Vlan%d:*", ref.VLANID))
		if err != nil {
			return nil, err
		}
		if len(keys) > 256 {
			return nil, fmt.Errorf("EVPN FDB observation exceeds bounded sample")
		}
		db, _, err := m.vlanChangeSnapshot(ctx)
		if err != nil {
			return nil, err
		}
		for _, key := range keys {
			row, err := read.hash(ctx, "APPL_DB", key)
			if err != nil {
				return nil, err
			}
			mac := strings.TrimPrefix(key, fmt.Sprintf("VXLAN_FDB_TABLE:Vlan%d:", ref.VLANID))
			ok, err := evpnRemoteFDBASIC(ctx, read, ref.Tunnel, db["VXLAN_TUNNEL|"+ref.Tunnel]["src_ip"], ref.VLANID, ref.VNI, mac, row["remote_vtep"])
			if err != nil {
				return nil, err
			}
			entries = append(entries, map[string]any{"mac": mac, "vlanID": ref.VLANID, "vni": ref.VNI, "remoteVTEP": row["remote_vtep"], "hardwareCorrelated": ok})
		}
		keys, err = read.keys(ctx, "APPL_DB", fmt.Sprintf("VXLAN_REMOTE_VNI_TABLE:Vlan%d:*", ref.VLANID))
		if err != nil {
			return nil, err
		}
		if len(keys) > 256 {
			return nil, fmt.Errorf("EVPN replication observation exceeds bounded sample")
		}
		for _, key := range keys {
			row, err := read.hash(ctx, "APPL_DB", key)
			if err != nil {
				return nil, err
			}
			if row["vni"] == fmt.Sprint(ref.VNI) {
				imet = append(imet, map[string]any{"vni": ref.VNI, "remoteVTEP": strings.TrimPrefix(key, fmt.Sprintf("VXLAN_REMOTE_VNI_TABLE:Vlan%d:", ref.VLANID)), "source": "APPL_DB"})
			}
		}
	}
	return map[string]any{"remoteFDB": entries, "replication": imet, "forwardingTested": false}, nil
}
