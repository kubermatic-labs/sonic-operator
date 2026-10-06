// SPDX-License-Identifier: Apache-2.0

package sonic

import "testing"

func TestEVPNRemoteFDBCorrelation(t *testing.T) {
	r := evpnASICFixture()
	r.db["APPL_DB"] = vlanChangeDB{"VXLAN_FDB_TABLE:Vlan10:02:00:00:00:00:01": {"remote_vtep": "192.0.2.2", "vni": "100", "type": "dynamic"}}
	asic := r.db["ASIC_DB"]
	asic[evpnASICPrefix+"VLAN:oid:0x10"] = map[string]string{"SAI_VLAN_ATTR_VLAN_ID": "10"}
	asic[evpnASICPrefix+`FDB_ENTRY:{"bvid":"oid:0x10","mac":"02:00:00:00:00:01","switch_id":"oid:0x99"}`] = map[string]string{"SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID": "oid:0x11", "SAI_FDB_ENTRY_ATTR_ENDPOINT_IP": "192.0.2.2"}
	asic[evpnASICPrefix+"BRIDGE_PORT:oid:0x11"] = map[string]string{"SAI_BRIDGE_PORT_ATTR_TYPE": "SAI_BRIDGE_PORT_TYPE_TUNNEL", "SAI_BRIDGE_PORT_ATTR_TUNNEL_ID": "oid:0x1"}
	asic["VIDTORID"]["oid:0x10"] = "oid:0xa10"
	asic["VIDTORID"]["oid:0x11"] = "oid:0xa11"
	ok, err := evpnRemoteFDBASIC(t.Context(), r, "vtep1", "192.0.2.1", 10, 100, "02:00:00:00:00:01", "192.0.2.2")
	if err != nil || !ok {
		t.Fatalf("correlated remote FDB: %v %v", ok, err)
	}
	asic[evpnASICPrefix+"BRIDGE_PORT:oid:0x11"]["SAI_BRIDGE_PORT_ATTR_TUNNEL_ID"] = "oid:0xdead"
	if ok, _ := evpnRemoteFDBASIC(t.Context(), r, "vtep1", "192.0.2.1", 10, 100, "02:00:00:00:00:01", "192.0.2.2"); ok {
		t.Fatal("unrelated tunnel accepted")
	}
}
