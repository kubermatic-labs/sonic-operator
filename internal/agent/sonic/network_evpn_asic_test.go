// SPDX-License-Identifier: Apache-2.0

package sonic

import "testing"

func evpnASICFixture() *qosFakeRead {
	return &qosFakeRead{db: map[string]vlanChangeDB{
		"COUNTERS_DB": {"COUNTERS_TUNNEL_NAME_MAP": {"vtep1": "oid:0x1"}},
		"ASIC_DB": {
			"VIDTORID":                                         {"oid:0x1": "oid:0xa1", "oid:0x2": "oid:0xa2", "oid:0x3": "oid:0xa3", "oid:0x4": "oid:0xa4", "oid:0x5": "oid:0xa5"},
			evpnASICPrefix + "TUNNEL:oid:0x1":                  {"SAI_TUNNEL_ATTR_TYPE": "SAI_TUNNEL_TYPE_VXLAN", "SAI_TUNNEL_ATTR_ENCAP_SRC_IP": "192.0.2.1", "SAI_TUNNEL_ATTR_UNDERLAY_INTERFACE": "oid:0x2", "SAI_TUNNEL_ATTR_DECAP_MAPPERS": "1:oid:0x4"},
			evpnASICPrefix + "ROUTER_INTERFACE:oid:0x2":        {"SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID": "oid:0x6"},
			evpnASICPrefix + "TUNNEL_TERM_TABLE_ENTRY:oid:0x3": {"SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_ACTION_TUNNEL_ID": "oid:0x1", "SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TYPE": "SAI_TUNNEL_TERM_TABLE_ENTRY_TYPE_P2MP", "SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TUNNEL_TYPE": "SAI_TUNNEL_TYPE_VXLAN", "SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_DST_IP": "192.0.2.1", "SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_VR_ID": "oid:0x6"},
			evpnASICPrefix + "TUNNEL_MAP:oid:0x4":              {"SAI_TUNNEL_MAP_ATTR_TYPE": "SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID"},
			evpnASICPrefix + "TUNNEL_MAP_ENTRY:oid:0x5":        {"SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP": "oid:0x4", "SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP_TYPE": "SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID", "SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_KEY": "100", "SAI_TUNNEL_MAP_ENTRY_ATTR_VLAN_ID_VALUE": "10"},
		},
	}}
}

func TestEVPNASICCorrelation(t *testing.T) {
	t.Parallel()
	if ok, err := evpnMapASIC(t.Context(), evpnASICFixture(), "vtep1", "192.0.2.1", 10, 100); err != nil || !ok {
		t.Fatalf("correlated mapping: %v %v", ok, err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*qosFakeRead)
	}{
		{"CONFIG_DB alone", func(r *qosFakeRead) { r.db["ASIC_DB"] = vlanChangeDB{} }},
		{"matching content but wrong name", func(r *qosFakeRead) {
			r.db["COUNTERS_DB"]["COUNTERS_TUNNEL_NAME_MAP"] = map[string]string{"other": "oid:0x1"}
		}},
		{"ambiguous name", func(r *qosFakeRead) { r.db["COUNTERS_DB"]["COUNTERS_TUNNEL_NAME_MAP"]["other"] = "oid:0x1" }},
		{"no RID", func(r *qosFakeRead) { delete(r.db["ASIC_DB"]["VIDTORID"], "oid:0x1") }},
		{"wrong source", func(r *qosFakeRead) {
			r.db["ASIC_DB"][evpnASICPrefix+"TUNNEL:oid:0x1"]["SAI_TUNNEL_ATTR_ENCAP_SRC_IP"] = "192.0.2.3"
		}},
		{"term points elsewhere", func(r *qosFakeRead) {
			r.db["ASIC_DB"][evpnASICPrefix+"TUNNEL_TERM_TABLE_ENTRY:oid:0x3"]["SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_ACTION_TUNNEL_ID"] = "oid:0x8"
		}},
		{"wrong term VR", func(r *qosFakeRead) {
			r.db["ASIC_DB"][evpnASICPrefix+"TUNNEL_TERM_TABLE_ENTRY:oid:0x3"]["SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_VR_ID"] = "oid:0x8"
		}},
		{"mapper belongs elsewhere", func(r *qosFakeRead) {
			r.db["ASIC_DB"][evpnASICPrefix+"TUNNEL:oid:0x1"]["SAI_TUNNEL_ATTR_DECAP_MAPPERS"] = "1:oid:0x8"
		}},
		{"wrong VLAN", func(r *qosFakeRead) {
			r.db["ASIC_DB"][evpnASICPrefix+"TUNNEL_MAP_ENTRY:oid:0x5"]["SAI_TUNNEL_MAP_ENTRY_ATTR_VLAN_ID_VALUE"] = "20"
		}},
		{"L3 mapper", func(r *qosFakeRead) {
			r.db["ASIC_DB"][evpnASICPrefix+"TUNNEL_MAP:oid:0x4"]["SAI_TUNNEL_MAP_ATTR_TYPE"] = "SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID"
		}},
		{"map not translated", func(r *qosFakeRead) { delete(r.db["ASIC_DB"]["VIDTORID"], "oid:0x5") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := evpnASICFixture()
			tc.mutate(r)
			if ok, err := evpnMapASIC(t.Context(), r, "vtep1", "192.0.2.1", 10, 100); err != nil || ok {
				t.Fatalf("uncorrelated mapping accepted: %v %v", ok, err)
			}
		})
	}
	r := evpnASICFixture()
	r.errDB = "ASIC_DB"
	if _, err := evpnMapASIC(t.Context(), r, "vtep1", "192.0.2.1", 10, 100); err == nil {
		t.Fatal("read error swallowed")
	}
}
