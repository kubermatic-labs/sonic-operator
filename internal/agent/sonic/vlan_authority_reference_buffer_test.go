// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package sonic

import "testing"

// Exact safe CONFIG_DB excerpt read from a reference switch via read-only
// SSH on 2026-10-05T02:00:02.245554Z. VLAN31's complete membership and member PORT
// hashes are included, together with the Ethernet11 PG7 correction. VLAN100 and
// an unrelated VLAN1000 member exercise preservation across other VLANs.
// The read found no BUFFER_QUEUE, PORT_QOS_MAP, QUEUE, TC_TO_PRIORITY_GROUP_MAP,
// PORTCHANNEL, PORTCHANNEL_MEMBER or INTERFACE rows. See the plan's provenance.
func vlanAuthorityCore001BufferFixture() vlanChangeDB {
	return vlanChangeDB{
		"VLAN|Vlan31":                          {"vlanid": "31"},
		"VLAN_MEMBER|Vlan31|Ethernet11":        {"tagging_mode": "untagged"},
		"VLAN_MEMBER|Vlan31|Ethernet120":       {"tagging_mode": "tagged"},
		"VLAN_MEMBER|Vlan31|Ethernet129":       {"tagging_mode": "tagged"},
		"VLAN_MEMBER|Vlan31|Ethernet8":         {"tagging_mode": "tagged"},
		"VLAN|Vlan100":                         {"vlanid": "100"},
		"VLAN_MEMBER|Vlan100|Ethernet120":      {"tagging_mode": "untagged"},
		"VLAN_MEMBER|Vlan100|Ethernet129":      {"tagging_mode": "untagged"},
		"VLAN|Vlan1000":                        {"vlanid": "1000"},
		"VLAN_MEMBER|Vlan1000|Ethernet0":       {"tagging_mode": "untagged"},
		"PORT|Ethernet0":                       {"admin_status": "up", "alias": "hundredGigE1/1", "dhcp_rate_limit": "300", "index": "1", "lanes": "49,50,51,52", "speed": "100000"},
		"PORT|Ethernet8":                       {"admin_status": "up", "alias": "hundredGigE1/3", "dhcp_rate_limit": "300", "index": "3", "lanes": "57", "speed": "25000", "subport": "1"},
		"PORT|Ethernet11":                      {"admin_status": "up", "alias": "Ethernet11", "index": "3", "lanes": "60", "speed": "25000", "subport": "4"},
		"PORT|Ethernet120":                     {"admin_status": "up", "alias": "hundredGigE1/31", "dhcp_rate_limit": "300", "index": "31", "lanes": "13,14,15,16", "speed": "100000"},
		"PORT|Ethernet129":                     {"admin_status": "up", "alias": "tenGigE1/33", "index": "33", "lanes": "129", "mtu": "9100", "speed": "10000"},
		"BUFFER_PG|Ethernet11|7":               {"profile": "PORT3_INGRESS_PROFILE"},
		"BUFFER_PROFILE|PORT3_INGRESS_PROFILE": {"dynamic_th": "3", "pool": "PORT3_INGRESS_POOL", "size": "0"},
		"BUFFER_POOL|PORT3_INGRESS_POOL":       {"mode": "dynamic", "size": "10875072", "type": "ingress", "xoff": "4194112"},
	}
}

func TestVLANAuthorityCore001BufferCoexistence(t *testing.T) {
	t.Parallel()
	testVLANAuthorityBufferCoexistence(t, vlanAuthorityCore001BufferFixture, 31, "Ethernet11")
}
