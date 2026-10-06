// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"testing"
)

// Safe CONFIG_DB excerpt captured read-only from a reference leaf switch.
// No credentials or unrelated switch configuration are copied here.
func vlanAuthorityBufferFixture() vlanChangeDB {
	db := vlanChangeDB{
		"VLAN|Vlan100":                                {"vlanid": "100"},
		"PORT|Ethernet8":                              {"admin_status": "up", "alias": "Ethernet8", "index": "3", "lanes": "57", "speed": "25000", "subport": "1"},
		"PORT|Ethernet9":                              {"admin_status": "up", "alias": "Ethernet9", "dhcp_rate_limit": "300", "index": "3", "lanes": "58", "speed": "25000", "subport": "2"},
		"PORT|Ethernet10":                             {"admin_status": "up", "alias": "Ethernet10", "index": "3", "lanes": "59", "speed": "25000", "subport": "3"},
		"PORT|Ethernet11":                             {"admin_status": "up", "alias": "Ethernet11", "index": "3", "lanes": "60", "speed": "25000", "subport": "4"},
		"PORT|Ethernet120":                            {"admin_status": "up", "alias": "Ethernet120", "dhcp_rate_limit": "300", "index": "31", "lanes": "13,14,15,16", "mtu": "9100", "speed": "100000", "subport": "0"},
		"BUFFER_POOL|egress_lossless_pool":            {"mode": "static", "size": "15982720", "type": "egress"},
		"BUFFER_POOL|egress_lossy_pool":               {"mode": "dynamic", "size": "9243812", "type": "egress"},
		"BUFFER_POOL|ingress_lossless_pool":           {"mode": "dynamic", "size": "10875072", "type": "ingress", "xoff": "4194112"},
		"BUFFER_PROFILE|egress_lossless_profile":      {"pool": "egress_lossless_pool", "size": "1518", "static_th": "15982720"},
		"BUFFER_PROFILE|egress_lossy_profile":         {"pool": "egress_lossy_pool", "size": "1518", "dynamic_th": "3"},
		"BUFFER_PROFILE|ingress_lossy_profile":        {"pool": "ingress_lossless_pool", "size": "0", "dynamic_th": "3"},
		"TC_TO_PRIORITY_GROUP_MAP|PROVISIONING_LOSSY": {"0": "0", "1": "0", "2": "0", "3": "0", "4": "0", "5": "0", "6": "0", "7": "0"},
	}
	for _, port := range []string{"Ethernet8", "Ethernet9", "Ethernet10", "Ethernet11", "Ethernet120"} {
		db["VLAN_MEMBER|Vlan100|"+port] = map[string]string{"tagging_mode": "untagged"}
		db["BUFFER_PG|"+port+"|0"] = map[string]string{"profile": "ingress_lossy_profile"}
		db["BUFFER_QUEUE|"+port+"|0-2"] = map[string]string{"profile": "egress_lossy_profile"}
		db["BUFFER_QUEUE|"+port+"|3-4"] = map[string]string{"profile": "egress_lossless_profile"}
		db["BUFFER_QUEUE|"+port+"|5-6"] = map[string]string{"profile": "egress_lossy_profile"}
		db["PORT_QOS_MAP|"+port] = map[string]string{"tc_to_pg_map": "PROVISIONING_LOSSY"}
	}
	return db
}

func TestVLANAuthorityBufferCoexistence(t *testing.T) {
	t.Parallel()
	testVLANAuthorityBufferCoexistence(t, vlanAuthorityBufferFixture, 100, "Ethernet8")
}

func testVLANAuthorityBufferCoexistence(t *testing.T, fixture func() vlanChangeDB, id uint32, port string) {
	t.Helper()
	memberKey := fmt.Sprintf("VLAN_MEMBER|Vlan%d|%s", id, port)
	for _, name := range []string{"exact adoption", "repair missing member", "retag", "prune", "delete"} {
		t.Run(name, func(t *testing.T) {
			db := fixture()
			after := vlanChangeTarget(db, id)
			switch name {
			case "repair missing member":
				delete(db, memberKey)
			case "retag":
				after[memberKey]["tagging_mode"] = "tagged"
			case "prune":
				delete(after, memberKey)
			case "delete":
				after = vlanChangeDB{}
			}
			original, _ := json.Marshal(db)
			before := vlanChangeTarget(db, id)
			if err := vlanAuthoritySafe(db, id, before); err != nil {
				t.Fatalf("current native state rejected: %v", err)
			}
			if err := vlanAuthoritySafe(db, id, after); err != nil {
				t.Fatalf("desired native state rejected: %v", err)
			}
			post := vlanAuthorityReplaceTarget(db, before, after)
			if !reflect.DeepEqual(vlanChangeTarget(post, id), after) {
				t.Fatal("replacement missed desired target")
			}
			for key, fields := range db {
				if before[key] == nil && !reflect.DeepEqual(post[key], fields) {
					t.Fatalf("unrelated row changed: %s", key)
				}
			}
			unchanged, _ := json.Marshal(db)
			if string(original) != string(unchanged) {
				t.Fatal("validation mutated full snapshot")
			}
		})
	}
}

func vlanAuthorityUnsafeBufferCases() []struct {
	name, key string
	fields    map[string]string
} {
	return []struct {
		name, key string
		fields    map[string]string
	}{
		{"unknown binding field", "BUFFER_PG|Ethernet8|0", map[string]string{"profile": "ingress_lossy_profile", "future": "opaque"}},
		{"missing profile", "BUFFER_PG|Ethernet8|0", map[string]string{"profile": "absent"}},
		{"NULL profile unsupported", "BUFFER_PG|Ethernet8|0", map[string]string{"profile": "NULL"}},
		{"profile wrong direction", "BUFFER_PG|Ethernet8|0", map[string]string{"profile": "egress_lossy_profile"}},
		{"queue wrong direction", "BUFFER_QUEUE|Ethernet8|0-2", map[string]string{"profile": "ingress_lossy_profile"}},
		{"missing index", "BUFFER_PG|Ethernet8", map[string]string{"profile": "ingress_lossy_profile"}},
		{"extra index", "BUFFER_PG|Ethernet8|0|1", map[string]string{"profile": "ingress_lossy_profile"}},
		{"invalid pg", "BUFFER_PG|Ethernet8|8", map[string]string{"profile": "ingress_lossy_profile"}},
		{"noncanonical pg", "BUFFER_PG|Ethernet8|00", map[string]string{"profile": "ingress_lossy_profile"}},
		{"reverse range", "BUFFER_PG|Ethernet8|7-0", map[string]string{"profile": "ingress_lossy_profile"}},
		{"range trailing junk", "BUFFER_PG|Ethernet8|0-7-8", map[string]string{"profile": "ingress_lossy_profile"}},
		{"invalid queue", "BUFFER_QUEUE|Ethernet8|16", map[string]string{"profile": "egress_lossy_profile"}},
		{"empty index", "BUFFER_PG|Ethernet8|", map[string]string{"profile": "ingress_lossy_profile"}},
		{"range missing end", "BUFFER_PG|Ethernet8|0-", map[string]string{"profile": "ingress_lossy_profile"}},
		{"range end too high", "BUFFER_QUEUE|Ethernet8|0-16", map[string]string{"profile": "egress_lossy_profile"}},
		{"grouped ports", "BUFFER_PG|Ethernet8,Ethernet9|0", map[string]string{"profile": "ingress_lossy_profile"}},
		{"VOQ grammar", "BUFFER_QUEUE|host|asic0|Ethernet8|0", map[string]string{"profile": "egress_lossy_profile"}},
		{"missing map", "PORT_QOS_MAP|Ethernet8", map[string]string{"tc_to_pg_map": "absent"}},
		{"unknown qos field", "PORT_QOS_MAP|Ethernet8", map[string]string{"tc_to_pg_map": "PROVISIONING_LOSSY", "future": "opaque"}},
		{"unqualified qos binding", "PORT_QOS_MAP|Ethernet8", map[string]string{"tc_to_queue_map": "PROVISIONING_LOSSY"}},
		{"malformed qos key", "PORT_QOS_MAP|Ethernet8|extra", map[string]string{"tc_to_pg_map": "PROVISIONING_LOSSY"}},
		{"invalid TC", "TC_TO_PRIORITY_GROUP_MAP|PROVISIONING_LOSSY", map[string]string{"16": "0"}},
		{"invalid PG", "TC_TO_PRIORITY_GROUP_MAP|PROVISIONING_LOSSY", map[string]string{"0": "8"}},
		{"empty PG", "TC_TO_PRIORITY_GROUP_MAP|PROVISIONING_LOSSY", map[string]string{"0": ""}},
		{"unknown map field", "TC_TO_PRIORITY_GROUP_MAP|PROVISIONING_LOSSY", map[string]string{"future": "0"}},
		{"missing pool", "BUFFER_PROFILE|ingress_lossy_profile", map[string]string{"pool": "absent", "size": "0", "dynamic_th": "3"}},
		{"unknown profile field", "BUFFER_PROFILE|ingress_lossy_profile", map[string]string{"pool": "ingress_lossless_pool", "size": "0", "dynamic_th": "3", "future": "opaque"}},
		{"invalid dynamic threshold", "BUFFER_PROFILE|ingress_lossy_profile", map[string]string{"pool": "ingress_lossless_pool", "size": "0", "dynamic_th": "8"}},
		{"negative size", "BUFFER_PROFILE|ingress_lossy_profile", map[string]string{"pool": "ingress_lossless_pool", "size": "-1", "dynamic_th": "3"}},
		{"missing profile size", "BUFFER_PROFILE|ingress_lossy_profile", map[string]string{"pool": "ingress_lossless_pool", "dynamic_th": "3"}},
		{"noncanonical dynamic threshold", "BUFFER_PROFILE|ingress_lossy_profile", map[string]string{"pool": "ingress_lossless_pool", "size": "0", "dynamic_th": "+3"}},
		{"invalid static threshold", "BUFFER_PROFILE|egress_lossless_profile", map[string]string{"pool": "egress_lossless_pool", "size": "1518", "static_th": "-1"}},
		{"wrong threshold mode", "BUFFER_PROFILE|ingress_lossy_profile", map[string]string{"pool": "ingress_lossless_pool", "size": "0", "static_th": "3"}},
		{"unknown pool field", "BUFFER_POOL|ingress_lossless_pool", map[string]string{"mode": "dynamic", "size": "10875072", "type": "ingress", "future": "opaque"}},
		{"invalid pool mode", "BUFFER_POOL|ingress_lossless_pool", map[string]string{"mode": "future", "size": "10875072", "type": "ingress"}},
		{"invalid pool size", "BUFFER_POOL|ingress_lossless_pool", map[string]string{"mode": "dynamic", "size": "many", "type": "ingress"}},
		{"overflow pool size", "BUFFER_POOL|ingress_lossless_pool", map[string]string{"mode": "dynamic", "size": "18446744073709551616", "type": "ingress"}},
		{"invalid pool xoff", "BUFFER_POOL|ingress_lossless_pool", map[string]string{"mode": "dynamic", "size": "10875072", "type": "ingress", "xoff": "bad"}},
		{"VOQ platform", "DEVICE_METADATA|localhost", map[string]string{"switch_type": "voq"}},
		{"unknown binding table", "BUFFER_FUTURE|Ethernet8|0", map[string]string{"profile": "ingress_lossy_profile"}},
		{"unknown port field reference", "FUTURE|row", map[string]string{"ports": "Ethernet8"}},
		{"unknown VLAN selector", "FUTURE|row", map[string]string{"vlans": "all"}},
		{"routed port", "INTERFACE|Ethernet8|192.0.2.1/24", map[string]string{"NULL": "NULL"}},
		{"LAG member", "PORTCHANNEL_MEMBER|PortChannel1|Ethernet8", map[string]string{"NULL": "NULL"}},
		{"competing untagged", "VLAN_MEMBER|Vlan200|Ethernet8", map[string]string{"tagging_mode": "untagged"}},
	}
}

func TestVLANAuthorityBufferNativeLimits(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, key string
		fields    map[string]string
	}{
		{"PG upper bound", "BUFFER_PG|Ethernet8|7", map[string]string{"profile": "ingress_lossy_profile"}},
		{"PG range", "BUFFER_PG|Ethernet8|0-7", map[string]string{"profile": "ingress_lossy_profile"}},
		{"queue upper bound", "BUFFER_QUEUE|Ethernet8|15", map[string]string{"profile": "egress_lossy_profile"}},
		{"queue range", "BUFFER_QUEUE|Ethernet8|8-15", map[string]string{"profile": "egress_lossy_profile"}},
		{"map limits", "TC_TO_PRIORITY_GROUP_MAP|PROVISIONING_LOSSY", map[string]string{"0": "0", "15": "7"}},
		{"dynamic lower bound", "BUFFER_PROFILE|ingress_lossy_profile", map[string]string{"pool": "ingress_lossless_pool", "size": "0", "dynamic_th": "-8"}},
		{"dynamic upper bound", "BUFFER_PROFILE|ingress_lossy_profile", map[string]string{"pool": "ingress_lossless_pool", "size": "0", "dynamic_th": "7"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := vlanAuthorityBufferFixture()
			// Replace the captured bindings when testing alternate native indices.
			delete(db, "BUFFER_PG|Ethernet8|0")
			db[tc.key] = tc.fields
			if err := vlanAuthoritySafe(db, 100, vlanChangeTarget(db, 100)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestVLANAuthorityBufferRejectUnsafe(t *testing.T) {
	t.Parallel()
	for _, tc := range vlanAuthorityUnsafeBufferCases() {
		t.Run(tc.name, func(t *testing.T) {
			db := vlanAuthorityBufferFixture()
			db[tc.key] = tc.fields
			if err := vlanAuthoritySafe(db, 100, vlanChangeTarget(db, 100)); err == nil {
				t.Fatal("unsafe dependency accepted")
			}
		})
	}
}

func TestVLANAuthorityBufferReferencesRemainChecked(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"Vlan100", "Ethernet8"} {
		t.Run(name, func(t *testing.T) {
			db := vlanAuthorityBufferFixture()
			// Even a syntactically valid, existing map cannot hide a VLAN/port
			// reference in a binding value behind the key-reference exception.
			db["TC_TO_PRIORITY_GROUP_MAP|"+name] = maps.Clone(db["TC_TO_PRIORITY_GROUP_MAP|PROVISIONING_LOSSY"])
			db["PORT_QOS_MAP|Ethernet8"]["tc_to_pg_map"] = name
			if err := vlanAuthoritySafe(db, 100, vlanChangeTarget(db, 100)); err == nil {
				t.Fatal("reference scan bypassed")
			}
		})
	}
}

func TestVLANAuthorityBufferFingerprint(t *testing.T) {
	t.Parallel()
	for _, key := range []string{"BUFFER_PG|Ethernet8|0", "BUFFER_QUEUE|Ethernet8|0-2", "PORT_QOS_MAP|Ethernet8", "BUFFER_PROFILE|ingress_lossy_profile", "BUFFER_POOL|ingress_lossless_pool", "TC_TO_PRIORITY_GROUP_MAP|PROVISIONING_LOSSY"} {
		t.Run(key, func(t *testing.T) {
			db := vlanAuthorityBufferFixture()
			hash, digest := vlanAuthorityHash(db), vlanAuthorityDigest(db, 100)
			delete(db, key)
			if hash == vlanAuthorityHash(db) || digest == vlanAuthorityDigest(db, 100) {
				t.Fatal("buffer dependency omitted from full snapshot fingerprint")
			}
		})
	}
}
