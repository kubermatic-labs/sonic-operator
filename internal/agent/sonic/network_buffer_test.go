// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"encoding/json"
	"os"
	"reflect"
	"strconv"
	"testing"
)

// Pool definitions and ports are synthetic dependencies, not captured evidence.
func bufferTestDB() vlanChangeDB {
	return vlanChangeDB{
		"PORT|Ethernet11":                      {"lanes": "11"},
		"BUFFER_POOL|PORT3_INGRESS_POOL":       {"type": "ingress", "mode": "dynamic", "size": "100000"},
		"BUFFER_POOL|egress":                   {"type": "egress", "mode": "static", "size": "100000"},
		"BUFFER_PROFILE|PORT3_INGRESS_PROFILE": {"pool": "PORT3_INGRESS_POOL", "size": "0", "dynamic_th": "3"},
		"BUFFER_PROFILE|out":                   {"pool": "egress", "size": "1518", "static_th": "1000"},
		"BUFFER_PG|Ethernet11|7":               {"profile": "PORT3_INGRESS_PROFILE"},
	}
}

func TestNetworkBufferPlanning(t *testing.T) {
	for _, tc := range []struct {
		kind, spec, key string
		fields          map[string]string
	}{
		{"BufferPool", `{"name":"PORT3_INGRESS_POOL","type":"ingress","mode":"dynamic","size":100000}`, "BUFFER_POOL|PORT3_INGRESS_POOL", map[string]string{"type": "ingress", "mode": "dynamic", "size": "100000"}},
		{"BufferProfile", `{"name":"PORT3_INGRESS_PROFILE","pool":"PORT3_INGRESS_POOL","size":0,"dynamicThreshold":3}`, "BUFFER_PROFILE|PORT3_INGRESS_PROFILE", map[string]string{"pool": "PORT3_INGRESS_POOL", "size": "0", "dynamic_th": "3"}},
		{"BufferPG", `{"interfaceName":"Ethernet11","range":"7","profile":"PORT3_INGRESS_PROFILE"}`, "BUFFER_PG|Ethernet11|7", map[string]string{"profile": "PORT3_INGRESS_PROFILE"}},
		{"BufferQueue", `{"interfaceName":"Ethernet11","range":"0-7","profile":"out"}`, "BUFFER_QUEUE|Ethernet11|0-7", map[string]string{"profile": "out"}},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			r := qosRequest(tc.kind, tc.spec)
			p, err := planNetworkResource(bufferTestDB(), r)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(p.Desired, vlanChangeDB{tc.key: tc.fields}) {
				t.Fatalf("desired=%v", p.Desired)
			}
			id, err := networkIdentity(r)
			if err != nil || id != p.Identity {
				t.Fatalf("identity=%s plan=%s err=%v", id, p.Identity, err)
			}
			if err := validateNetworkFields(tc.kind, p.Desired); err != nil {
				t.Fatal(err)
			}
			if p.Preflight == nil || p.Runtime == nil {
				t.Fatal("missing independent native guard")
			}
		})
	}
}

func TestNetworkBufferRejectsInvalidSpec(t *testing.T) {
	for _, tc := range []struct{ kind, spec string }{
		{"BufferPool", `{"name":"bad|key","type":"ingress","mode":"dynamic","size":10}`},
		{"BufferPool", `{"name":"new","type":"both","mode":"dynamic","size":10}`},
		{"BufferPool", `{"name":"new","type":"ingress","mode":"dynamic","size":0}`},
		{"BufferProfile", `{"name":"new","pool":"absent","size":0,"dynamicThreshold":3}`},
		{"BufferProfile", `{"name":"new","pool":"egress","size":0,"dynamicThreshold":3}`},
		{"BufferProfile", `{"name":"new","pool":"PORT3_INGRESS_POOL","size":0}`},
		{"BufferProfile", `{"name":"new","pool":"PORT3_INGRESS_POOL","size":0,"dynamicThreshold":3,"staticThreshold":1}`},
		{"BufferProfile", `{"name":"new","pool":"PORT3_INGRESS_POOL","size":0,"dynamicThreshold":8}`},
		{"BufferProfile", `{"name":"new","pool":"PORT3_INGRESS_POOL","size":0,"dynamicThreshold":3,"command":"bad"}`},
		{"BufferPG", `{"interfaceName":"Ethernet11","range":"8","profile":"PORT3_INGRESS_PROFILE"}`},
		{"BufferPG", `{"interfaceName":"Ethernet11","range":"0-8","profile":"PORT3_INGRESS_PROFILE"}`},
		{"BufferPG", `{"interfaceName":"Ethernet11","range":"07","profile":"PORT3_INGRESS_PROFILE"}`},
		{"BufferPG", `{"interfaceName":"Ethernet11","range":"7-7","profile":"PORT3_INGRESS_PROFILE"}`},
		{"BufferPG", `{"interfaceName":"Ethernet11","range":"7-0","profile":"PORT3_INGRESS_PROFILE"}`},
		{"BufferPG", `{"interfaceName":"Ethernet11","range":"0","profile":"out"}`},
		{"BufferPG", `{"interfaceName":"Ethernet12","range":"0","profile":"PORT3_INGRESS_PROFILE"}`},
		{"BufferPG", `{"interfaceName":"Ethernet11","range":"0","profile":"missing"}`},
		{"BufferQueue", `{"interfaceName":"Ethernet11","range":"256","profile":"out"}`},
		{"BufferQueue", `{"interfaceName":"Ethernet11","range":"0","profile":"PORT3_INGRESS_PROFILE"}`},
	} {
		t.Run(tc.kind+tc.spec, func(t *testing.T) {
			if _, err := planNetworkResource(bufferTestDB(), qosRequest(tc.kind, tc.spec)); err == nil {
				t.Fatal("accepted invalid buffer spec")
			}
		})
	}
}

func TestNetworkBufferOverlapsAndConflicts(t *testing.T) {
	for _, key := range []string{"BUFFER_PG|Ethernet11|6-7", "BUFFER_PG|Ethernet10,Ethernet11|7"} {
		db := bufferTestDB()
		db[key] = map[string]string{"profile": "PORT3_INGRESS_PROFILE"}
		if _, err := planNetworkResource(db, qosRequest("BufferPG", `{"interfaceName":"Ethernet11","range":"7","profile":"PORT3_INGRESS_PROFILE"}`)); err == nil {
			t.Fatalf("accepted overlapping %s", key)
		}
	}
	db := bufferTestDB()
	db["BUFFER_PG|Ethernet11|7"]["profile"] = "foreign"
	if _, err := planNetworkResource(db, qosRequest("BufferPG", `{"interfaceName":"Ethernet11","range":"7","profile":"PORT3_INGRESS_PROFILE"}`)); err == nil {
		t.Fatal("overwrote correction")
	}
}

func TestNetworkBufferCapturedPGCorrection(t *testing.T) {
	for _, host := range []string{"core-01", "leaf-03", "leaf-05"} {
		data, err := os.ReadFile("testdata/buffer-ownership/" + host + ".json")
		if err != nil {
			t.Fatal(err)
		}
		var capture map[string]map[string]map[string]string
		if err := json.Unmarshal(data, &capture); err != nil {
			t.Fatal(err)
		}
		if host == "core-01" && capture["BUFFER_PG"]["Ethernet11|7"]["profile"] != "PORT3_INGRESS_PROFILE" {
			t.Fatal("lost captured correction")
		}
		for key, row := range capture["BUFFER_PROFILE"] {
			if row["pool"] == "" {
				t.Fatalf("profile %s lost pool", key)
			}
			// Only the profile is captured. Supply clearly synthetic pool metadata
			// to validate field encoding without inventing fleet pool evidence.
			mode := "dynamic"
			threshold, field := row["dynamic_th"], "dynamicThreshold"
			if value, ok := row["static_th"]; ok {
				mode, threshold, field = "static", value, "staticThreshold"
			}
			size, err := strconv.ParseUint(row["size"], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			n, err := strconv.ParseInt(threshold, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			spec, err := json.Marshal(map[string]any{"name": key, "pool": row["pool"], "size": size, field: n})
			if err != nil {
				t.Fatal(err)
			}
			db := vlanChangeDB{"BUFFER_POOL|" + row["pool"]: {"type": "ingress", "mode": mode, "size": "64000000"}, "BUFFER_PROFILE|" + key: row}
			plan, err := planNetworkResource(db, qosRequest("BufferProfile", string(spec)))
			if err != nil || !reflect.DeepEqual(plan.Desired, vlanChangeDB{"BUFFER_PROFILE|" + key: row}) {
				t.Fatalf("captured %s/%s plan=%+v err=%v", host, key, plan, err)
			}
		}
	}
}

func TestNetworkBufferTCToPriorityGroup(t *testing.T) {
	p, err := planNetworkResource(vlanChangeDB{}, qosRequest("QoSMap", `{"name":"AZURE","type":"TCToPriorityGroup","entries":[{"from":7,"to":7}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Desired["TC_TO_PRIORITY_GROUP_MAP|AZURE"]["7"] != "7" {
		t.Fatal(p.Desired)
	}
	db := bufferTestDB()
	db["TC_TO_PRIORITY_GROUP_MAP|AZURE"] = map[string]string{"7": "7"}
	db["PORT_QOS_MAP|Ethernet11"] = map[string]string{"pfc_enable": "3,4", "tc_to_pg_map": "AZURE"}
	p, err = planNetworkResource(db, qosRequest("QoSBinding", `{"interfaceName":"Ethernet11","tcToPriorityGroup":"AZURE"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.Desired, vlanChangeDB{"PORT_QOS_MAP|Ethernet11": {"tc_to_pg_map": "AZURE"}}) {
		t.Fatal(p.Desired)
	}
	if err := validateNetworkFields("QoSBinding", p.Desired); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkBufferRecoveryIdentityIgnoresMutableFields(t *testing.T) {
	for _, tc := range []struct{ kind, spec, want string }{
		{"BufferPool", `{"name":"pool","type":null,"mode":[],"size":null}`, "BufferPool|pool"},
		{"BufferProfile", `{"name":"profile","pool":null,"dynamicThreshold":[]}`, "BufferProfile|profile"},
		{"BufferPG", `{"interfaceName":"Ethernet11","range":"7","profile":null}`, "BufferPG|Ethernet11|7"},
		{"BufferQueue", `{"interfaceName":"Ethernet11","range":"0-7","profile":null}`, "BufferQueue|Ethernet11|0-7"},
	} {
		id, err := networkIdentity(qosRequest(tc.kind, tc.spec))
		if err != nil || id != tc.want {
			t.Fatalf("%s identity=%q err=%v", tc.kind, id, err)
		}
	}
}

func TestNetworkBufferJournalTargetsAreNarrow(t *testing.T) {
	for _, tc := range []struct{ kind, key, field string }{
		{"BufferPool", "BUFFER_PROFILE|pool", "size"},
		{"BufferProfile", "BUFFER_PROFILE|profile", "command"},
		{"BufferPG", "BUFFER_PG|Ethernet11|8", "profile"},
		{"BufferPG", "BUFFER_PG|Ethernet10,Ethernet11|7", "profile"},
		{"BufferQueue", "BUFFER_QUEUE|Ethernet11|256", "profile"},
		{"BufferQueue", "QUEUE|Ethernet11|7", "scheduler"},
	} {
		if err := validateNetworkFields(tc.kind, vlanChangeDB{tc.key: {tc.field: "anything"}}); err == nil {
			t.Fatalf("journal allowed %s/%s", tc.key, tc.field)
		}
	}
}
