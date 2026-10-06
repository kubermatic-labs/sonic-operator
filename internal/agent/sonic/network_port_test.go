// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

func TestNetworkPortRuntime(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, attribute, value string
		want                   bool
	}{
		{"carrier down", "", "", true},
		{"wrong SAI speed", "SAI_PORT_ATTR_SPEED", "10000", false},
		{"missing L2 overhead", "SAI_PORT_ATTR_MTU", "9100", false},
		{"wrong SAI FEC", "SAI_PORT_ATTR_FEC_MODE", "SAI_PORT_FEC_MODE_NONE", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attrs := map[string]string{"SAI_PORT_ATTR_SPEED": "1000", "SAI_PORT_ATTR_MTU": "9122", "SAI_PORT_ATTR_FEC_MODE": "SAI_PORT_FEC_MODE_RS"}
			if tc.attribute != "" {
				attrs[tc.attribute] = tc.value
			}
			read := func(_ context.Context, db, key string) (map[string]string, error) {
				switch db + "/" + key {
				case "APPL_DB/PORT_TABLE:Ethernet0":
					return map[string]string{"speed": "1000", "mtu": "9100", "fec": "rs", "oper_status": "down"}, nil
				case "COUNTERS_DB/COUNTERS_PORT_NAME_MAP":
					return map[string]string{"Ethernet0": "oid:0x1000000000001"}, nil
				case "ASIC_DB/ASIC_STATE:SAI_OBJECT_TYPE_PORT:oid:0x1000000000001":
					return attrs, nil
				case "ASIC_DB/VIDTORID":
					return map[string]string{"oid:0x1000000000001": "oid:0xabc"}, nil
				default:
					t.Fatalf("unexpected read %s/%s", db, key)
					return nil, nil
				}
			}
			got, _, err := networkPortRuntime(t.Context(), "Ethernet0", map[string]string{"speed": "1000", "mtu": "9100", "fec": "rs"}, read)
			if err != nil || got != tc.want {
				t.Fatalf("runtime=%v want=%v err=%v", got, tc.want, err)
			}
		})
	}
}

func TestNetworkPortAppliedIdentity(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, vid, rid               string
		alias, changeName, changeRID bool
	}{
		{"absent translation", "oid:0x1000000000001", "", false, false, false},
		{"zero translation", "oid:0x1000000000001", "oid:0x0", false, false, false},
		{"aliased translation", "oid:0x1000000000001", "oid:0xabc", true, false, false},
		{"wrong object type", "oid:0x7000000000001", "oid:0xabc", false, false, false},
		{"changed name mapping", "oid:0x1000000000001", "oid:0xabc", false, true, false},
		{"changed translation", "oid:0x1000000000001", "oid:0xabc", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			after := false
			read := func(_ context.Context, db, key string) (map[string]string, error) {
				switch db + "/" + key {
				case "APPL_DB/PORT_TABLE:Ethernet0":
					return map[string]string{"speed": "1000"}, nil
				case "COUNTERS_DB/COUNTERS_PORT_NAME_MAP":
					vid := tc.vid
					if after && tc.changeName {
						vid = "oid:0x1000000000002"
					}
					return map[string]string{"Ethernet0": vid}, nil
				case "ASIC_DB/VIDTORID":
					ids := map[string]string{}
					if tc.rid != "" {
						ids[tc.vid] = tc.rid
					}
					if tc.alias {
						ids["oid:0x1000000000003"] = tc.rid
					}
					if after && tc.changeRID {
						ids[tc.vid] = "oid:0xdef"
					}
					return ids, nil
				default:
					after = true
					return map[string]string{"SAI_PORT_ATTR_SPEED": "1000"}, nil
				}
			}
			if ok, _, err := networkPortRuntime(t.Context(), "Ethernet0", map[string]string{"speed": "1000"}, read); err != nil || ok {
				t.Fatalf("accepted invalid applied identity: %v %v", ok, err)
			}
		})
	}
}

func TestNetworkPortPlan(t *testing.T) {
	t.Parallel()
	db := vlanChangeDB{"PORT|Ethernet0": {"speed": "1000", "mtu": "9100", "fec": "rs", "admin_status": "down", "lanes": "1", "alias": "keep"}}
	for _, tc := range []struct {
		name, spec string
		fields     map[string]string
	}{
		{"speed only", `{"nativeName":"Ethernet0","speed":1000}`, map[string]string{"speed": "1000"}},
		{"mtu only", `{"nativeName":"Ethernet0","mtu":9100}`, map[string]string{"mtu": "9100"}},
		{"fec only", `{"nativeName":"Ethernet0","fec":"rs"}`, map[string]string{"fec": "rs"}},
		{"all with inventory", `{"nativeName":"Ethernet0","handle":"port-0","adminState":"Down","speed":1000,"mtu":9100,"fec":"rs"}`, map[string]string{"speed": "1000", "mtu": "9100", "fec": "rs"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &agent.NetworkRequest{Kind: "Port", OwnerID: "owner", Spec: json.RawMessage(tc.spec)}
			p, err := planNetworkResource(db, r)
			if err != nil {
				t.Fatal(err)
			}
			identity, err := networkIdentity(r)
			if err != nil || identity != "Port|Ethernet0" || p.Identity != identity || !reflect.DeepEqual(p.Desired, vlanChangeDB{"PORT|Ethernet0": tc.fields}) || p.Runtime == nil || p.Activate != nil {
				t.Fatalf("invalid plan: %+v %v", p, err)
			}
			if err := validateNetworkFields(r.Kind, p.Desired); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNetworkPortRejects(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, spec string }{
		{"empty", `{"nativeName":"Ethernet0"}`},
		{"absent port", `{"nativeName":"Ethernet1","speed":1000}`},
		{"noncanonical name", `{"nativeName":"Ethernet00","speed":1000}`},
		{"speed zero", `{"nativeName":"Ethernet0","speed":0}`},
		{"unqualified speed", `{"nativeName":"Ethernet0","speed":400000}`},
		{"string speed", `{"nativeName":"Ethernet0","speed":"1000"}`},
		{"low mtu", `{"nativeName":"Ethernet0","mtu":1279}`},
		{"high mtu", `{"nativeName":"Ethernet0","mtu":9217}`},
		{"unknown fec", `{"nativeName":"Ethernet0","fec":"auto"}`},
		{"null", `{"nativeName":"Ethernet0","speed":null}`},
		{"case folded", `{"nativeName":"Ethernet0","Speed":1000}`},
		{"duplicates", `{"nativeName":"Ethernet0","speed":1000,"speed":10000}`},
		{"unknown field", `{"nativeName":"Ethernet0","speed":1000,"lanes":"2"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := planNetworkResource(vlanChangeDB{"PORT|Ethernet0": {"speed": "1000"}}, &agent.NetworkRequest{Kind: "Port", OwnerID: "owner", Spec: json.RawMessage(tc.spec)}); err == nil {
				t.Fatal("accepted invalid port spec")
			}
		})
	}
}

func TestNetworkPortOwnership(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, live, want, owned, layout string
		allowed                         bool
	}{
		{"equal adoption", "1000", "1000", "", "1", true},
		{"foreign value", "10000", "1000", "", "1", false},
		{"absent native field", "", "1000", "", "1", false},
		{"owned drift repair", "10000", "1000", "1000", "1", true},
		{"owned deletion repair", "", "1000", "1000", "1", true},
		{"new speed is unqualified", "1000", "10000", "1000", "1", false},
		{"changed lanes", "10000", "1000", "1000", "2", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := vlanChangeDB{"PORT|Ethernet0": {"lanes": tc.layout}}
			if tc.live != "" {
				db["PORT|Ethernet0"]["speed"] = tc.live
			}
			p := &networkPlan{Identity: "Port|Ethernet0", Desired: vlanChangeDB{"PORT|Ethernet0": {"speed": tc.want}}}
			var r *networkRecord
			if tc.owned != "" {
				r = &networkRecord{Fields: vlanChangeDB{"PORT|Ethernet0": {"speed": tc.owned}}, PortLayout: networkPortLayout(vlanChangeDB{"PORT|Ethernet0": {"lanes": "1"}}, p)}
			}
			err := networkPortOwnership(db, p, r)
			if (err == nil) != tc.allowed {
				t.Fatalf("allowed=%v err=%v", tc.allowed, err)
			}
		})
	}
}

func TestNetworkPortJournalValidation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, key, field, value string }{
		{"wrong target", "PORT|Ethernet0|extra", "speed", "1000"},
		{"noncanonical target", "PORT|Ethernet00", "speed", "1000"},
		{"invalid speed", "PORT|Ethernet0", "speed", "1001"},
		{"noncanonical MTU", "PORT|Ethernet0", "mtu", "09100"},
		{"invalid FEC", "PORT|Ethernet0", "fec", "bogus"},
		{"admin ownership", "PORT|Ethernet0", "admin_status", "up"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateNetworkFields("Port", vlanChangeDB{tc.key: {tc.field: tc.value}}); err == nil {
				t.Fatal("accepted untyped port journal field")
			}
		})
	}
}
