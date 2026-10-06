// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"encoding/json"
	"reflect"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

const traditionalSpec = `{"mode":"Traditional","localASN":65100,"routerID":"10.1.0.1","prefixes":["10.1.0.1/32"]}`

func traditionalDB() vlanChangeDB {
	return vlanChangeDB{
		"DEVICE_METADATA|localhost":                {"bgp_asn": "65100", "type": "LeafRouter", "hostname": "switch"},
		"LOOPBACK_INTERFACE|Loopback0":             {"NULL": "NULL"},
		"LOOPBACK_INTERFACE|Loopback0|10.1.0.1/32": {"NULL": "NULL"},
		"BGP_DEVICE_GLOBAL|STATE":                  {"idf_isolation_state": "unisolated", "tsa_enabled": "false", "wcmp_enabled": "false"},
	}
}

func TestTraditionalBGPPlan(t *testing.T) {
	t.Parallel()
	db := traditionalDB()
	before, _ := json.Marshal(db)
	p, err := planNetworkResource(db, &agent.NetworkRequest{Kind: "BGP", OwnerID: "owner", Spec: json.RawMessage(traditionalSpec)})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.Desired, vlanChangeDB{"DEVICE_METADATA|localhost": {"bgp_asn": "65100", "type": "LeafRouter"}}) || p.Identity != "BGP|default" || p.Runtime == nil || p.Persisted == nil || p.Preflight == nil || p.Activate == nil {
		t.Fatalf("incomplete native-input plan: %+v", p)
	}
	if err := validateNetworkFields("BGP", p.Desired); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(db)
	if string(before) != string(after) {
		t.Fatal("planner mutated current configuration")
	}
}

func TestTraditionalBGPRejectsUnsupportedInputs(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, key string
		fields    map[string]string
	}{
		{"unified mode", "DEVICE_METADATA|localhost", map[string]string{"bgp_asn": "65100", "type": "LeafRouter", "frr_mgmt_framework_config": "true"}},
		{"split startup", "DEVICE_METADATA|localhost", map[string]string{"bgp_asn": "65100", "type": "LeafRouter", "docker_routing_config_mode": "split"}},
		{"router-id override", "DEVICE_METADATA|localhost", map[string]string{"bgp_asn": "65100", "type": "LeafRouter", "bgp_router_id": "10.1.0.1"}},
		{"peer", "BGP_NEIGHBOR|10.1.0.2", map[string]string{"asn": "65101"}},
		{"dynamic peer", "BGP_PEER_RANGE|group", map[string]string{"ip_range": "10.1.0.0/24"}},
		{"implicit VLAN advertisement", "VLAN_INTERFACE|Vlan10|10.2.0.1/24", map[string]string{"NULL": "NULL"}},
		{"extra loopback prefix", "LOOPBACK_INTERFACE|Loopback0|10.1.0.2/32", map[string]string{"NULL": "NULL"}},
		{"nondefault VRF", "LOOPBACK_INTERFACE|Loopback0", map[string]string{"vrf_name": "VrfBlue"}},
		{"redistribution", "ROUTE_REDISTRIBUTE|default|connected", map[string]string{"route_type": "bgp"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := traditionalDB()
			db[tc.key] = tc.fields
			if _, err := planNetworkResource(db, &agent.NetworkRequest{Kind: "BGP", OwnerID: "owner", Spec: json.RawMessage(traditionalSpec)}); err == nil {
				t.Fatal("accepted unsupported traditional inputs")
			}
		})
	}
}
