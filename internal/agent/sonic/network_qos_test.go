// SPDX-License-Identifier: Apache-2.0

package sonic

import (
	"encoding/json"
	"math"
	"reflect"
	"testing"

	agent "github.com/ironcore-dev/sonic-operator/internal/agent/types"
)

func qosRequest(kind, spec string) *agent.NetworkRequest {
	return &agent.NetworkRequest{Kind: kind, OwnerID: "qos-owner", Spec: json.RawMessage(spec)}
}

func TestNetworkQoSMapPlanning(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, spec string
		valid      bool
	}{
		{"dscp", `{"name":"AZURE","type":"DSCPToTC","entries":[{"from":63,"to":9}]}`, true},
		{"dot1p", `{"name":"AZURE","type":"Dot1pToTC","entries":[{"from":7,"to":9}]}`, true},
		{"tc", `{"name":"AZURE","type":"TCToQueue","entries":[{"from":9,"to":9}]}`, true},
		{"unknown", `{"name":"x","type":"DSCPToTC","entries":[{"from":1,"to":0}],"policer":"p"}`, false},
		{"missing from", `{"name":"x","type":"DSCPToTC","entries":[{"to":0}]}`, false},
		{"missing to", `{"name":"x","type":"DSCPToTC","entries":[{"from":0}]}`, false},
		{"duplicate nested", `{"name":"x","type":"DSCPToTC","entries":[{"from":0,"from":1,"to":0}]}`, false},
		{"case folded", `{"name":"x","type":"DSCPToTC","entries":[{"From":0,"to":0}]}`, false},
		{"duplicate entry", `{"name":"x","type":"DSCPToTC","entries":[{"from":0,"to":0},{"from":0,"to":1}]}`, false},
		{"dscp range", `{"name":"x","type":"DSCPToTC","entries":[{"from":64,"to":0}]}`, false},
		{"dot1p range", `{"name":"x","type":"Dot1pToTC","entries":[{"from":8,"to":0}]}`, false},
		{"empty", `{"name":"x","type":"TCToQueue","entries":[]}`, false},
		{"null", `{"name":"x","type":"TCToQueue","entries":null}`, false},
		{"name injection", `{"name":"x|y","type":"TCToQueue","entries":[{"from":0,"to":0}]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := planNetworkQoSMap(vlanChangeDB{}, qosRequest("QoSMap", tc.spec))
			if (err == nil) != tc.valid {
				t.Fatalf("plan=%+v err=%v", p, err)
			}
			if tc.valid && (p.Preflight == nil || p.Runtime == nil || len(p.Desired) != 1) {
				t.Fatal("missing preflight/runtime or excess writes")
			}
		})
	}
	// Existing entries are preserved, but desired ownership includes only explicit fields.
	db := vlanChangeDB{"DSCP_TO_TC_MAP|AZURE": {"0": "0"}}
	p, err := planNetworkQoSMap(db, qosRequest("QoSMap", `{"name":"AZURE","type":"DSCPToTC","entries":[{"from":1,"to":1}]}`))
	if err != nil || !reflect.DeepEqual(p.Desired, vlanChangeDB{"DSCP_TO_TC_MAP|AZURE": {"1": "1"}}) {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := planNetworkQoSMap(db, qosRequest("QoSMap", `{"name":"AZURE","type":"DSCPToTC","entries":[{"from":0,"to":1}]}`)); err == nil {
		t.Fatal("foreign conflict accepted")
	}
}

func TestNetworkQoSSchedulerPlanning(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, spec string
		valid      bool
	}{
		{"strict", `{"name":"s","algorithm":"STRICT"}`, true},
		{"weighted", `{"name":"s","algorithm":"DWRR","weight":100}`, true},
		{"shaping", `{"name":"s","algorithm":"WRR","weight":1,"committedRate":1000,"peakRate":2000,"committedBurst":100,"peakBurst":200}`, true},
		{"packets", `{"name":"s","algorithm":"WRR","weight":1,"meterType":"Packets"}`, true},
		{"weight required", `{"name":"s","algorithm":"WRR"}`, false},
		{"strict weight", `{"name":"s","algorithm":"STRICT","weight":1}`, false},
		{"pir requires cir", `{"name":"s","algorithm":"STRICT","peakRate":100}`, false},
		{"cbs requires cir", `{"name":"s","algorithm":"STRICT","committedBurst":100}`, false},
		{"pbs requires pir", `{"name":"s","algorithm":"STRICT","peakBurst":100}`, false},
		{"rate ordering", `{"name":"s","algorithm":"STRICT","committedRate":100,"peakRate":50}`, false},
		{"burst ordering", `{"name":"s","algorithm":"STRICT","committedRate":1,"peakRate":2,"committedBurst":100,"peakBurst":50}`, false},
		{"zero", `{"name":"s","algorithm":"STRICT","committedRate":0}`, false},
		{"uint32 burst", `{"name":"s","algorithm":"STRICT","committedRate":1,"committedBurst":4294967296}`, false},
		{"int64 rate", `{"name":"s","algorithm":"STRICT","committedRate":9223372036854775808}`, false},
		{"inert priority", `{"name":"s","algorithm":"STRICT","priority":1}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := planNetworkScheduler(vlanChangeDB{}, qosRequest("Scheduler", tc.spec))
			if (err == nil) != tc.valid {
				t.Fatalf("plan=%+v err=%v", p, err)
			}
			if tc.valid && (p.Preflight == nil || p.Runtime == nil) {
				t.Fatal("unguarded scheduler")
			}
		})
	}
	p, err := planNetworkScheduler(nil, qosRequest("Scheduler", `{"name":"s","algorithm":"STRICT","committedRate":1000,"peakRate":2000}`))
	if err != nil || !reflect.DeepEqual(p.Desired, vlanChangeDB{"SCHEDULER|s": {"type": "STRICT", "meter_type": "bytes", "cir": "1000", "pir": "2000"}}) {
		t.Fatalf("rates must remain bytes/sec: %+v %v", p, err)
	}
}

func TestNetworkQoSCapabilityBounds(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, count string
		index       uint32
		valid       bool
	}{
		{"ten classes", "10", 9, true}, {"eight classes", "8", 9, false},
		{"exclusive bound", "10", 10, false}, {"missing", "", 0, false},
		{"zero", "0", 0, false}, {"malformed", "10 queues", 0, false},
		{"overflow", "4294967296", math.MaxUint32, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := qosCheckMapBounds("TC_TO_QUEUE_MAP", map[string]string{"0": qosUint(uint64(tc.index))}, map[string]string{"SWITCH|NUMBER_OF_TRAFFIC_CLASSES": tc.count, "SWITCH|NUMBER_OF_UNICAST_QUEUES": tc.count})
			if (err == nil) != tc.valid {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestNetworkQoSBindingPlanning(t *testing.T) {
	t.Parallel()
	seed := vlanChangeDB{"PORT|Ethernet0": {"lanes": "1,2,3,4"}, "DSCP_TO_TC_MAP|AZURE": {"0": "0"}, "SCHEDULER|native": {"type": "STRICT", "meter_type": "bytes"}, "QUEUE|Ethernet0|1": {"wred_profile": "preserve"}}
	for _, tc := range []struct {
		name, spec string
		valid      bool
	}{
		{"exact native refs", `{"interfaceName":"Ethernet0","dscpToTC":"AZURE","queues":[{"index":1,"scheduler":"native"}]}`, true},
		{"absent reference", `{"interfaceName":"Ethernet0","dscpToTC":"missing"}`, false},
		{"missing queue index", `{"interfaceName":"Ethernet0","queues":[{"scheduler":"native"}]}`, false},
		{"duplicate queue", `{"interfaceName":"Ethernet0","queues":[{"index":1,"scheduler":"native"},{"index":1,"scheduler":"native"}]}`, false},
		{"noncanonical", `{"interfaceName":"Ethernet00","dscpToTC":"AZURE"}`, false},
		{"nonphysical", `{"interfaceName":"PortChannel1","dscpToTC":"AZURE"}`, false},
		{"missing port", `{"interfaceName":"Ethernet4","dscpToTC":"AZURE"}`, false},
		{"empty", `{"interfaceName":"Ethernet0"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := planNetworkQoSBinding(seed, qosRequest("QoSBinding", tc.spec))
			if (err == nil) != tc.valid {
				t.Fatalf("plan=%+v err=%v", p, err)
			}
			if tc.valid && (!reflect.DeepEqual(p.Desired, vlanChangeDB{"PORT_QOS_MAP|Ethernet0": {"dscp_to_tc_map": "AZURE"}, "QUEUE|Ethernet0|1": {"scheduler": "native"}}) || p.Preflight == nil || p.Runtime == nil) {
				t.Fatalf("unsafe desired: %+v", p)
			}
		})
	}
}
