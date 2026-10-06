// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	api "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func trafficInvalidFields(kind string, duplicate bool) map[string]any {
	if duplicate {
		switch kind {
		case "ACLPolicy":
			return map[string]any{"rules": []any{map[string]any{"name": "a", "priority": 2, "action": "Drop"}, map[string]any{"name": "b", "priority": 2, "action": "Permit"}}}
		case "ACLBinding":
			return map[string]any{"interfaces": []string{"Ethernet0", "Ethernet0"}}
		case "QoSMap":
			return map[string]any{"entries": []any{map[string]any{"from": 0, "to": 0}, map[string]any{"from": 0, "to": 1}}}
		case "Scheduler":
			return map[string]any{"algorithm": "STRICT", "weight": 10}
		case "QoSBinding":
			return map[string]any{"queues": []any{map[string]any{"index": 0, "scheduler": "a"}, map[string]any{"index": 0, "scheduler": "b"}}}
		}
	}
	switch kind {
	case "ACLPolicy":
		return map[string]any{"defaultAction": "Police"}
	case "ACLBinding":
		return map[string]any{"interfaces": []string{"eth0"}}
	case "QoSMap":
		return map[string]any{"entries": []any{map[string]any{"from": 64, "to": 0}}}
	case "Scheduler":
		return map[string]any{"weight": 0}
	case "QoSBinding":
		return map[string]any{"interfaceName": "eth0"}
	default:
		panic("unknown traffic kind")
	}
}

func TestTrafficGroupedGate(t *testing.T) {
	t.Parallel()
	for _, resource := range networkTestSpecs {
		if !isTrafficKind(resource.kind) {
			continue
		}
		for _, phase := range []string{"observe", "bound", "delete"} {
			t.Run(resource.kind+"/"+phase, func(t *testing.T) {
				t.Parallel()
				obj, _, a, c, r := networkFixture(t, resource.kind, resource.spec)
				req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}
				if phase != "observe" {
					if _, err := r.Reconcile(t.Context(), req); err != nil {
						t.Fatal(err)
					}
					if err := c.Get(t.Context(), req.NamespacedName, obj); err != nil {
						t.Fatal(err)
					}
					if phase == "delete" {
						if err := c.Delete(t.Context(), obj); err != nil {
							t.Fatal(err)
						}
					}
				}
				r.AllowTrafficPolicy = false
				_, err := r.Reconcile(t.Context(), req)
				if (err != nil) != (phase != "observe") {
					t.Fatalf("phase %s: %v", phase, err)
				}
				if len(a.requests) != 0 || len(a.recoveries) != 0 {
					t.Fatal("disabled traffic gate allowed Ensure or Recover")
				}
				if err := c.Get(t.Context(), req.NamespacedName, obj); err != nil {
					t.Fatal(err)
				}
				if phase != "observe" && !slices.Contains(obj.GetFinalizers(), networkRecoveryFinalizer) {
					t.Fatal("blocked recovery lost finalizer")
				}
				if phase == "observe" {
					_, status, _ := networkFields(obj)
					if string(status.Observed.Raw) != string(a.current.Observed) {
						t.Fatal("disabled gate prevented observation")
					}
				}
			})
		}
	}
}

func TestTrafficRecoveryImmutableSelectors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ kind, field, value string }{
		{"ACLPolicy", "name", "other"}, {"ACLBinding", "policy", "other"},
		{"QoSMap", "name", "other"}, {"QoSMap", "type", "TCToQueue"},
		{"Scheduler", "name", "other"}, {"QoSBinding", "interfaceName", "Ethernet4"},
	} {
		t.Run(tc.kind+"/"+tc.field, func(t *testing.T) {
			t.Parallel()
			for _, resource := range networkTestSpecs {
				if resource.kind != tc.kind {
					continue
				}
				obj, _, a, c, r := networkFixture(t, resource.kind, resource.spec)
				req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}
				if _, err := r.Reconcile(t.Context(), req); err != nil {
					t.Fatal(err)
				}
				if err := c.Get(t.Context(), req.NamespacedName, obj); err != nil {
					t.Fatal(err)
				}
				raw, _ := json.Marshal(map[string]any{"spec": map[string]any{tc.field: tc.value}})
				if err := json.Unmarshal(raw, obj); err != nil {
					t.Fatal(err)
				}
				if err := c.Update(t.Context(), obj); err != nil {
					t.Fatal(err)
				}
				if err := c.Delete(t.Context(), obj); err != nil {
					t.Fatal(err)
				}
				if _, err := r.Reconcile(t.Context(), req); err == nil {
					t.Fatal("changed selector recovered")
				}
				if len(a.recoveries) != 0 || len(a.requests) != 0 {
					t.Fatal("changed selector contacted write RPC")
				}
			}
		})
	}
}

// The same contract cases also exercise generated OpenAPI/CEL through envtest.
var trafficValidationCases = []struct {
	name, kind, spec string
	valid            bool
}{
	{"empty rules catchall", "ACLPolicy", `{"name":"edge","family":"IPv4","defaultAction":"Permit","rules":[]}`, true},
	{"missing default action", "ACLPolicy", `{"name":"edge","family":"IPv4","rules":[]}`, false},
	{"wrong family", "ACLPolicy", `{"name":"edge","family":"IPv4","defaultAction":"Drop","rules":[{"name":"v6","priority":2,"action":"Permit","source":"2001:db8::/64"}]}`, false},
	{"IPv6 rule", "ACLPolicy", `{"name":"edge","family":"IPv6","defaultAction":"Drop","rules":[{"name":"v6","priority":999999,"action":"Permit","destination":"2001:db8::/64","protocol":17,"sourcePort":0,"destinationPort":65535}]}`, true},
	{"reserved priority", "ACLPolicy", `{"name":"edge","family":"IPv4","defaultAction":"Drop","rules":[{"name":"a","priority":1,"action":"Permit"}]}`, false},
	{"reserved catchall name", "ACLPolicy", `{"name":"edge","family":"IPv4","defaultAction":"Drop","rules":[{"name":"DEFAULT","priority":2,"action":"Permit"}]}`, false},
	{"duplicate names", "ACLPolicy", `{"name":"edge","family":"IPv4","defaultAction":"Drop","rules":[{"name":"a","priority":2,"action":"Permit"},{"name":"a","priority":3,"action":"Drop"}]}`, false},
	{"port without protocol", "ACLPolicy", `{"name":"edge","family":"IPv4","defaultAction":"Drop","rules":[{"name":"a","priority":2,"action":"Permit","sourcePort":0}]}`, false},
	{"ICMP port", "ACLPolicy", `{"name":"edge","family":"IPv4","defaultAction":"Drop","rules":[{"name":"a","priority":2,"action":"Permit","protocol":1,"destinationPort":80}]}`, false},
	{"zero protocol", "ACLPolicy", `{"name":"edge","family":"IPv4","defaultAction":"Drop","rules":[{"name":"a","priority":2,"action":"Permit","protocol":0}]}`, false},
	{"protocol overflow", "ACLPolicy", `{"name":"edge","family":"IPv4","defaultAction":"Drop","rules":[{"name":"a","priority":2,"action":"Permit","protocol":144}]}`, false},
	{"port overflow", "ACLPolicy", `{"name":"edge","family":"IPv4","defaultAction":"Drop","rules":[{"name":"a","priority":2,"action":"Permit","protocol":6,"sourcePort":65536}]}`, false},
	{"noncanonical prefix", "ACLPolicy", `{"name":"edge","family":"IPv4","defaultAction":"Drop","rules":[{"name":"a","priority":2,"action":"Permit","source":"192.0.2.1/24"}]}`, false},
	{"empty interfaces", "ACLBinding", `{"policy":"edge","interfaces":[]}`, false},
	{"management interface", "ACLBinding", `{"policy":"edge","interfaces":["eth0"]}`, false},
	{"invalid identifier", "ACLBinding", `{"policy":"ACL|edge","interfaces":["Ethernet0"]}`, false},
	{"dot1p max", "QoSMap", `{"name":"dot1p","type":"Dot1pToTC","entries":[{"from":7,"to":0}]}`, true},
	{"dot1p overflow", "QoSMap", `{"name":"dot1p","type":"Dot1pToTC","entries":[{"from":8,"to":0}]}`, false},
	{"uint32 device bounds deferred", "QoSMap", `{"name":"tc","type":"TCToQueue","entries":[{"from":4294967295,"to":4294967295}]}`, true},
	{"strict nil optionals", "Scheduler", `{"name":"strict","algorithm":"STRICT"}`, true},
	{"strict weight", "Scheduler", `{"name":"strict","algorithm":"STRICT","weight":1}`, false},
	{"weighted missing weight", "Scheduler", `{"name":"wrr","algorithm":"WRR"}`, false},
	{"weight overflow", "Scheduler", `{"name":"wrr","algorithm":"WRR","weight":101}`, false},
	{"packet shaper", "Scheduler", `{"name":"wrr","algorithm":"WRR","weight":100,"meterType":"Packets","committedRate":100,"peakRate":200,"committedBurst":10,"peakBurst":20}`, true},
	{"int64 max", "Scheduler", `{"name":"strict","algorithm":"STRICT","committedRate":1,"peakRate":9223372036854775807}`, true},
	{"int64 overflow", "Scheduler", `{"name":"strict","algorithm":"STRICT","peakRate":9223372036854775808}`, false},
	{"zero rate", "Scheduler", `{"name":"strict","algorithm":"STRICT","peakRate":0}`, false},
	{"CIR without PIR", "Scheduler", `{"name":"strict","algorithm":"STRICT","committedRate":1}`, true},
	{"PIR without CIR", "Scheduler", `{"name":"strict","algorithm":"STRICT","peakRate":1}`, false},
	{"PIR below CIR", "Scheduler", `{"name":"strict","algorithm":"STRICT","committedRate":2,"peakRate":1}`, false},
	{"committed burst without rate", "Scheduler", `{"name":"strict","algorithm":"STRICT","committedBurst":1}`, false},
	{"peak burst without rate", "Scheduler", `{"name":"strict","algorithm":"STRICT","peakBurst":1}`, false},
	{"peak burst below committed", "Scheduler", `{"name":"strict","algorithm":"STRICT","committedRate":1,"peakRate":2,"committedBurst":2,"peakBurst":1}`, false},
	{"empty binding", "QoSBinding", `{"interfaceName":"Ethernet0"}`, false},
	{"queue only", "QoSBinding", `{"interfaceName":"Ethernet0","queues":[{"index":0,"scheduler":"strict"}]}`, true},
	{"maps only", "QoSBinding", `{"interfaceName":"Ethernet0","dot1pToTC":"dot1p","tcToQueue":"tc"}`, true},
	{"management QoS", "QoSBinding", `{"interfaceName":"eth0","dscpToTC":"dscp"}`, false},
}

func TestTrafficValidation(t *testing.T) {
	t.Parallel()
	for _, tc := range trafficValidationCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			obj, _, a, _, r := networkFixture(t, tc.kind, tc.spec)
			original := obj.DeepCopyObject()
			req, target, err := networkDesired(tc.kind, obj)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
			if !reflect.DeepEqual(obj, original) {
				t.Fatal("normalization mutated original")
			}
			if tc.valid {
				if target == "" || req.Kind != tc.kind {
					t.Fatal("missing target or wrong kind")
				}
				if tc.kind == "Scheduler" {
					var s api.SwitchSchedulerSpec
					if err := json.Unmarshal(req.Spec, &s); err != nil {
						t.Fatal(err)
					}
					if s.MeterType == "" {
						t.Fatal("missing meterType default")
					}
				}
			} else {
				if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}); err == nil {
					t.Fatal("invalid spec reconciled")
				}
				if len(a.requests) != 0 {
					t.Fatal("invalid spec wrote")
				}
			}
		})
	}
	// Values above OpenAPI int64 must also be rejected by admission-bypassing callers.
	for _, field := range []string{"committedRate", "peakRate", "committedBurst", "peakBurst"} {
		t.Run(field+" overflow", func(t *testing.T) {
			obj, _, _, _, _ := networkFixture(t, "Scheduler", `{"name":"strict","algorithm":"STRICT","`+field+`":9223372036854775808}`)
			if _, _, err := networkDesired("Scheduler", obj); err == nil {
				t.Fatal("uint64 above int64 accepted")
			}
		})
	}
}
