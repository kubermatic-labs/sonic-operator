// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"encoding/json"
	"testing"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestTraditionalBGPRuntimeDriftRequestsEnsure(t *testing.T) {
	obj, _, a, _, r := networkFixture(t, "BGP", `{"mode":"Traditional","localASN":65100,"routerID":"10.1.0.1","prefixes":["10.1.0.1/32"]}`)
	a.current.Exists, a.current.ConfigurationVerified, a.current.PersistenceVerified = true, true, true
	for i := 0; i < 3; i++ {
		if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}); err != nil {
			t.Fatal(err)
		}
	}
	if len(a.requests) != 1 {
		t.Fatalf("runtime-only traditional drift writes=%d want1", len(a.requests))
	}
}

func TestTraditionalBGPDefaultRetainsLegacyWire(t *testing.T) {
	for _, tc := range []struct{ name, mode string }{{"omitted mode", ""}, {"explicit default", `"mode":"Unified",`}} {
		t.Run(tc.name, func(t *testing.T) {
			obj, _, _, _, _ := networkFixture(t, "BGP", `{`+tc.mode+`"localASN":65001,"routerID":"192.0.2.1"}`)
			r, _, err := networkDesired("BGP", obj)
			if err != nil {
				t.Fatal(err)
			}
			var wire map[string]json.RawMessage
			_ = json.Unmarshal(r.Spec, &wire)
			if _, exists := wire["mode"]; exists {
				t.Fatal("default backend broke strict legacy agent decoding")
			}
		})
	}
}
