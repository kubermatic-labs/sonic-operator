// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"encoding/json"
	"testing"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestMLAGDualPeerDependenciesBeforeInitialDomain(t *testing.T) {
	for _, side := range []string{"both eligible", "local member missing", "peer member missing"} {
		t.Run(side, func(t *testing.T) {
			obj, _, _, local, peer, _, r := mlagFixture(t)
			// Neither native domain exists. Eligibility proves the pre-existing
			// LAG/source dependencies without requiring either session to be up.
			local.current.Exists, peer.current.Exists = false, false
			local.current.ConfigurationVerified, peer.current.ConfigurationVerified = false, false
			local.current.RuntimeVerified, peer.current.RuntimeVerified = false, false
			blocked := json.RawMessage(`{"consumerReady":true,"preflightEligible":false,"reason":"MLAG LAG PortChannel20 does not exist"}`)
			if side == "local member missing" {
				local.current.Observed = blocked
			}
			if side == "peer member missing" {
				peer.current.Observed = blocked
			}
			req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)}
			_, err := r.Reconcile(t.Context(), req)
			if side != "both eligible" {
				if err == nil || len(local.requests) != 0 {
					t.Fatalf("missing dependency staged: err=%v writes=%d", err, len(local.requests))
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := r.Reconcile(t.Context(), req); err != nil {
				t.Fatal(err)
			}
			if len(local.requests) != 1 {
				t.Fatalf("initial staging blocked by absent domains: writes=%d", len(local.requests))
			}
		})
	}
}
