// SPDX-License-Identifier: Apache-2.0

package sonic

import "context"

// Eligibility permits a native creation attempt; it is not evidence that SAI
// accepted it. SONiC can instantiate the tunnel only when the first VLAN map
// arrives. Requiring tunnel hardware here would deadlock fresh provisioning.
// Runtime verification retains exact name/OID, termination and mapper checks.
func evpnBootstrapPreflight(ctx context.Context, m *SonicAgent, source string) error {
	if err := evpnNative(ctx); err != nil {
		return err
	}
	db, _, err := m.vlanChangeSnapshot(ctx)
	if err != nil {
		return err
	}
	if err := evpnSafeConfig(db); err != nil {
		return err
	}
	config, err := runRoutingRead(ctx, routingBGPConfig)
	if err != nil {
		return err
	}
	if _, err := evpnFRRParse(config, db); err != nil {
		return err
	}
	return evpnUnderlay(ctx, db, source, "")
}
