// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package types

import "context"

// VLANAuthorityRequest declares the ENTIRE membership, including an empty set.
// OwnerID is the immutable CR UID. AdoptionDigest approves the current snapshot
// only on first takeover; Delete requires already-held ownership.
type VLANAuthorityRequest struct {
	OwnerID        string `json:"owner_id"`
	VLAN           *VLAN  `json:"vlan"`
	AdoptionDigest string `json:"adoption_digest"`
	Delete         bool   `json:"delete"`
}

type VLANAuthorityResult struct {
	// OwnershipKnown is true only after reading a secured, durable journal.
	// Empty OwnerID without this proof must never authorize finalizer removal.
	OwnershipKnown      bool   `json:"ownership_known"`
	VLAN                *VLAN  `json:"vlan"`
	Digest              string `json:"digest"`
	OwnerID             string `json:"owner_id"`
	RuntimeVerified     bool   `json:"runtime_verified"`
	PersistenceVerified bool   `json:"persistence_verified"`
}

// VLANAuthorityAgent is optional and does not change the additive Agent API.
// RuntimeVerified requires CONFIG_DB and APPL_DB VLAN membership convergence,
// never ASIC or forwarding state. Persistence is not confirmed before convergence.
// Get returns a nonempty digest even when VLAN is nil. Callers must retry a
// non-success status even if the returned result describes a verified old target.
type VLANAuthorityAgent interface {
	GetVLANAuthority(context.Context, uint32) (*VLANAuthorityResult, *Status)
	ReconcileVLANAuthority(context.Context, *VLANAuthorityRequest) (*VLANAuthorityResult, *Status)
	ReleaseVLANAuthority(context.Context, uint32, string) *Status
}
