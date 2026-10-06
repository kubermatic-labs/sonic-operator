// SPDX-License-Identifier: Apache-2.0

package types

import (
	"context"
	"encoding/json"
	"fmt"
)

// NetworkAgent is an optional, typed network capability. There is deliberately
// no raw table, command, delete, or ownership-transfer operation.
type NetworkAgent interface {
	GetNetworkResource(context.Context, *NetworkRequest) (*NetworkResult, *Status)
	EnsureNetworkResource(context.Context, *NetworkRequest) (*NetworkResult, *Status)
}

// NetworkRecoveryAgent completes only an already-journaled operation. It never
// creates a new desired operation, deletes configuration, or releases ownership.
type NetworkRecoveryAgent interface {
	RecoverNetworkResource(context.Context, *NetworkRequest) (*NetworkResult, *Status)
}

type NetworkRequest struct {
	Kind    string          `json:"kind"`
	OwnerID string          `json:"ownerID"`
	Spec    json.RawMessage `json:"spec"`
}

type NetworkResult struct {
	Exists                bool            `json:"exists"`
	ConfigurationVerified bool            `json:"configurationVerified"`
	RuntimeVerified       bool            `json:"runtimeVerified"`
	PersistenceVerified   bool            `json:"persistenceVerified"`
	Observed              json.RawMessage `json:"observed,omitempty"`
	Message               string          `json:"message,omitempty"`
}

// ValidateNetworkRequest validates the envelope. Each planner additionally
// decodes its own spec with DisallowUnknownFields and validates network values.
func ValidateNetworkRequest(r *NetworkRequest, write bool) error {
	if r == nil {
		return fmt.Errorf("network request required")
	}
	switch r.Kind {
	case "Port", "PortChannel", "VRF", "L3Interface", "StaticRoute", "BGP", "BGPPeer", "DHCPRelay", "FRRMigration",
		"ACLPolicy", "ACLBinding", "QoSMap", "Scheduler", "QoSBinding",
		"MLAG", "VXLANTunnel", "VLANVNI", "EVPNPeer", "EVPN":
	default:
		return fmt.Errorf("unsupported network kind")
	}
	if (write && r.OwnerID == "") || len(r.OwnerID) > 256 {
		return fmt.Errorf("owner UID required for writes (maximum 256 bytes)")
	}
	if len(r.Spec) == 0 || len(r.Spec) > 1<<20 || !json.Valid(r.Spec) {
		return fmt.Errorf("valid network spec JSON required (maximum 1 MiB)")
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(r.Spec, &object) != nil || object == nil {
		return fmt.Errorf("network spec must be an object")
	}
	return nil
}
