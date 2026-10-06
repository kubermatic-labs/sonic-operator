// SPDX-License-Identifier: Apache-2.0

package types

import "context"

// Port and child names are canonical native SONiC names, not abstract names.
type PortBreakoutRequest struct {
	Port            string `json:"port"`
	Mode            string `json:"mode"`
	ChildAdminState string `json:"child_admin_state"`
}

type PortBreakoutChild struct {
	Name       string `json:"name"`
	Lanes      string `json:"lanes"`
	Speed      string `json:"speed"`
	AdminState string `json:"admin_state"`
	MTU        string `json:"mtu"`
}

type PortBreakout struct {
	Port           string              `json:"port"`
	Mode           string              `json:"mode"`
	SupportedModes []string            `json:"supported_modes"`
	Children       []PortBreakoutChild `json:"children"`
	// ConfigurationVerified proves exact native layout in a stable CONFIG_DB
	// observation, independently of APPL_DB or kernel convergence.
	ConfigurationVerified bool   `json:"configuration_verified"`
	RuntimeVerified       bool   `json:"runtime_verified"`
	PersistenceVerified   bool   `json:"persistence_verified"`
	Pending               bool   `json:"pending"`
	Message               string `json:"message"`
}

// PortBreakoutAgent is optional. Runtime verification is CONFIG_DB, APPL_DB
// and kernel link presence, not carrier, ASIC forwarding or cable verification.
type PortBreakoutAgent interface {
	GetPortBreakout(context.Context, string) (*PortBreakout, *Status)
	ReconcilePortBreakout(context.Context, *PortBreakoutRequest) (*PortBreakout, *Status)
}
