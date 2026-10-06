// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package types

// VLAN is a CONFIG_DB observation or an additive desired configuration, not a
// statement about forwarding health. Omitted members are never removed.
type VLAN struct {
	ID      uint32       `json:"id"`
	Members []VLANMember `json:"members"`
}

type VLANMember struct {
	InterfaceName string `json:"interface_name"`
	TaggingMode   string `json:"tagging_mode"`
}
