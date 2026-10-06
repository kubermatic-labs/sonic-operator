// SPDX-License-Identifier: Apache-2.0

// Package host owns a closed host-configuration protocol. Credentials are carried
// only in private RPC payloads and native configuration, never recovery records.
package host

type Address struct {
	Prefix  string `json:"prefix"`
	Gateway string `json:"gateway,omitempty"`
}

type Management struct {
	Interface string    `json:"interface"`
	Addresses []Address `json:"addresses"`
	MAC       string    `json:"mac,omitempty"`
}

// Credential deliberately redacts fmt formatting. JSON encoding is for the
// private mTLS wire only; System must never be serialized into ownership storage.
type Credential string

func (Credential) String() string   { return "[redacted]" }
func (Credential) GoString() string { return "[redacted]" }

type NTP struct {
	Servers         []string `json:"servers"`
	AdminState      string   `json:"adminState,omitempty"`
	DHCP            string   `json:"dhcp,omitempty"`
	ServerRole      string   `json:"serverRole,omitempty"`
	SourceInterface string   `json:"sourceInterface,omitempty"`
}
type SNMP struct {
	Location  string     `json:"location"`
	Contact   string     `json:"contact"`
	Community Credential `json:"community"`
}
type System struct {
	NTP  *NTP  `json:"ntp,omitempty"`
	SNMP *SNMP `json:"snmp,omitempty"`
}

type Request struct {
	Kind       string      `json:"kind"`
	Owner      string      `json:"owner"`
	Target     string      `json:"target"`
	Management *Management `json:"management,omitempty"`
	System     *System     `json:"system,omitempty"`
	// Revision is a public Kubernetes generation/Secret-resourceVersion identity,
	// never a credential hash (which would permit offline credential guessing).
	Revision        string `json:"revision"`
	RollbackSeconds int    `json:"rollbackSeconds,omitempty"`
}

// Result is intentionally public: no desired/observed raw JSON and no tool output.
type Result struct {
	ConfigurationVerified bool   `json:"configurationVerified"`
	RuntimeVerified       bool   `json:"runtimeVerified"`
	PersistenceVerified   bool   `json:"persistenceVerified"`
	GatewayVerified       bool   `json:"gatewayVerified"`
	Recovery              string `json:"recovery"`
	Transaction           string `json:"transaction,omitempty"`
	Challenge             string `json:"challenge,omitempty"`
	Owner                 string `json:"owner,omitempty"`
}

func (r Result) Ready() bool {
	return r.ConfigurationVerified && r.RuntimeVerified && r.PersistenceVerified && r.GatewayVerified && r.Recovery != "Pending" && r.Recovery != "RollbackRequired" && r.Recovery != "RolledBack"
}

type Confirmation struct {
	Owner       string `json:"owner"`
	Target      string `json:"target"`
	Transaction string `json:"transaction"`
	Challenge   string `json:"challenge"`
}
