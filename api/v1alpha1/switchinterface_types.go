// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type AdminState string

const (
	AdminStateUnknown AdminState = "Unknown"
	AdminStateUp      AdminState = "Up"
	AdminStateDown    AdminState = "Down"
)

// SwitchInterfaceSpec defines the desired state of SwitchInterface
type SwitchInterfaceSpec struct {
	// Handle uniquely identifies this interface on the switch.
	// +required
	Handle string `json:"handle"`
	// NativeName is the native name of the interface on the switch (e.g., "Ethernet0").
	// +required +immutable
	NativeName string `json:"nativeName,omitempty"`

	// SwitchRef is a reference to the Switch this interface is connected to.
	// +required
	SwitchRef *v1.LocalObjectReference `json:"switchRef"`

	// AdminState represents the desired administrative state of the interface.
	// +optional
	AdminState AdminState `json:"adminState,omitempty"`

	// ManagementPolicy controls only speed, MTU and FEC ownership. AdminState
	// retains its separate opt-in management annotation.
	// +optional
	// +kubebuilder:default=Observe
	// +kubebuilder:validation:Enum=Observe;Manage
	ManagementPolicy NetworkManagementPolicy `json:"managementPolicy,omitempty"`
	// Speed is the existing configured port speed in Mbit/s. Omission is unowned.
	// Adoption and repair are supported; changing an adopted value is not.
	// +optional
	// +kubebuilder:validation:Enum=1000;10000;25000;100000
	Speed *uint32 `json:"speed,omitempty"`
	// MTU is the existing configured L3 MTU. Omission preserves native defaults.
	// +optional
	// +kubebuilder:validation:Minimum=1280
	// +kubebuilder:validation:Maximum=9216
	MTU *uint32 `json:"mtu,omitempty"`
	// FEC is an existing native FEC setting. Omission does not install a default.
	// +optional
	// +kubebuilder:validation:Enum=none;rs;fc
	FEC string `json:"fec,omitempty"`
}

type OperationState string

const (
	OperationStateUp      OperationState = "Up"
	OperationStateDown    OperationState = "Down"
	OperationStateUnknown OperationState = "Unknown"
)

type SwitchInterfaceState string

const (
	SwitchInterfaceStatePending      SwitchInterfaceState = "Pending"
	SwitchInterfaceStateInitializing SwitchInterfaceState = "Initializing"
	SwitchInterfaceStateReady        SwitchInterfaceState = "Ready"
	SwitchInterfaceStateFailed       SwitchInterfaceState = "Failed"
)

// Neighbor represents a connected neighbor device.
type Neighbor struct {
	// MacAddress is the MAC address of the neighbor device.
	MacAddress string `json:"macAddress,omitempty"`

	// SystemName is the name of the neighbor device.
	SystemName string `json:"systemName,omitempty"`

	// InterfaceHandle is the name of the remote switch interface.
	InterfaceHandle string `json:"interfaceHandle,omitempty"`
}

// SwitchInterfaceStatus defines the observed state of SwitchInterface.
type SwitchInterfaceStatus struct {
	// PortConfiguration reports speed/MTU/FEC independently of carrier and admin state.
	// +optional
	PortConfiguration NetworkResourceStatus `json:"portConfiguration,omitempty"`
	// AdminState represents the desired administrative state of the interface.
	// +optional
	AdminState AdminState `json:"adminState,omitempty"`

	// OperationalState represents the actual operational state of the interface.
	// +optional
	OperationalState OperationState `json:"operationalState,omitempty"`

	// State represents the high-level state of the SwitchInterface.
	// +optional
	State SwitchInterfaceState `json:"state,omitempty"`

	// AdminStateManaged reports whether the explicit admin opt-in and the manager
	// write gate were enabled for this reconciliation. It does not prove success;
	// require AdminPersistenceReady=True for the current request and generation.
	// False or absent means observed/read-only, not managed ownership.
	// +optional
	AdminStateManaged bool `json:"adminStateManaged,omitempty"`
	// AdminStateRequest is the observed admin-state-request annotation. Use a new
	// unique token for each annotation-only adoption and wait for this exact echo
	// together with AdminPersistenceReady=True. The echo alone is not success.
	// +optional
	AdminStateRequest string `json:"adminStateRequest,omitempty"`
	// AdminStateDigest is the SHA-256 fingerprint of the reconciled admin intent,
	// including CR UID, generation, target, desired state, request and write gates.
	// It is not a digest of the complete native configuration or forwarding state.
	// +optional
	AdminStateDigest string `json:"adminStateDigest,omitempty"`

	// Neighbor is a reference to the connected neighbor device, if any.
	// +optional
	Neighbor Neighbor `json:"neighbor,omitempty"`

	// MacAddress is the MAC address assigned to this interface.
	// +optional
	MacAddress string `json:"macAddress,omitempty"`
	// AliasName is the alias name of the interface.
	// +optional
	AliasName string `json:"aliasName,omitempty"`

	// The status of each condition is one of True, False, or Unknown.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Switch",type=string,JSONPath=`.spec.switchRef.name`
// +kubebuilder:printcolumn:name="Interface",type=string,JSONPath=`.spec.nativeName`
// +kubebuilder:printcolumn:name="AdminState",type=string,JSONPath=`.status.adminState`
// +kubebuilder:printcolumn:name="OperationalState",type=string,JSONPath=`.status.operationalState`
// +kubebuilder:printcolumn:name="State",type=string,JSONPath=`.status.state`
// +kubebuilder:printcolumn:name="Alias",type=string,JSONPath=`.status.aliasName`,priority=1
// +kubebuilder:printcolumn:name="Speed",type=integer,JSONPath=`.spec.speed`,priority=1
// +kubebuilder:printcolumn:name="MTU",type=integer,JSONPath=`.spec.mtu`,priority=1
// +kubebuilder:printcolumn:name="FEC",type=string,JSONPath=`.spec.fec`,priority=1
// +kubebuilder:printcolumn:name="Policy",type=string,JSONPath=`.spec.managementPolicy`,priority=1
// +kubebuilder:printcolumn:name="Neighbor",type=string,JSONPath=`.status.neighbor.systemName`,priority=1
// +kubebuilder:printcolumn:name="NeighborPort",type=string,JSONPath=`.status.neighbor.interfaceHandle`,priority=1
// +kubebuilder:printcolumn:name="MACAddress",type=string,JSONPath=`.status.macAddress`,priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// SwitchInterface is the Schema for the switchinterfaces API
type SwitchInterface struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of SwitchInterface
	// +required
	Spec SwitchInterfaceSpec `json:"spec"`

	// status defines the observed state of SwitchInterface
	// +optional
	Status SwitchInterfaceStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// SwitchInterfaceList contains a list of SwitchInterface
type SwitchInterfaceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SwitchInterface `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(GroupVersion, &SwitchInterface{}, &SwitchInterfaceList{})
		return nil
	})
}
