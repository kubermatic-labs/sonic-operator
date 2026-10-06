// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// NetworkManagementPolicy permits writes only with the manager and agent gates.
// +kubebuilder:validation:Enum=Observe;Manage
type NetworkManagementPolicy string

const (
	NetworkManagementPolicyObserve NetworkManagementPolicy = "Observe"
	NetworkManagementPolicyManage  NetworkManagementPolicy = "Manage"
)

type NetworkSwitchReference struct {
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`
	Name string `json:"name"`
}

// NetworkResourceSpec is shared by the eight network resources.
type NetworkResourceSpec struct {
	// +required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="switchRef is immutable"
	SwitchRef NetworkSwitchReference `json:"switchRef"`
	// +optional
	// +kubebuilder:default=Observe
	ManagementPolicy NetworkManagementPolicy `json:"managementPolicy,omitempty"`
}

// NetworkVRFName excludes management VRFs; default is the global routing table.
// +kubebuilder:validation:MaxLength=15
// +kubebuilder:validation:Pattern=`^(default|Vrf[A-Za-z0-9_-]{1,12})$`
type NetworkVRFName string

// NetworkIP is an unscoped IPv4 or IPv6 address, never an IPv4-mapped IPv6 address.
// +kubebuilder:validation:MaxLength=45
// +kubebuilder:validation:XValidation:rule="isIP(self)",message="must be an IPv4 or IPv6 address"
type NetworkIP string

// NetworkPrefix is a canonical network prefix, not an interface address.
// +kubebuilder:validation:MaxLength=49
// +kubebuilder:validation:XValidation:rule="isCIDR(self) && self == string(cidr(self).masked())",message="must be a canonical IPv4 or IPv6 network prefix"
type NetworkPrefix string

// NetworkInterfaceAddress deliberately retains host bits.
// +kubebuilder:validation:MaxLength=49
// +kubebuilder:validation:XValidation:rule="isCIDR(self)",message="must be an IPv4 or IPv6 CIDR address"
type NetworkInterfaceAddress string

// NetworkResourceStatus reports independent proof, not inferred forwarding health.
type NetworkResourceStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// +optional
	Exists bool `json:"exists,omitempty"`
	// +optional
	ConfigurationVerified bool `json:"configurationVerified,omitempty"`
	// +optional
	RuntimeVerified bool `json:"runtimeVerified,omitempty"`
	// +optional
	PersistenceVerified bool `json:"persistenceVerified,omitempty"`
	// Observed preserves the agent's structured observation without interpreting it.
	// +optional
	// +kubebuilder:validation:Type=object
	// +kubebuilder:pruning:PreserveUnknownFields
	Observed runtime.RawExtension `json:"observed,omitempty"`
	// Ready, Synced, ConfigurationReady, RuntimeReady and PersistenceReady are independent.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(GroupVersion,
			&SwitchPortChannel{}, &SwitchPortChannelList{}, &SwitchVRF{}, &SwitchVRFList{},
			&SwitchL3Interface{}, &SwitchL3InterfaceList{}, &SwitchStaticRoute{}, &SwitchStaticRouteList{},
			&SwitchBGP{}, &SwitchBGPList{}, &SwitchBGPPeer{}, &SwitchBGPPeerList{}, &SwitchDHCPRelay{}, &SwitchDHCPRelayList{},
			&SwitchFRRMigration{}, &SwitchFRRMigrationList{})
		return nil
	})
}
