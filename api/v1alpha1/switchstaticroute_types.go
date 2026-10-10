// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type StaticRouteNextHop struct {
	// +required
	Address NetworkIP `json:"address"`
	// +optional
	// +kubebuilder:validation:MaxLength=32
	// +kubebuilder:validation:Pattern=`^(Ethernet(0|[1-9][0-9]*)|PortChannel(0|[1-9][0-9]{0,3})|Vlan[1-9][0-9]{0,3})$`
	// +kubebuilder:validation:XValidation:rule="!self.startsWith('Vlan') || int(self.substring(4)) <= 4094",message="VLAN interface ID must be 1..4094"
	InterfaceName string `json:"interfaceName,omitempty"`
	// +optional
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=255
	Distance uint32 `json:"distance,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="self.nextHops.all(n, ip(n.address).family() == cidr(self.prefix).ip().family())",message="next hops must match the prefix address family"
type SwitchStaticRouteSpec struct {
	NetworkResourceSpec `json:",inline"`
	// +optional
	// +kubebuilder:default=default
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="vrf is immutable"
	VRF NetworkVRFName `json:"vrf,omitempty"`
	// +required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="prefix is immutable"
	Prefix NetworkPrefix `json:"prefix"`
	// +required
	// +listType=map
	// +listMapKey=address
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	NextHops []StaticRouteNextHop `json:"nextHops"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Switch",type=string,JSONPath=`.spec.switchRef.name`
// +kubebuilder:printcolumn:name="VRF",type=string,JSONPath=`.spec.vrf`
// +kubebuilder:printcolumn:name="Prefix",type=string,JSONPath=`.spec.prefix`
// +kubebuilder:printcolumn:name="Policy",type=string,JSONPath=`.spec.managementPolicy`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`,priority=1
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`,priority=1
// +kubebuilder:printcolumn:name="NextHops",type=string,JSONPath=`.spec.nextHops`,priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type SwitchStaticRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +required
	Spec SwitchStaticRouteSpec `json:"spec"`
	// +optional
	Status NetworkResourceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type SwitchStaticRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SwitchStaticRoute `json:"items"`
}
