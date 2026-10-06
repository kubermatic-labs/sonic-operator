// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +kubebuilder:validation:XValidation:rule="(has(self.ipv4Servers) && size(self.ipv4Servers) > 0) || (has(self.ipv6Servers) && size(self.ipv6Servers) > 0)",message="at least one relay server is required; discovery and removal are unsupported"
type SwitchDHCPRelaySpec struct {
	NetworkResourceSpec `json:",inline"`
	// +required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4094
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="vlanID is immutable"
	VLANID uint32 `json:"vlanID"`
	// +optional
	// +kubebuilder:default=default
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="vrf binding is immutable"
	VRF NetworkVRFName `json:"vrf,omitempty"`
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:items:MaxLength=15
	// +kubebuilder:validation:XValidation:rule="self.all(a, isIP(a) && ip(a).family() == 4)",message="ipv4Servers must contain IPv4 addresses"
	IPv4Servers []string `json:"ipv4Servers,omitempty"`
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:items:MaxLength=45
	// +kubebuilder:validation:XValidation:rule="self.all(a, isIP(a) && ip(a).family() == 6)",message="ipv6Servers must contain IPv6 addresses"
	IPv6Servers []string `json:"ipv6Servers,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Switch",type=string,JSONPath=`.spec.switchRef.name`
// +kubebuilder:printcolumn:name="Policy",type=string,JSONPath=`.spec.managementPolicy`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
type SwitchDHCPRelay struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +required
	Spec SwitchDHCPRelaySpec `json:"spec"`
	// +optional
	Status NetworkResourceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type SwitchDHCPRelayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SwitchDHCPRelay `json:"items"`
}
