// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +kubebuilder:validation:XValidation:rule="!has(self.localAddress) || ip(self.localAddress).family() == ip(self.address).family()",message="localAddress must match the peer address family"
type SwitchBGPPeerSpec struct {
	NetworkResourceSpec `json:",inline"`
	// +optional
	// +kubebuilder:default=default
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="vrf is immutable"
	VRF NetworkVRFName `json:"vrf,omitempty"`
	// +required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="address is immutable"
	Address NetworkIP `json:"address"`
	// +required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4294967295
	// +kubebuilder:validation:Format=int64
	RemoteASN uint32 `json:"remoteASN"`
	// +optional
	LocalAddress NetworkIP `json:"localAddress,omitempty"`
	// +required
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=2
	// +kubebuilder:validation:items:Enum=ipv4Unicast;ipv6Unicast
	AddressFamilies []string `json:"addressFamilies"`
	// +optional
	// +kubebuilder:default=Down
	// +kubebuilder:validation:Enum=Up;Down
	AdminState AdminState `json:"adminState,omitempty"`
	// +optional
	// +kubebuilder:default=1000
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4294967295
	// +kubebuilder:validation:Format=int64
	MaxPrefixes uint32 `json:"maxPrefixes,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Switch",type=string,JSONPath=`.spec.switchRef.name`
// +kubebuilder:printcolumn:name="Peer",type=string,JSONPath=`.spec.address`
// +kubebuilder:printcolumn:name="RemoteASN",type=integer,JSONPath=`.spec.remoteASN`
// +kubebuilder:printcolumn:name="VRF",type=string,JSONPath=`.spec.vrf`
// +kubebuilder:printcolumn:name="Admin",type=string,JSONPath=`.spec.adminState`
// +kubebuilder:printcolumn:name="Policy",type=string,JSONPath=`.spec.managementPolicy`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`,priority=1
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`,priority=1
// +kubebuilder:printcolumn:name="LocalAddress",type=string,JSONPath=`.spec.localAddress`,priority=1
// +kubebuilder:printcolumn:name="Families",type=string,JSONPath=`.spec.addressFamilies`,priority=1
// +kubebuilder:printcolumn:name="MaxPrefixes",type=integer,JSONPath=`.spec.maxPrefixes`,priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type SwitchBGPPeer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +required
	Spec SwitchBGPPeerSpec `json:"spec"`
	// +optional
	Status NetworkResourceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type SwitchBGPPeerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SwitchBGPPeer `json:"items"`
}
