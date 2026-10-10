// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +kubebuilder:validation:XValidation:rule="!has(self.mode) || self.mode != 'Traditional' || ((!has(self.vrf) || self.vrf == 'default') && has(self.prefixes) && size(self.prefixes) == 1 && self.prefixes[0] == self.routerID + '/32')",message="Traditional requires default VRF and the router-ID /32 prefix"
type SwitchBGPSpec struct {
	NetworkResourceSpec `json:",inline"`
	// Mode selects the existing native backend; it never changes FRR mode.
	// Traditional supports the qualified peerless LeafRouter Loopback0 /32 contract.
	// +optional
	// +kubebuilder:default=Unified
	// +kubebuilder:validation:Enum=Unified;Traditional
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="backend mode is immutable"
	Mode string `json:"mode,omitempty"`
	// +optional
	// +kubebuilder:default=default
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="vrf is immutable"
	VRF NetworkVRFName `json:"vrf,omitempty"`
	// +required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4294967295
	// +kubebuilder:validation:Format=int64
	LocalASN uint32 `json:"localASN"`
	// +required
	// +kubebuilder:validation:MaxLength=15
	// +kubebuilder:validation:XValidation:rule="isIP(self) && ip(self).family() == 4",message="routerID must be IPv4"
	RouterID string `json:"routerID"`
	// Prefixes is an explicit allowlist; empty means no advertisements.
	// +optional
	// +kubebuilder:default={}
	// +listType=set
	// +kubebuilder:validation:MaxItems=256
	Prefixes []NetworkPrefix `json:"prefixes,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Switch",type=string,JSONPath=`.spec.switchRef.name`
// +kubebuilder:printcolumn:name="ASN",type=integer,JSONPath=`.spec.localASN`
// +kubebuilder:printcolumn:name="RouterID",type=string,JSONPath=`.spec.routerID`
// +kubebuilder:printcolumn:name="VRF",type=string,JSONPath=`.spec.vrf`
// +kubebuilder:printcolumn:name="Policy",type=string,JSONPath=`.spec.managementPolicy`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`,priority=1
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`,priority=1
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`,priority=1
// +kubebuilder:printcolumn:name="Prefixes",type=string,JSONPath=`.spec.prefixes`,priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type SwitchBGP struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +required
	Spec SwitchBGPSpec `json:"spec"`
	// +optional
	Status NetworkResourceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type SwitchBGPList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SwitchBGP `json:"items"`
}
