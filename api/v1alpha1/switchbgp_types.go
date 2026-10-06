// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type SwitchBGPSpec struct {
	NetworkResourceSpec `json:",inline"`
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
// +kubebuilder:printcolumn:name="Policy",type=string,JSONPath=`.spec.managementPolicy`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
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
