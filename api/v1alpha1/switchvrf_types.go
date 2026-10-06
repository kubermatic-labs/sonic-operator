// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type SwitchVRFSpec struct {
	NetworkResourceSpec `json:",inline"`
	// +required
	// +kubebuilder:validation:MaxLength=15
	// +kubebuilder:validation:Pattern=`^Vrf[A-Za-z0-9_-]{1,12}$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="name is immutable"
	Name string `json:"name"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Switch",type=string,JSONPath=`.spec.switchRef.name`
// +kubebuilder:printcolumn:name="Policy",type=string,JSONPath=`.spec.managementPolicy`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// SwitchVRF manages a non-management VRF without a VNI.
type SwitchVRF struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +required
	Spec SwitchVRFSpec `json:"spec"`
	// +optional
	Status NetworkResourceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type SwitchVRFList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SwitchVRF `json:"items"`
}
