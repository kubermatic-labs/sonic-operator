// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// SwitchBufferPGSpec binds an ingress profile to an exact native PG selector.
type SwitchBufferPGSpec struct {
	NetworkResourceSpec `json:",inline"`
	// +required
	// +kubebuilder:validation:MaxLength=32
	// +kubebuilder:validation:Pattern=`^Ethernet(0|[1-9][0-9]*)$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="interfaceName is immutable"
	InterfaceName string `json:"interfaceName"`
	// Range is one index or an inclusive ascending range, e.g. 3-4.
	// +required
	// +kubebuilder:validation:MaxLength=3
	// +kubebuilder:validation:Pattern=`^[0-7](-[0-7])?$`
	// +kubebuilder:validation:XValidation:rule="!self.contains('-') || int(self.split('-')[0]) < int(self.split('-')[1])",message="range must be ascending and nonredundant"
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="range is immutable"
	Range string `json:"range"`
	// +required
	Profile BufferName `json:"profile"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Switch",type=string,JSONPath=`.spec.switchRef.name`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
type SwitchBufferPG struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +required
	Spec SwitchBufferPGSpec `json:"spec"`
	// +optional
	Status NetworkResourceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type SwitchBufferPGList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SwitchBufferPG `json:"items"`
}
