// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// SwitchBufferProfileSpec owns BUFFER_PROFILE fields. Threshold mode must match the pool.
// +kubebuilder:validation:XValidation:rule="has(self.dynamicThreshold) != has(self.staticThreshold)",message="exactly one threshold is required"
type SwitchBufferProfileSpec struct {
	NetworkResourceSpec `json:",inline"`
	// +required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="name is immutable"
	Name BufferName `json:"name"`
	// +required
	Pool BufferName `json:"pool"`
	// Size is reserved buffer bytes, including an explicit zero.
	// +required
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:XValidation:rule="self <= 9223372036854775807",message="must fit a signed int64"
	Size *uint64 `json:"size"`
	// +optional
	// +kubebuilder:validation:Minimum=-8
	// +kubebuilder:validation:Maximum=7
	DynamicThreshold *int32 `json:"dynamicThreshold,omitempty"`
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:XValidation:rule="self <= 9223372036854775807",message="must fit a signed int64"
	StaticThreshold *uint64 `json:"staticThreshold,omitempty"`
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:XValidation:rule="self <= 9223372036854775807",message="must fit a signed int64"
	Xon *uint64 `json:"xon,omitempty"`
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:XValidation:rule="self <= 9223372036854775807",message="must fit a signed int64"
	Xoff *uint64 `json:"xoff,omitempty"`
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:XValidation:rule="self <= 9223372036854775807",message="must fit a signed int64"
	XonOffset *uint64 `json:"xonOffset,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Switch",type=string,JSONPath=`.spec.switchRef.name`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
type SwitchBufferProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +required
	Spec SwitchBufferProfileSpec `json:"spec"`
	// +optional
	Status NetworkResourceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type SwitchBufferProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SwitchBufferProfile `json:"items"`
}
