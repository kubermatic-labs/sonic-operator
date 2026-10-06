// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// BufferName is a literal native buffer name, not a Kubernetes object reference.
// +kubebuilder:validation:MaxLength=32
// +kubebuilder:validation:Pattern=`^[A-Za-z0-9][-A-Za-z0-9_]{0,31}$`
type BufferName string

// SwitchBufferPoolSpec owns explicitly declared BUFFER_POOL fields.
// +kubebuilder:validation:XValidation:rule="!has(self.xoff) || (self.type == 'ingress' && self.xoff <= self.size)",message="shared headroom requires ingress pool and cannot exceed size"
type SwitchBufferPoolSpec struct {
	NetworkResourceSpec `json:",inline"`
	// +required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="name is immutable"
	Name BufferName `json:"name"`
	// +required
	// +kubebuilder:validation:Enum=ingress;egress
	Type string `json:"type"`
	// +required
	// +kubebuilder:validation:Enum=static;dynamic
	Mode string `json:"mode"`
	// Size is the pool size in bytes. Actual capacity requires native qualification.
	// +required
	// +kubebuilder:validation:Minimum=1
	// CEL retains the exact integer bound; OpenAPI maximum is float64 and rounds it.
	// +kubebuilder:validation:XValidation:rule="self <= 9223372036854775807",message="must fit a signed int64"
	Size *uint64 `json:"size"`
	// Xoff is shared headroom in bytes.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:XValidation:rule="self <= 9223372036854775807",message="must fit a signed int64"
	Xoff *uint64 `json:"xoff,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Switch",type=string,JSONPath=`.spec.switchRef.name`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
type SwitchBufferPool struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +required
	Spec SwitchBufferPoolSpec `json:"spec"`
	// +optional
	Status NetworkResourceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type SwitchBufferPoolList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SwitchBufferPool `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(GroupVersion, &SwitchBufferPool{}, &SwitchBufferPoolList{}, &SwitchBufferProfile{}, &SwitchBufferProfileList{}, &SwitchBufferPG{}, &SwitchBufferPGList{}, &SwitchBufferQueue{}, &SwitchBufferQueueList{})
		return nil
	})
}
