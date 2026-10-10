// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// SwitchBufferQueueSpec binds an egress profile to an exact native queue selector.
type SwitchBufferQueueSpec struct {
	NetworkResourceSpec `json:",inline"`
	// +required
	// +kubebuilder:validation:MaxLength=32
	// +kubebuilder:validation:Pattern=`^Ethernet(0|[1-9][0-9]*)$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="interfaceName is immutable"
	InterfaceName string `json:"interfaceName"`
	// Range preserves the native selector. Actual queue limits require device evidence.
	// +required
	// +kubebuilder:validation:MaxLength=7
	// +kubebuilder:validation:Pattern=`^(0|[1-9][0-9]{0,2})(-(0|[1-9][0-9]{0,2}))?$`
	// +kubebuilder:validation:XValidation:rule="self.split('-').all(n, int(n) <= 255)",message="queue schema ceiling is 255"
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
// +kubebuilder:printcolumn:name="Interface",type=string,JSONPath=`.spec.interfaceName`
// +kubebuilder:printcolumn:name="Range",type=string,JSONPath=`.spec.range`
// +kubebuilder:printcolumn:name="Profile",type=string,JSONPath=`.spec.profile`
// +kubebuilder:printcolumn:name="Policy",type=string,JSONPath=`.spec.managementPolicy`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`,priority=1
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`,priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type SwitchBufferQueue struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +required
	Spec SwitchBufferQueueSpec `json:"spec"`
	// +optional
	Status NetworkResourceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type SwitchBufferQueueList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SwitchBufferQueue `json:"items"`
}
