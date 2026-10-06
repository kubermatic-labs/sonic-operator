// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type QoSQueueBinding struct {
	// +required
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=4294967295
	// +kubebuilder:validation:Format=int64
	Index uint32 `json:"index"`
	// +required
	Scheduler QoSPolicyName `json:"scheduler"`
}

// SwitchQoSBindingSpec references existing, applied maps and schedulers on one data port.
// +kubebuilder:validation:XValidation:rule="has(self.dscpToTC) || has(self.dot1pToTC) || has(self.tcToQueue) || (has(self.queues) && size(self.queues) > 0)",message="at least one map or queue binding is required"
type SwitchQoSBindingSpec struct {
	NetworkResourceSpec `json:",inline"`
	// +required
	// +kubebuilder:validation:MaxLength=32
	// +kubebuilder:validation:Pattern=`^Ethernet(0|[1-9][0-9]*)$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="interfaceName is immutable"
	InterfaceName string `json:"interfaceName"`
	// +optional
	DSCPToTC QoSPolicyName `json:"dscpToTC,omitempty"`
	// +optional
	Dot1pToTC QoSPolicyName `json:"dot1pToTC,omitempty"`
	// +optional
	TCToQueue QoSPolicyName `json:"tcToQueue,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxItems=256
	// +listType=map
	// +listMapKey=index
	Queues []QoSQueueBinding `json:"queues,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Switch",type=string,JSONPath=`.spec.switchRef.name`
// +kubebuilder:printcolumn:name="Policy",type=string,JSONPath=`.spec.managementPolicy`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
type SwitchQoSBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +required
	Spec SwitchQoSBindingSpec `json:"spec"`
	// +optional
	Status NetworkResourceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type SwitchQoSBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SwitchQoSBinding `json:"items"`
}
