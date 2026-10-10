// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// QoSPolicyName is the native map or scheduler identifier.
// +kubebuilder:validation:MaxLength=32
// +kubebuilder:validation:Pattern=`^[A-Za-z0-9][-A-Za-z0-9_]{0,31}$`
type QoSPolicyName string

type QoSMapEntry struct {
	// +required
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=4294967295
	// +kubebuilder:validation:Format=int64
	From uint32 `json:"from"`
	// +required
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=4294967295
	// +kubebuilder:validation:Format=int64
	To uint32 `json:"to"`
}

// SwitchQoSMapSpec defines a map; actual TC and queue bounds require device capabilities.
// +kubebuilder:validation:XValidation:rule="self.entries.all(e, self.type == 'DSCPToTC' ? e.from <= 63 : (self.type == 'Dot1pToTC' ? e.from <= 7 : true))",message="DSCP inputs must be 0..63 and dot1p inputs 0..7"
// +kubebuilder:validation:XValidation:rule="self.type != 'TCToPriorityGroup' || self.entries.all(e, e.from <= 15 && e.to <= 7)",message="TC-to-PG schema ceilings are TC 15 and PG 7; hardware bounds require native evidence"
type SwitchQoSMapSpec struct {
	NetworkResourceSpec `json:",inline"`
	// +required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="name is immutable"
	Name QoSPolicyName `json:"name"`
	// +required
	// +kubebuilder:validation:Enum=DSCPToTC;Dot1pToTC;TCToQueue;TCToPriorityGroup
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="type is immutable"
	Type string `json:"type"`
	// +required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=256
	// +listType=map
	// +listMapKey=from
	Entries []QoSMapEntry `json:"entries"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Switch",type=string,JSONPath=`.spec.switchRef.name`
// +kubebuilder:printcolumn:name="Map",type=string,JSONPath=`.spec.name`
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.type`
// +kubebuilder:printcolumn:name="Policy",type=string,JSONPath=`.spec.managementPolicy`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`,priority=1
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`,priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type SwitchQoSMap struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +required
	Spec SwitchQoSMapSpec `json:"spec"`
	// +optional
	Status NetworkResourceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type SwitchQoSMapList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SwitchQoSMap `json:"items"`
}
