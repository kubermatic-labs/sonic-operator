// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type SwitchFRRMigrationSpec struct {
	NetworkResourceSpec `json:",inline"`
	// Mode selects the target framework for an empty-routing switch. Change mode
	// on the same resource; each transition requires a fresh approved preflight.
	// Traditional explicitly sets false/separated metadata, rather than restoring absent fields.
	// +required
	// +kubebuilder:validation:Enum=Traditional;Unified
	Mode string `json:"mode"`
	// ApprovedDigest approves exactly the snapshot published as observed.adoptionDigest.
	// Omit it for read-only preflight. A new Ensure requires a matching digest.
	// +optional
	// +kubebuilder:validation:Pattern=`^[a-f0-9]{64}$`
	// +kubebuilder:validation:MaxLength=64
	ApprovedDigest string `json:"approvedDigest,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Switch",type=string,JSONPath=`.spec.switchRef.name`
// +kubebuilder:printcolumn:name="Policy",type=string,JSONPath=`.spec.managementPolicy`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// SwitchFRRMigration migrates empty routing between traditional bgpcfgd and unified frrcfgd.
// Deletion orphans the framework after any pending journal operation is recovered.
type SwitchFRRMigration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +required
	Spec SwitchFRRMigrationSpec `json:"spec"`
	// +optional
	Status NetworkResourceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type SwitchFRRMigrationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SwitchFRRMigration `json:"items"`
}
