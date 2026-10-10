// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// SwitchSchedulerSpec configures scheduling and optional shaping, not policing.
// Rates are bytes/second or packets/second according to meterType; bursts use the same unit.
// +kubebuilder:validation:XValidation:rule="self.algorithm == 'STRICT' ? !has(self.weight) : has(self.weight)",message="STRICT forbids weight; WRR and DWRR require weight"
// +kubebuilder:validation:XValidation:rule="!has(self.peakRate) || (has(self.committedRate) && self.peakRate >= self.committedRate)",message="peakRate requires committedRate and must be >= committedRate"
// +kubebuilder:validation:XValidation:rule="!has(self.committedBurst) || has(self.committedRate)",message="committedBurst requires committedRate"
// +kubebuilder:validation:XValidation:rule="!has(self.peakBurst) || has(self.peakRate)",message="peakBurst requires peakRate"
// +kubebuilder:validation:XValidation:rule="!has(self.committedBurst) || !has(self.peakBurst) || self.peakBurst >= self.committedBurst",message="peakBurst must be >= committedBurst"
type SwitchSchedulerSpec struct {
	NetworkResourceSpec `json:",inline"`
	// +required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="name is immutable"
	Name QoSPolicyName `json:"name"`
	// +required
	// +kubebuilder:validation:Enum=STRICT;WRR;DWRR
	Algorithm string `json:"algorithm"`
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	Weight *uint32 `json:"weight,omitempty"`
	// +optional
	// +kubebuilder:default=Bytes
	// +kubebuilder:validation:Enum=Bytes;Packets
	MeterType string `json:"meterType,omitempty"`
	// +optional
	// +kubebuilder:validation:Minimum=1
	// CEL retains the exact integer bound; OpenAPI maximum is float64 and rounds it.
	// +kubebuilder:validation:XValidation:rule="self <= 9223372036854775807",message="must fit a signed int64"
	// +kubebuilder:validation:Format=int64
	CommittedRate *uint64 `json:"committedRate,omitempty"`
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:XValidation:rule="self <= 9223372036854775807",message="must fit a signed int64"
	// +kubebuilder:validation:Format=int64
	PeakRate *uint64 `json:"peakRate,omitempty"`
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:XValidation:rule="self <= 9223372036854775807",message="must fit a signed int64"
	// +kubebuilder:validation:Format=int64
	CommittedBurst *uint64 `json:"committedBurst,omitempty"`
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:XValidation:rule="self <= 9223372036854775807",message="must fit a signed int64"
	// +kubebuilder:validation:Format=int64
	PeakBurst *uint64 `json:"peakBurst,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Switch",type=string,JSONPath=`.spec.switchRef.name`
// +kubebuilder:printcolumn:name="Scheduler",type=string,JSONPath=`.spec.name`
// +kubebuilder:printcolumn:name="Algorithm",type=string,JSONPath=`.spec.algorithm`
// +kubebuilder:printcolumn:name="Weight",type=integer,JSONPath=`.spec.weight`
// +kubebuilder:printcolumn:name="Policy",type=string,JSONPath=`.spec.managementPolicy`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`,priority=1
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`,priority=1
// +kubebuilder:printcolumn:name="Meter",type=string,JSONPath=`.spec.meterType`,priority=1
// +kubebuilder:printcolumn:name="CIR",type=integer,JSONPath=`.spec.committedRate`,priority=1
// +kubebuilder:printcolumn:name="PIR",type=integer,JSONPath=`.spec.peakRate`,priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type SwitchScheduler struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +required
	Spec SwitchSchedulerSpec `json:"spec"`
	// +optional
	Status NetworkResourceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type SwitchSchedulerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SwitchScheduler `json:"items"`
}
