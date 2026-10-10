// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// SwitchPortChannelSpec requests an additive LACP port channel.
// +kubebuilder:validation:XValidation:rule="!has(self.minLinks) || self.minLinks <= size(self.members)",message="minLinks must not exceed the member count"
type SwitchPortChannelSpec struct {
	NetworkResourceSpec `json:",inline"`
	// +required
	// +kubebuilder:validation:MaxLength=15
	// +kubebuilder:validation:Pattern=`^PortChannel(0|[1-9][0-9]{0,3})$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="name is immutable"
	Name string `json:"name"`
	// +required
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=256
	// +kubebuilder:validation:items:MaxLength=32
	// +kubebuilder:validation:items:Pattern=`^Ethernet(0|[1-9][0-9]*)$`
	Members []string `json:"members"`
	// +optional
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=256
	MinLinks uint32 `json:"minLinks,omitempty"`
	// +optional
	// +kubebuilder:default=active
	// +kubebuilder:validation:Enum=active
	LACPMode string `json:"lacpMode,omitempty"`
	// +optional
	// +kubebuilder:default=false
	FastRate bool `json:"fastRate,omitempty"`
	// +optional
	// +kubebuilder:default=9100
	// +kubebuilder:validation:Minimum=1280
	// +kubebuilder:validation:Maximum=9216
	MTU uint32 `json:"mtu,omitempty"`
	// +optional
	// +kubebuilder:default=Up
	// +kubebuilder:validation:Enum=Up;Down
	AdminState AdminState `json:"adminState,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Switch",type=string,JSONPath=`.spec.switchRef.name`
// +kubebuilder:printcolumn:name="PortChannel",type=string,JSONPath=`.spec.name`
// +kubebuilder:printcolumn:name="Admin",type=string,JSONPath=`.spec.adminState`
// +kubebuilder:printcolumn:name="Policy",type=string,JSONPath=`.spec.managementPolicy`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`,priority=1
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`,priority=1
// +kubebuilder:printcolumn:name="Members",type=string,JSONPath=`.spec.members`,priority=1
// +kubebuilder:printcolumn:name="MinLinks",type=integer,JSONPath=`.spec.minLinks`,priority=1
// +kubebuilder:printcolumn:name="MTU",type=integer,JSONPath=`.spec.mtu`,priority=1
// +kubebuilder:printcolumn:name="FastRate",type=boolean,JSONPath=`.spec.fastRate`,priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// SwitchPortChannel leaves device configuration intact on deletion.
type SwitchPortChannel struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +required
	Spec SwitchPortChannelSpec `json:"spec"`
	// +optional
	Status NetworkResourceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type SwitchPortChannelList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SwitchPortChannel `json:"items"`
}
