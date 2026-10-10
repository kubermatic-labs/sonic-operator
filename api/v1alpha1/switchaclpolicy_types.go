// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// TrafficPolicyName is a SONiC policy identifier, never a CONFIG_DB key.
// +kubebuilder:validation:MaxLength=64
// +kubebuilder:validation:Pattern=`^[A-Za-z][A-Za-z0-9_-]{0,63}$`
type TrafficPolicyName string

// +kubebuilder:validation:Enum=Permit;Drop
type ACLAction string

// ACLRule matches one IP family. Ports require an explicit TCP or UDP protocol.
// +kubebuilder:validation:XValidation:rule="(!has(self.sourcePort) && !has(self.destinationPort)) || (has(self.protocol) && self.protocol in [6, 17])",message="ports require TCP (6) or UDP (17)"
type ACLRule struct {
	// +required
	// +kubebuilder:validation:XValidation:rule="self != 'DEFAULT'",message="DEFAULT is reserved for the catchall rule"
	Name TrafficPolicyName `json:"name"`
	// +required
	// +kubebuilder:validation:Minimum=2
	// +kubebuilder:validation:Maximum=999999
	Priority uint32 `json:"priority"`
	// +required
	Action ACLAction `json:"action"`
	// +optional
	Source NetworkPrefix `json:"source,omitempty"`
	// +optional
	Destination NetworkPrefix `json:"destination,omitempty"`
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=143
	Protocol *uint32 `json:"protocol,omitempty"`
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	SourcePort *uint32 `json:"sourcePort,omitempty"`
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	DestinationPort *uint32 `json:"destinationPort,omitempty"`
}

// SwitchACLPolicySpec stages an unbound ingress table with an explicit priority-1 catchall.
// +kubebuilder:validation:XValidation:rule="self.rules.all(r, !has(r.source) || (isCIDR(r.source) && cidr(r.source).ip().family() == (self.family == 'IPv4' ? 4 : 6)))",message="source must match policy family"
// +kubebuilder:validation:XValidation:rule="self.rules.all(r, !has(r.destination) || (isCIDR(r.destination) && cidr(r.destination).ip().family() == (self.family == 'IPv4' ? 4 : 6)))",message="destination must match policy family"
type SwitchACLPolicySpec struct {
	NetworkResourceSpec `json:",inline"`
	// +required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="name is immutable"
	Name TrafficPolicyName `json:"name"`
	// +required
	// +kubebuilder:validation:Enum=IPv4;IPv6
	Family string `json:"family"`
	// +required
	DefaultAction ACLAction `json:"defaultAction"`
	// +required
	// +kubebuilder:validation:MaxItems=256
	// +kubebuilder:validation:XValidation:rule="self.all(r, self.exists_one(other, other.priority == r.priority))",message="rule priorities must be unique"
	// +listType=map
	// +listMapKey=name
	Rules []ACLRule `json:"rules"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Switch",type=string,JSONPath=`.spec.switchRef.name`
// +kubebuilder:printcolumn:name="ACL",type=string,JSONPath=`.spec.name`
// +kubebuilder:printcolumn:name="Family",type=string,JSONPath=`.spec.family`
// +kubebuilder:printcolumn:name="Default",type=string,JSONPath=`.spec.defaultAction`
// +kubebuilder:printcolumn:name="Policy",type=string,JSONPath=`.spec.managementPolicy`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`,priority=1
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`,priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type SwitchACLPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +required
	Spec SwitchACLPolicySpec `json:"spec"`
	// +optional
	Status NetworkResourceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type SwitchACLPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SwitchACLPolicy `json:"items"`
}
