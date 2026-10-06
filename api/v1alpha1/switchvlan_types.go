// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// VLANManagementPolicy controls whether VLAN configuration may be changed.
// +kubebuilder:validation:Enum=Observe;Manage
type VLANManagementPolicy string

const (
	VLANManagementPolicyObserve VLANManagementPolicy = "Observe"
	VLANManagementPolicyManage  VLANManagementPolicy = "Manage"
)

// VLANReconcilePolicy selects additive assertions or entire VLAN membership.
// +kubebuilder:validation:Enum=Additive;Authoritative
type VLANReconcilePolicy string

const (
	VLANReconcilePolicyAdditive      VLANReconcilePolicy = "Additive"
	VLANReconcilePolicyAuthoritative VLANReconcilePolicy = "Authoritative"
)

// VLANDeletionPolicy selects release-only or guarded deletion for owned VLANs.
// +kubebuilder:validation:Enum=Orphan;Delete
type VLANDeletionPolicy string

const (
	VLANDeletionPolicyOrphan VLANDeletionPolicy = "Orphan"
	VLANDeletionPolicyDelete VLANDeletionPolicy = "Delete"
)

// SwitchVLANReference identifies the cluster-scoped Switch to configure.
type SwitchVLANReference struct {
	// Name is the name of an existing Switch.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

// SwitchVLANMember declares a Layer-2 membership.
type SwitchVLANMember struct {
	// InterfaceName is the canonical SONiC Ethernet or PortChannel name, not an alias.
	// +required
	// +kubebuilder:validation:Pattern=`^(Ethernet(0|[1-9][0-9]*)|PortChannel(0|[1-9][0-9]{0,3}))$`
	InterfaceName string `json:"interfaceName"`
	// TaggingMode can replace an existing mode only under Authoritative policy.
	// +required
	// +kubebuilder:validation:Enum=tagged;untagged
	TaggingMode string `json:"taggingMode"`
}

// SwitchVLANSpec declares a VLAN and the members that must exist.
type SwitchVLANSpec struct {
	// SwitchRef is immutable. Only one CR may claim a switch/VLAN pair.
	// +required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="switchRef is immutable"
	SwitchRef SwitchVLANReference `json:"switchRef"`
	// VLANID is immutable and excludes reserved VLAN IDs.
	// +required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4094
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="vlanID is immutable"
	VLANID uint32 `json:"vlanID"`
	// ManagementPolicy defaults to observation. Manage also requires both the
	// controller's observe-only gate and the agent's read-only gate to be disabled.
	// +optional
	// +kubebuilder:default=Observe
	ManagementPolicy VLANManagementPolicy `json:"managementPolicy,omitempty"`
	// ReconcilePolicy defaults to Additive. Authoritative owns the entire VLAN
	// membership, pruning omitted members and replacing tagging modes.
	// +optional
	// +kubebuilder:default=Additive
	ReconcilePolicy VLANReconcilePolicy `json:"reconcilePolicy,omitempty"`
	// DeletionPolicy defaults to Orphan. Delete applies only to agent-confirmed
	// ownership by this CR UID, with all authoritative write gates enabled.
	// +optional
	// +kubebuilder:default=Orphan
	DeletionPolicy VLANDeletionPolicy `json:"deletionPolicy,omitempty"`
	// AdoptionDigest approves the exact agent snapshot for first takeover of an
	// existing VLAN. Review status.adoptionDigest; newly created VLANs need none.
	// +optional
	// +kubebuilder:validation:Pattern=`^[a-f0-9]{64}$`
	AdoptionDigest string `json:"adoptionDigest,omitempty"`
	// Members are additive by default, or the complete set under Authoritative.
	// +optional
	// +listType=map
	// +listMapKey=interfaceName
	Members []SwitchVLANMember `json:"members,omitempty"`
}

// SwitchVLANObservedMember includes unmanaged members, which may use interface
// names outside the Ethernet/PortChannel scope allowed in spec.
type SwitchVLANObservedMember struct {
	InterfaceName string `json:"interfaceName"`
	TaggingMode   string `json:"taggingMode"`
}

// SwitchVLANStatus reports configuration, not dataplane or forwarding health.
type SwitchVLANStatus struct {
	// ObservedGeneration is the generation last attempted by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// AdoptionDigest is the latest agent snapshot digest for explicit review.
	// +optional
	AdoptionDigest string `json:"adoptionDigest,omitempty"`
	// OwnerID is the last confirmed agent owner UID, never a grant of ownership.
	// +optional
	OwnerID string `json:"ownerID,omitempty"`
	// TargetIdentity binds ownership to the Switch UID and explicit endpoint.
	// +optional
	TargetIdentity string `json:"targetIdentity,omitempty"`
	// RuntimeVerified confirms CONFIG_DB only, not ASIC state or forwarding.
	// +optional
	RuntimeVerified bool `json:"runtimeVerified,omitempty"`
	// PersistenceVerified confirms the agent's durable configuration save.
	// +optional
	PersistenceVerified bool `json:"persistenceVerified,omitempty"`
	// Exists is unset when existence could not be determined in this attempt.
	// +optional
	Exists *bool `json:"exists,omitempty"`
	// Members is the latest successful observation, including unmanaged members.
	// +optional
	// +listType=map
	// +listMapKey=interfaceName
	Members []SwitchVLANObservedMember `json:"members,omitempty"`
	// Ready and Synced are true only after confirming the requested configuration.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Switch",type=string,JSONPath=`.spec.switchRef.name`
// +kubebuilder:printcolumn:name="VLAN",type=integer,JSONPath=`.spec.vlanID`
// +kubebuilder:printcolumn:name="Policy",type=string,JSONPath=`.spec.managementPolicy`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// SwitchVLAN manages Layer-2 VLAN configuration. Additive is the safe default;
// authoritative ownership requires explicit gates and a cleanup finalizer.
type SwitchVLAN struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +required
	Spec SwitchVLANSpec `json:"spec"`
	// +optional
	Status SwitchVLANStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SwitchVLANList contains a list of SwitchVLAN resources.
type SwitchVLANList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SwitchVLAN `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(GroupVersion, &SwitchVLAN{}, &SwitchVLANList{})
		return nil
	})
}
