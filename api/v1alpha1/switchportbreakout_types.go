// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// BreakoutManagementPolicy controls whether a port layout may be changed.
// +kubebuilder:validation:Enum=Observe;Manage
type BreakoutManagementPolicy string

const (
	BreakoutManagementPolicyObserve BreakoutManagementPolicy = "Observe"
	BreakoutManagementPolicyManage  BreakoutManagementPolicy = "Manage"
)

// SwitchPortBreakoutReference identifies a cluster-scoped Switch.
type SwitchPortBreakoutReference struct {
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

// SwitchPortBreakoutSpec requests an exact platform-supported port layout.
type SwitchPortBreakoutSpec struct {
	// SwitchRef is immutable. Target UID and endpoint are bound before writes.
	// +required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="switchRef is immutable"
	SwitchRef SwitchPortBreakoutReference `json:"switchRef"`
	// Port is the immutable canonical native parent, not an alias or handle.
	// +required
	// +kubebuilder:validation:Pattern=`^Ethernet(0|[1-9][0-9]*)$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="port is immutable"
	Port string `json:"port"`
	// Mode must exactly match one of status.supportedModes.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	Mode string `json:"mode"`
	// Manage also requires both manager and agent write gates.
	// +optional
	// +kubebuilder:default=Observe
	ManagementPolicy BreakoutManagementPolicy `json:"managementPolicy,omitempty"`
	// ChildAdminState seeds only newly created device children. Existing
	// SwitchInterface desired state and unaffected device attributes are retained.
	// +optional
	// +kubebuilder:default=Down
	// +kubebuilder:validation:Enum=Up;Down
	ChildAdminState AdminState `json:"childAdminState,omitempty"`
}

// SwitchPortBreakoutChild is an observed native child, independent of agent types.
type SwitchPortBreakoutChild struct {
	Name       string     `json:"name"`
	Lanes      string     `json:"lanes"`
	Speed      string     `json:"speed"`
	AdminState AdminState `json:"adminState"`
	MTU        string     `json:"mtu"`
}

// SwitchPortBreakoutStatus reports configuration, runtime and save proof, not
// carrier or forwarding health. Failed mutations never authorize inventory pruning.
type SwitchPortBreakoutStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// TargetIdentity mirrors the durable metadata binding; it is not authority.
	// +optional
	TargetIdentity string `json:"targetIdentity,omitempty"`
	// Mode is the latest observed CONFIG_DB mode, not necessarily the desired mode.
	// +optional
	Mode string `json:"mode,omitempty"`
	// +optional
	// +listType=set
	SupportedModes []string `json:"supportedModes,omitempty"`
	// +optional
	// +listType=map
	// +listMapKey=name
	Children []SwitchPortBreakoutChild `json:"children,omitempty"`
	// PreviousChildren retains the pre-operation inventory across interrupted
	// attempts. Only a subsequent confirmed operation can authorize its cleanup.
	// +optional
	// +listType=map
	// +listMapKey=name
	PreviousChildren []SwitchPortBreakoutChild `json:"previousChildren,omitempty"`
	// +optional
	ConfigurationVerified bool `json:"configurationVerified,omitempty"`
	// RuntimeVerified confirms APPL_DB and kernel layout, not cable/link health.
	// +optional
	RuntimeVerified bool `json:"runtimeVerified,omitempty"`
	// +optional
	PersistenceVerified bool `json:"persistenceVerified,omitempty"`
	// Pending indicates an unresolved operation; recovery must not blindly rerun CLI.
	// +optional
	Pending bool `json:"pending,omitempty"`
	// +optional
	Message string `json:"message,omitempty"`
	// Ready, ConfigurationReady, RuntimeReady, PersistenceReady and Progressing
	// describe this generation independently.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Switch",type=string,JSONPath=`.spec.switchRef.name`
// +kubebuilder:printcolumn:name="Port",type=string,JSONPath=`.spec.port`
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.status.mode`
// +kubebuilder:printcolumn:name="Policy",type=string,JSONPath=`.spec.managementPolicy`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// SwitchPortBreakout manages a parent port layout. Deletion leaves hardware
// unchanged; this resource deliberately has no device-cleanup finalizer.
type SwitchPortBreakout struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +required
	Spec SwitchPortBreakoutSpec `json:"spec"`
	// +optional
	Status SwitchPortBreakoutStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SwitchPortBreakoutList contains breakout claims.
type SwitchPortBreakoutList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SwitchPortBreakout `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(GroupVersion, &SwitchPortBreakout{}, &SwitchPortBreakoutList{})
		return nil
	})
}
