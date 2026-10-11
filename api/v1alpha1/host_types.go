// SPDX-License-Identifier: Apache-2.0
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type ManagementAddress struct {
	// +required
	Prefix NetworkInterfaceAddress `json:"prefix"`
	// Gateway is on-link and of the same address family as Prefix.
	// +optional
	Gateway NetworkIP `json:"gateway,omitempty"`
}
type SwitchManagementSpec struct {
	NetworkResourceSpec `json:",inline"`
	// +kubebuilder:default=eth0
	// +kubebuilder:validation:Enum=eth0
	Interface string `json:"interface,omitempty"`
	// +required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=8
	// +listType=map
	// +listMapKey=prefix
	Addresses []ManagementAddress `json:"addresses"`
	// MAC overrides only eth0; device/base/front-panel MACs are never changed.
	// Omission leaves the active and boot MAC configuration unowned.
	// +optional
	// +kubebuilder:validation:Pattern=`^([0-9a-f]{2}:){5}[0-9a-f]{2}$`
	MAC string `json:"mac,omitempty"`
	// +kubebuilder:default=120
	// +kubebuilder:validation:Minimum=30
	// +kubebuilder:validation:Maximum=600
	RollbackSeconds int `json:"rollbackSeconds,omitempty"`
}

type HostSecretKeyReference struct {
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Namespace string `json:"namespace"`
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Key string `json:"key"`
}
type SystemNTP struct {
	// +kubebuilder:default=enabled
	// +kubebuilder:validation:Enum=enabled;disabled
	AdminState string `json:"adminState,omitempty"`
	// +kubebuilder:default=enabled
	// +kubebuilder:validation:Enum=enabled;disabled
	DHCP string `json:"dhcp,omitempty"`
	// +kubebuilder:default=disabled
	// +kubebuilder:validation:Enum=enabled;disabled
	ServerRole string `json:"serverRole,omitempty"`
	// +kubebuilder:default=eth0
	// +kubebuilder:validation:Enum=eth0
	SourceInterface string `json:"sourceInterface,omitempty"`
	// Servers owns the configured NTP_SERVER membership. Empty removes all
	// configured servers; DHCP/vendor-generated sources remain separately checked.
	// +required
	// +kubebuilder:validation:MaxItems=16
	// +listType=set
	Servers []string `json:"servers"`
	// MakeStep lets chronyd step the clock instead of slewing it when the offset
	// exceeds ThresholdSeconds during its first Limit clock updates after start.
	// Use it on platforms whose RTC cannot be read at boot. Omission removes the
	// operator-owned drop-in. Supported only by the chrony backend.
	// +optional
	MakeStep *NTPMakeStep `json:"makeStep,omitempty"`
}

type NTPMakeStep struct {
	// +required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=86400
	ThresholdSeconds int `json:"thresholdSeconds"`
	// +required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10
	Limit int `json:"limit"`
}
type SystemSNMP struct {
	// +kubebuilder:validation:MaxLength=256
	Location string `json:"location"`
	// +kubebuilder:validation:MaxLength=256
	// Empty Contact leaves the native contact input unowned.
	Contact string `json:"contact,omitempty"`
	// CommunitySecretRef supplies the sole read-only community. Omission declares
	// no communities. Plaintext is never allowed in this resource.
	// +optional
	CommunitySecretRef *HostSecretKeyReference `json:"communitySecretRef,omitempty"`
	// Users owns the complete set of read-only SNMPv3 USM users. Omission or an
	// empty list declares no users. Passwords are referenced, never inlined.
	// +optional
	// +kubebuilder:validation:MaxItems=8
	// +listType=map
	// +listMapKey=name
	Users []SystemSNMPUser `json:"users,omitempty"`
}

// SystemSNMPUser is a read-only SNMPv3 user with authentication and, by
// default, privacy.
// +kubebuilder:validation:XValidation:rule="self.securityLevel != 'authPriv' || has(self.privPasswordSecretRef)",message="authPriv requires privPasswordSecretRef"
// +kubebuilder:validation:XValidation:rule="self.securityLevel != 'authNoPriv' || (!has(self.privPasswordSecretRef) && !has(self.privProtocol))",message="authNoPriv must not declare privacy settings"
type SystemSNMPUser struct {
	// Name is the USM user (security) name.
	// +required
	// +kubebuilder:validation:MinLength=4
	// +kubebuilder:validation:MaxLength=32
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9._-]+$`
	Name string `json:"name"`
	// +kubebuilder:default=authPriv
	// +kubebuilder:validation:Enum=authNoPriv;authPriv
	SecurityLevel string `json:"securityLevel,omitempty"`
	// +kubebuilder:default=SHA
	// +kubebuilder:validation:Enum=SHA
	AuthProtocol string `json:"authProtocol,omitempty"`
	// AuthPasswordSecretRef supplies the authentication passphrase: 8 to 64
	// printable ASCII characters without whitespace, quotes, '\', '#', '@' or ':'.
	// +required
	AuthPasswordSecretRef HostSecretKeyReference `json:"authPasswordSecretRef"`
	// PrivProtocol defaults to AES (AES-128-CFB) for authPriv.
	// +optional
	// +kubebuilder:validation:Enum=AES
	PrivProtocol string `json:"privProtocol,omitempty"`
	// PrivPasswordSecretRef supplies the privacy passphrase for authPriv, with
	// the same character rules as the authentication passphrase.
	// +optional
	PrivPasswordSecretRef *HostSecretKeyReference `json:"privPasswordSecretRef,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="has(self.ntp) || has(self.snmp)",message="at least one system setting is required"
type SwitchSystemSpec struct {
	NetworkResourceSpec `json:",inline"`
	// +optional
	NTP *SystemNTP `json:"ntp,omitempty"`
	// +optional
	SNMP *SystemSNMP `json:"snmp,omitempty"`
}
type HostResourceStatus struct {
	ObservedGeneration    int64  `json:"observedGeneration,omitempty"`
	ConfigurationVerified bool   `json:"configurationVerified,omitempty"`
	RuntimeVerified       bool   `json:"runtimeVerified,omitempty"`
	PersistenceVerified   bool   `json:"persistenceVerified,omitempty"`
	GatewayVerified       bool   `json:"gatewayVerified,omitempty"`
	Recovery              string `json:"recovery,omitempty"`
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Switch",type=string,JSONPath=`.spec.switchRef.name`
// +kubebuilder:printcolumn:name="Address",type=string,JSONPath=`.spec.addresses[0].prefix`
// +kubebuilder:printcolumn:name="Policy",type=string,JSONPath=`.spec.managementPolicy`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`,priority=1
// +kubebuilder:printcolumn:name="Addresses",type=string,JSONPath=`.spec.addresses`,priority=1
// +kubebuilder:printcolumn:name="MAC",type=string,JSONPath=`.spec.mac`,priority=1
// +kubebuilder:printcolumn:name="Recovery",type=string,JSONPath=`.status.recovery`,priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type SwitchManagement struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              SwitchManagementSpec `json:"spec"`
	Status            HostResourceStatus   `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type SwitchManagementList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SwitchManagement `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Switch",type=string,JSONPath=`.spec.switchRef.name`
// +kubebuilder:printcolumn:name="Policy",type=string,JSONPath=`.spec.managementPolicy`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`,priority=1
// +kubebuilder:printcolumn:name="NTPServers",type=string,JSONPath=`.spec.ntp.servers`,priority=1
// +kubebuilder:printcolumn:name="SNMPLocation",type=string,JSONPath=`.spec.snmp.location`,priority=1
// +kubebuilder:printcolumn:name="SNMPUsers",type=string,JSONPath=`.spec.snmp.users[*].name`,priority=1
// +kubebuilder:printcolumn:name="Recovery",type=string,JSONPath=`.status.recovery`,priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type SwitchSystem struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              SwitchSystemSpec   `json:"spec"`
	Status            HostResourceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type SwitchSystemList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SwitchSystem `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(GroupVersion, &SwitchManagement{}, &SwitchManagementList{}, &SwitchSystem{}, &SwitchSystemList{})
		return nil
	})
}
