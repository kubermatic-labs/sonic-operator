// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// RedundancyName is a native SONiC identifier, never a table key or command.
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=32
// +kubebuilder:validation:Pattern=`^[A-Za-z][A-Za-z0-9_-]*$`
type RedundancyName string

// +kubebuilder:validation:MaxLength=15
// +kubebuilder:validation:XValidation:rule="isIP(self) && ip(self).family() == 4",message="must be an IPv4 address"
type RedundancyIPv4 string

// +kubebuilder:validation:MaxLength=32
// +kubebuilder:validation:Pattern=`^PortChannel(0|[1-9][0-9]{0,3})$`
type MLAGPortChannel string

// RouteIdentifier accepts the two-octet ASN, four-octet ASN, and IPv4 forms.
// +kubebuilder:validation:MaxLength=21
// +kubebuilder:validation:Pattern=`^((0|[1-9][0-9]{0,9})|([0-9]{1,3}\.){3}[0-9]{1,3}):(0|[1-9][0-9]{0,9})$`
// +kubebuilder:validation:XValidation:rule="self.split(':').size() == 2 && (self.split(':')[0].contains('.') ? (isIP(self.split(':')[0]) && ip(self.split(':')[0]).family() == 4 && int(self.split(':')[1]) <= 65535) : (int(self.split(':')[0]) <= 4294967295 && int(self.split(':')[1]) <= (int(self.split(':')[0]) <= 65535 ? 4294967295 : 65535)))",message="must be a valid ASN:number or IPv4:number RD/RT"
type RouteIdentifier string

// SwitchMLAGSpec coordinates staged, reciprocal configurations on two switches.
// +kubebuilder:validation:XValidation:rule="self.switchRef.name != self.peerSwitchRef.name",message="peer switch must be distinct"
// +kubebuilder:validation:XValidation:rule="self.localAddress != self.peerAddress",message="peer and local addresses must differ"
// +kubebuilder:validation:XValidation:rule="self.members.all(m, m != self.peerLink)",message="peerLink cannot be an MLAG member"
// +kubebuilder:validation:XValidation:rule="self.sessionTimeout >= 3 * self.keepaliveInterval",message="sessionTimeout must be at least three keepalive intervals"
// +kubebuilder:validation:XValidation:rule="!ip(self.localAddress).isUnspecified() && !ip(self.localAddress).isLoopback() && !ip(self.localAddress).isLinkLocalUnicast() && !cidr('224.0.0.0/4').containsIP(self.localAddress) && self.localAddress != '255.255.255.255'",message="localAddress must be unicast IPv4"
// +kubebuilder:validation:XValidation:rule="!ip(self.peerAddress).isUnspecified() && !ip(self.peerAddress).isLoopback() && !ip(self.peerAddress).isLinkLocalUnicast() && !cidr('224.0.0.0/4').containsIP(self.peerAddress) && self.peerAddress != '255.255.255.255'",message="peerAddress must be unicast IPv4"
type SwitchMLAGSpec struct {
	NetworkResourceSpec `json:",inline"`
	// +required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4095
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="domainID is immutable"
	DomainID uint32 `json:"domainID"`
	// +required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="peerSwitchRef is immutable"
	PeerSwitchRef NetworkSwitchReference `json:"peerSwitchRef"`
	// +required
	LocalAddress RedundancyIPv4 `json:"localAddress"`
	// +required
	PeerAddress RedundancyIPv4 `json:"peerAddress"`
	// +required
	PeerLink MLAGPortChannel `json:"peerLink"`
	// +required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=256
	// +listType=set
	Members []MLAGPortChannel `json:"members"`
	// KeepaliveInterval is in seconds.
	// +optional
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=60
	KeepaliveInterval uint32 `json:"keepaliveInterval,omitempty"`
	// SessionTimeout is in seconds.
	// +optional
	// +kubebuilder:default=30
	// +kubebuilder:validation:Minimum=2
	// +kubebuilder:validation:Maximum=3600
	SessionTimeout uint32 `json:"sessionTimeout,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Switch",type=string,JSONPath=`.spec.switchRef.name`
// +kubebuilder:printcolumn:name="Peer",type=string,JSONPath=`.spec.peerSwitchRef.name`
// +kubebuilder:printcolumn:name="Domain",type=integer,JSONPath=`.spec.domainID`
// +kubebuilder:printcolumn:name="PeerLink",type=string,JSONPath=`.spec.peerLink`
// +kubebuilder:printcolumn:name="Policy",type=string,JSONPath=`.spec.managementPolicy`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`,priority=1
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`,priority=1
// +kubebuilder:printcolumn:name="LocalAddress",type=string,JSONPath=`.spec.localAddress`,priority=1
// +kubebuilder:printcolumn:name="PeerAddress",type=string,JSONPath=`.spec.peerAddress`,priority=1
// +kubebuilder:printcolumn:name="Members",type=string,JSONPath=`.spec.members`,priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type SwitchMLAG struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +required
	Spec SwitchMLAGSpec `json:"spec"`
	// +optional
	Status NetworkResourceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type SwitchMLAGList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SwitchMLAG `json:"items"`
}

type SwitchVXLANTunnelSpec struct {
	NetworkResourceSpec `json:",inline"`
	// +required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="name is immutable"
	Name RedundancyName `json:"name"`
	// +required
	SourceAddress RedundancyIPv4 `json:"sourceAddress"`
	// +required
	EVPNNVO RedundancyName `json:"evpnNVO"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Switch",type=string,JSONPath=`.spec.switchRef.name`
// +kubebuilder:printcolumn:name="Tunnel",type=string,JSONPath=`.spec.name`
// +kubebuilder:printcolumn:name="Source",type=string,JSONPath=`.spec.sourceAddress`
// +kubebuilder:printcolumn:name="Policy",type=string,JSONPath=`.spec.managementPolicy`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`,priority=1
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`,priority=1
// +kubebuilder:printcolumn:name="NVO",type=string,JSONPath=`.spec.evpnNVO`,priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type SwitchVXLANTunnel struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +required
	Spec SwitchVXLANTunnelSpec `json:"spec"`
	// +optional
	Status NetworkResourceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type SwitchVXLANTunnelList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SwitchVXLANTunnel `json:"items"`
}

// SwitchVLANVNISpec maps an existing VLAN to an L2VNI with explicit import/export policy.
type SwitchVLANVNISpec struct {
	NetworkResourceSpec `json:",inline"`
	// +required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="tunnel is immutable"
	Tunnel RedundancyName `json:"tunnel"`
	// +required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4094
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="vlanID is immutable"
	VLANID uint32 `json:"vlanID"`
	// +required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=16777215
	VNI uint32 `json:"vni"`
	// +required
	RouteDistinguisher RouteIdentifier `json:"routeDistinguisher"`
	// +required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	// +listType=set
	ImportRouteTargets []RouteIdentifier `json:"importRouteTargets"`
	// +required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	// +listType=set
	ExportRouteTargets []RouteIdentifier `json:"exportRouteTargets"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Switch",type=string,JSONPath=`.spec.switchRef.name`
// +kubebuilder:printcolumn:name="VLAN",type=integer,JSONPath=`.spec.vlanID`
// +kubebuilder:printcolumn:name="VNI",type=integer,JSONPath=`.spec.vni`
// +kubebuilder:printcolumn:name="Tunnel",type=string,JSONPath=`.spec.tunnel`
// +kubebuilder:printcolumn:name="Policy",type=string,JSONPath=`.spec.managementPolicy`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`,priority=1
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`,priority=1
// +kubebuilder:printcolumn:name="RD",type=string,JSONPath=`.spec.routeDistinguisher`,priority=1
// +kubebuilder:printcolumn:name="ImportRT",type=string,JSONPath=`.spec.importRouteTargets`,priority=1
// +kubebuilder:printcolumn:name="ExportRT",type=string,JSONPath=`.spec.exportRouteTargets`,priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type SwitchVLANVNI struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +required
	Spec SwitchVLANVNISpec `json:"spec"`
	// +optional
	Status NetworkResourceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type SwitchVLANVNIList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SwitchVLANVNI `json:"items"`
}

// SwitchEVPNPeerSpec owns the EVPN AF of an existing shared BGP neighbor.
// +kubebuilder:validation:XValidation:rule="ip(self.address).family() == ip(self.localAddress).family()",message="localAddress must match peer address family"
// +kubebuilder:validation:XValidation:rule="self.role != 'Transit' || ((!has(self.mappingRefs) || size(self.mappingRefs) == 0) && has(self.importRouteTargets) && size(self.importRouteTargets) > 0 && has(self.exportRouteTargets) && size(self.exportRouteTargets) > 0)",message="Transit requires explicit RT sets and no local mapping references"
// +kubebuilder:validation:XValidation:rule="self.role != 'Leaf' || ((!has(self.importRouteTargets) || size(self.importRouteTargets) == 0) && (!has(self.exportRouteTargets) || size(self.exportRouteTargets) == 0))",message="Leaf RT policy comes from mapping references"
type SwitchEVPNPeerSpec struct {
	NetworkResourceSpec `json:",inline"`
	// Role distinguishes local VTEP participation from spine transit.
	// +optional
	// +kubebuilder:default=Leaf
	// +kubebuilder:validation:Enum=Leaf;Transit
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="role is immutable"
	Role string `json:"role,omitempty"`
	// Transit peers use explicit RT sets without local mapping references.
	// +optional
	// +kubebuilder:validation:MaxItems=64
	// +listType=set
	ImportRouteTargets []RouteIdentifier `json:"importRouteTargets,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxItems=64
	// +listType=set
	ExportRouteTargets []RouteIdentifier `json:"exportRouteTargets,omitempty"`
	// +optional
	// +kubebuilder:default=default
	// +kubebuilder:validation:Enum=default
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="vrf is immutable"
	VRF NetworkVRFName `json:"vrf,omitempty"`
	// +required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="address is immutable"
	Address NetworkIP `json:"address"`
	// +required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4294967295
	// +kubebuilder:validation:Format=int64
	RemoteASN uint32 `json:"remoteASN"`
	// +required
	LocalAddress NetworkIP `json:"localAddress"`
	// AdminState controls the EVPN address family, not shared neighbor fields.
	// +optional
	// +kubebuilder:default=Down
	// +kubebuilder:validation:Enum=Up;Down
	AdminState AdminState `json:"adminState,omitempty"`
	// MappingRefs selects the local VLAN/VNI policies permitted on this peer.
	// Existing Down-only peers may omit this field; activation requires it.
	// +optional
	// +kubebuilder:validation:MaxItems=64
	// +listType=map
	// +listMapKey=name
	MappingRefs []NetworkSwitchReference `json:"mappingRefs,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Switch",type=string,JSONPath=`.spec.switchRef.name`
// +kubebuilder:printcolumn:name="Peer",type=string,JSONPath=`.spec.address`
// +kubebuilder:printcolumn:name="RemoteASN",type=integer,JSONPath=`.spec.remoteASN`
// +kubebuilder:printcolumn:name="Role",type=string,JSONPath=`.spec.role`
// +kubebuilder:printcolumn:name="Admin",type=string,JSONPath=`.spec.adminState`
// +kubebuilder:printcolumn:name="Policy",type=string,JSONPath=`.spec.managementPolicy`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`,priority=1
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`,priority=1
// +kubebuilder:printcolumn:name="LocalAddress",type=string,JSONPath=`.spec.localAddress`,priority=1
// +kubebuilder:printcolumn:name="VRF",type=string,JSONPath=`.spec.vrf`,priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type SwitchEVPNPeer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +required
	Spec SwitchEVPNPeerSpec `json:"spec"`
	// +optional
	Status NetworkResourceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type SwitchEVPNPeerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SwitchEVPNPeer `json:"items"`
}
