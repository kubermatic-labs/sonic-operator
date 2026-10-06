# API Reference

## Packages
- [sonic.networking.metal.ironcore.dev/v1alpha1](#sonicnetworkingmetalironcoredevv1alpha1)


## sonic.networking.metal.ironcore.dev/v1alpha1

Package v1alpha1 contains API Schema definitions for the settings.gardener.cloud API group

Package v1alpha1 contains API Schema definitions for the networking v1alpha1 API group.

### Resource Types
- [Switch](#switch)
- [SwitchBGP](#switchbgp)
- [SwitchBGPPeer](#switchbgppeer)
- [SwitchCredentials](#switchcredentials)
- [SwitchDHCPRelay](#switchdhcprelay)
- [SwitchFRRMigration](#switchfrrmigration)
- [SwitchInterface](#switchinterface)
- [SwitchL3Interface](#switchl3interface)
- [SwitchPortBreakout](#switchportbreakout)
- [SwitchPortChannel](#switchportchannel)
- [SwitchStaticRoute](#switchstaticroute)
- [SwitchVLAN](#switchvlan)
- [SwitchVRF](#switchvrf)



#### AdminState

_Underlying type:_ _string_





_Appears in:_
- [SwitchBGPPeerSpec](#switchbgppeerspec)
- [SwitchInterfaceSpec](#switchinterfacespec)
- [SwitchInterfaceStatus](#switchinterfacestatus)
- [SwitchPortBreakoutChild](#switchportbreakoutchild)
- [SwitchPortBreakoutSpec](#switchportbreakoutspec)
- [SwitchPortChannelSpec](#switchportchannelspec)

| Field | Description |
| --- | --- |
| `Unknown` |  |
| `Up` |  |
| `Down` |  |


#### BreakoutManagementPolicy

_Underlying type:_ _string_

BreakoutManagementPolicy controls whether a port layout may be changed.

_Validation:_
- Enum: [Observe Manage]

_Appears in:_
- [SwitchPortBreakoutSpec](#switchportbreakoutspec)

| Field | Description |
| --- | --- |
| `Observe` |  |
| `Manage` |  |


#### Container



Container declares a Docker container that the provisioning server starts on
the switch during generated ZTP provisioning.



_Appears in:_
- [SwitchSpec](#switchspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name is both the Docker container name and its stable identity on the switch. |  | MaxLength: 63 <br />Pattern: `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` <br /> |
| `image` _string_ | Image is the container image pulled by Docker on the switch. |  | MinLength: 1 <br /> |
| `command` _string array_ | Command overrides the image entrypoint. |  |  |
| `args` _string array_ | Args are appended after Command, or after the image entrypoint when Command is empty. |  |  |
| `volumeMounts` _[VolumeMount](#volumemount) array_ | VolumeMounts describes the volumes mounted into the container. Each mount<br />name must refer to an entry in SwitchSpec.Volumes. |  |  |
| `hostPID` _boolean_ | HostPID controls whether the container shares the SONiC host PID namespace. |  |  |
| `securityContext` _[ContainerSecurityContext](#containersecuritycontext)_ | SecurityContext configures the Unix identity used to run the container. |  |  |
| `injectControlKubeconfig` _boolean_ | InjectControlKubeconfig mounts the operator's configured control kubeconfig<br />into this container and sets KUBECONFIG to its in-container path. A<br />securityContext with runAsUser is required so the generated script can<br />grant access to a private, per-container credential file. |  |  |


#### ContainerSecurityContext



ContainerSecurityContext is the supported subset of Kubernetes
container securityContext for generated Docker containers.



_Appears in:_
- [Container](#container)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `privileged` _boolean_ | Privileged runs the container with full access to the SONiC host. |  |  |
| `runAsUser` _integer_ | RunAsUser is the numeric Unix user ID used by the container. |  | Minimum: 0 <br /> |
| `runAsGroup` _integer_ | RunAsGroup is the numeric Unix group ID used by the container. It requires<br />runAsUser to be set as well. |  | Minimum: 0 <br /> |


#### HostPathVolumeSource



HostPathVolumeSource represents a host directory or file mounted into a
Switch container.



_Appears in:_
- [Volume](#volume)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `path` _string_ | Path is the absolute path on the SONiC host. |  |  |
| `type` _[HostPathType](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#hostpathtype-v1-core)_ | Type describes the expected host-path type, following the Kubernetes Pod<br />hostPath API. Generated ZTP does not create missing paths. |  |  |


#### Management







_Appears in:_
- [SwitchSpec](#switchspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `host` _string_ |  |  |  |
| `port` _string_ |  |  |  |
| `credentials` _[ObjectReference](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#objectreference-v1-core)_ |  |  |  |


#### Neighbor



Neighbor represents a connected neighbor device.



_Appears in:_
- [SwitchInterfaceStatus](#switchinterfacestatus)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `macAddress` _string_ | MacAddress is the MAC address of the neighbor device. |  |  |
| `systemName` _string_ | SystemName is the name of the neighbor device. |  |  |
| `interfaceHandle` _string_ | InterfaceHandle is the name of the remote switch interface. |  |  |


#### NetworkIP

_Underlying type:_ _string_

NetworkIP is an unscoped IPv4 or IPv6 address, never an IPv4-mapped IPv6 address.

_Validation:_
- MaxLength: 45

_Appears in:_
- [StaticRouteNextHop](#staticroutenexthop)
- [SwitchBGPPeerSpec](#switchbgppeerspec)



#### NetworkInterfaceAddress

_Underlying type:_ _string_

NetworkInterfaceAddress deliberately retains host bits.

_Validation:_
- MaxLength: 49

_Appears in:_
- [SwitchL3InterfaceSpec](#switchl3interfacespec)



#### NetworkManagementPolicy

_Underlying type:_ _string_

NetworkManagementPolicy permits writes only with the manager and agent gates.

_Validation:_
- Enum: [Observe Manage]

_Appears in:_
- [NetworkResourceSpec](#networkresourcespec)
- [SwitchBGPPeerSpec](#switchbgppeerspec)
- [SwitchBGPSpec](#switchbgpspec)
- [SwitchDHCPRelaySpec](#switchdhcprelayspec)
- [SwitchFRRMigrationSpec](#switchfrrmigrationspec)
- [SwitchL3InterfaceSpec](#switchl3interfacespec)
- [SwitchPortChannelSpec](#switchportchannelspec)
- [SwitchStaticRouteSpec](#switchstaticroutespec)
- [SwitchVRFSpec](#switchvrfspec)

| Field | Description |
| --- | --- |
| `Observe` |  |
| `Manage` |  |


#### NetworkPrefix

_Underlying type:_ _string_

NetworkPrefix is a canonical network prefix, not an interface address.

_Validation:_
- MaxLength: 49

_Appears in:_
- [SwitchBGPSpec](#switchbgpspec)
- [SwitchStaticRouteSpec](#switchstaticroutespec)



#### NetworkResourceSpec



NetworkResourceSpec is shared by the eight network resources.



_Appears in:_
- [SwitchBGPPeerSpec](#switchbgppeerspec)
- [SwitchBGPSpec](#switchbgpspec)
- [SwitchDHCPRelaySpec](#switchdhcprelayspec)
- [SwitchFRRMigrationSpec](#switchfrrmigrationspec)
- [SwitchL3InterfaceSpec](#switchl3interfacespec)
- [SwitchPortChannelSpec](#switchportchannelspec)
- [SwitchStaticRouteSpec](#switchstaticroutespec)
- [SwitchVRFSpec](#switchvrfspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `switchRef` _[NetworkSwitchReference](#networkswitchreference)_ |  |  |  |
| `managementPolicy` _[NetworkManagementPolicy](#networkmanagementpolicy)_ |  | Observe | Enum: [Observe Manage] <br /> |


#### NetworkResourceStatus



NetworkResourceStatus reports independent proof, not inferred forwarding health.



_Appears in:_
- [SwitchBGP](#switchbgp)
- [SwitchBGPPeer](#switchbgppeer)
- [SwitchDHCPRelay](#switchdhcprelay)
- [SwitchFRRMigration](#switchfrrmigration)
- [SwitchL3Interface](#switchl3interface)
- [SwitchPortChannel](#switchportchannel)
- [SwitchStaticRoute](#switchstaticroute)
- [SwitchVRF](#switchvrf)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ |  |  |  |
| `exists` _boolean_ |  |  |  |
| `configurationVerified` _boolean_ |  |  |  |
| `runtimeVerified` _boolean_ |  |  |  |
| `persistenceVerified` _boolean_ |  |  |  |
| `observed` _[RawExtension](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#rawextension-runtime-pkg)_ | Observed preserves the agent's structured observation without interpreting it. |  | Type: object <br /> |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#condition-v1-meta) array_ | Ready, Synced, ConfigurationReady, RuntimeReady and PersistenceReady are independent. |  |  |


#### NetworkSwitchReference







_Appears in:_
- [NetworkResourceSpec](#networkresourcespec)
- [SwitchBGPPeerSpec](#switchbgppeerspec)
- [SwitchBGPSpec](#switchbgpspec)
- [SwitchDHCPRelaySpec](#switchdhcprelayspec)
- [SwitchFRRMigrationSpec](#switchfrrmigrationspec)
- [SwitchL3InterfaceSpec](#switchl3interfacespec)
- [SwitchPortChannelSpec](#switchportchannelspec)
- [SwitchStaticRouteSpec](#switchstaticroutespec)
- [SwitchVRFSpec](#switchvrfspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ |  |  | MaxLength: 253 <br />MinLength: 1 <br />Pattern: `^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$` <br /> |


#### NetworkVRFName

_Underlying type:_ _string_

NetworkVRFName excludes management VRFs; default is the global routing table.

_Validation:_
- MaxLength: 15
- Pattern: `^(default|Vrf[A-Za-z0-9_-]{1,12})$`

_Appears in:_
- [SwitchBGPPeerSpec](#switchbgppeerspec)
- [SwitchBGPSpec](#switchbgpspec)
- [SwitchDHCPRelaySpec](#switchdhcprelayspec)
- [SwitchL3InterfaceSpec](#switchl3interfacespec)
- [SwitchStaticRouteSpec](#switchstaticroutespec)



#### NextBootMode

_Underlying type:_ _string_

NextBootMode describes the desired behavior of the switch's next boot.
Providers translate this high-level intent to their platform-specific boot
mechanism. For SONiC, InstallOS enters ONIE install discovery.



_Appears in:_
- [SwitchSpec](#switchspec)

| Field | Description |
| --- | --- |
| `None` | NextBootModeNone leaves the normal installed network OS boot path intact.<br /> |
| `InstallOS` | NextBootModeInstallOS enters the platform's OS installation/discovery flow.<br /> |


#### OperationState

_Underlying type:_ _string_





_Appears in:_
- [SwitchInterfaceStatus](#switchinterfacestatus)

| Field | Description |
| --- | --- |
| `Up` |  |
| `Down` |  |
| `Unknown` |  |


#### PortSpec







_Appears in:_
- [SwitchSpec](#switchspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ |  |  |  |


#### PortStatus



PortStatus defines the observed state of a port on the Switch.



_Appears in:_
- [SwitchStatus](#switchstatus)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name is the name of the port. |  |  |
| `interfaceRefs` _[LocalObjectReference](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#localobjectreference-v1-core) array_ | InterfaceRefs lists the references to Interfaces connected to this port. |  |  |


#### StaticRouteNextHop







_Appears in:_
- [SwitchStaticRouteSpec](#switchstaticroutespec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `address` _[NetworkIP](#networkip)_ |  |  | MaxLength: 45 <br /> |
| `interfaceName` _string_ |  |  | MaxLength: 32 <br />Pattern: `^(Ethernet(0\|[1-9][0-9]*)\|PortChannel(0\|[1-9][0-9]\{0,3\})\|Vlan[1-9][0-9]\{0,3\})$` <br /> |
| `distance` _integer_ |  | 1 | Maximum: 255 <br />Minimum: 1 <br /> |


#### Switch



Switch is the Schema for the switch API





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `sonic.networking.metal.ironcore.dev/v1alpha1` | | |
| `kind` _string_ | `Switch` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[SwitchSpec](#switchspec)_ | spec defines the desired state of Switch |  |  |
| `status` _[SwitchStatus](#switchstatus)_ | status defines the observed state of Switch |  |  |


#### SwitchBGP









| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `sonic.networking.metal.ironcore.dev/v1alpha1` | | |
| `kind` _string_ | `SwitchBGP` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[SwitchBGPSpec](#switchbgpspec)_ |  |  |  |
| `status` _[NetworkResourceStatus](#networkresourcestatus)_ |  |  |  |


#### SwitchBGPPeer









| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `sonic.networking.metal.ironcore.dev/v1alpha1` | | |
| `kind` _string_ | `SwitchBGPPeer` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[SwitchBGPPeerSpec](#switchbgppeerspec)_ |  |  |  |
| `status` _[NetworkResourceStatus](#networkresourcestatus)_ |  |  |  |


#### SwitchBGPPeerSpec







_Appears in:_
- [SwitchBGPPeer](#switchbgppeer)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `switchRef` _[NetworkSwitchReference](#networkswitchreference)_ |  |  |  |
| `managementPolicy` _[NetworkManagementPolicy](#networkmanagementpolicy)_ |  | Observe | Enum: [Observe Manage] <br /> |
| `vrf` _[NetworkVRFName](#networkvrfname)_ |  | default | MaxLength: 15 <br />Pattern: `^(default\|Vrf[A-Za-z0-9_-]\{1,12\})$` <br /> |
| `address` _[NetworkIP](#networkip)_ |  |  | MaxLength: 45 <br /> |
| `remoteASN` _integer_ |  |  | Format: int64 <br />Maximum: 4.294967295e+09 <br />Minimum: 1 <br /> |
| `localAddress` _[NetworkIP](#networkip)_ |  |  | MaxLength: 45 <br /> |
| `addressFamilies` _string array_ |  |  | MaxItems: 2 <br />MinItems: 1 <br />items:Enum: [ipv4Unicast ipv6Unicast] <br /> |
| `adminState` _[AdminState](#adminstate)_ |  | Down | Enum: [Up Down] <br /> |
| `maxPrefixes` _integer_ |  | 1000 | Format: int64 <br />Maximum: 4.294967295e+09 <br />Minimum: 1 <br /> |


#### SwitchBGPSpec







_Appears in:_
- [SwitchBGP](#switchbgp)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `switchRef` _[NetworkSwitchReference](#networkswitchreference)_ |  |  |  |
| `managementPolicy` _[NetworkManagementPolicy](#networkmanagementpolicy)_ |  | Observe | Enum: [Observe Manage] <br /> |
| `vrf` _[NetworkVRFName](#networkvrfname)_ |  | default | MaxLength: 15 <br />Pattern: `^(default\|Vrf[A-Za-z0-9_-]\{1,12\})$` <br /> |
| `localASN` _integer_ |  |  | Format: int64 <br />Maximum: 4.294967295e+09 <br />Minimum: 1 <br /> |
| `routerID` _string_ |  |  | MaxLength: 15 <br /> |
| `prefixes` _[NetworkPrefix](#networkprefix) array_ | Prefixes is an explicit allowlist; empty means no advertisements. | \{  \} | MaxItems: 256 <br />MaxLength: 49 <br /> |


#### SwitchCredentials



SwitchCredentials is the Schema for the switchcredentials API





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `sonic.networking.metal.ironcore.dev/v1alpha1` | | |
| `kind` _string_ | `SwitchCredentials` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `immutable` _boolean_ | Immutable, if set to true, ensures that data stored in the Secret cannot<br />be updated (only object metadata can be modified).<br />If not set to true, the field can be modified at any time.<br />Defaulted to nil. |  |  |
| `data` _object (keys:string, values:integer array)_ | Data contains the secret data. Each key must consist of alphanumeric<br />characters, '-', '_' or '.'. The serialized form of the secret data is a<br />base64 encoded string, representing the arbitrary (possibly non-string)<br />data value here. Described in https://tools.ietf.org/html/rfc4648#section-4 |  |  |
| `stringData` _object (keys:string, values:string)_ | stringData allows specifying non-binary secret data in string form.<br />It is provided as a write-only input field for convenience.<br />All keys and values are merged into the data field on write, overwriting any existing values.<br />The stringData field is never output when reading from the API. |  |  |
| `type` _[SecretType](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#secrettype-v1-core)_ | Used to facilitate programmatic handling of secret data.<br />More info: https://kubernetes.io/docs/concepts/configuration/secret/#secret-types |  |  |


#### SwitchDHCPRelay









| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `sonic.networking.metal.ironcore.dev/v1alpha1` | | |
| `kind` _string_ | `SwitchDHCPRelay` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[SwitchDHCPRelaySpec](#switchdhcprelayspec)_ |  |  |  |
| `status` _[NetworkResourceStatus](#networkresourcestatus)_ |  |  |  |


#### SwitchDHCPRelaySpec







_Appears in:_
- [SwitchDHCPRelay](#switchdhcprelay)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `switchRef` _[NetworkSwitchReference](#networkswitchreference)_ |  |  |  |
| `managementPolicy` _[NetworkManagementPolicy](#networkmanagementpolicy)_ |  | Observe | Enum: [Observe Manage] <br /> |
| `vlanID` _integer_ |  |  | Maximum: 4094 <br />Minimum: 1 <br /> |
| `vrf` _[NetworkVRFName](#networkvrfname)_ |  | default | MaxLength: 15 <br />Pattern: `^(default\|Vrf[A-Za-z0-9_-]\{1,12\})$` <br /> |
| `ipv4Servers` _string array_ |  |  | MaxItems: 16 <br />items:MaxLength: 15 <br /> |
| `ipv6Servers` _string array_ |  |  | MaxItems: 16 <br />items:MaxLength: 45 <br /> |


#### SwitchFRRMigration



SwitchFRRMigration migrates empty routing between traditional bgpcfgd and unified frrcfgd.
Deletion orphans the framework after any pending journal operation is recovered.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `sonic.networking.metal.ironcore.dev/v1alpha1` | | |
| `kind` _string_ | `SwitchFRRMigration` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[SwitchFRRMigrationSpec](#switchfrrmigrationspec)_ |  |  |  |
| `status` _[NetworkResourceStatus](#networkresourcestatus)_ |  |  |  |


#### SwitchFRRMigrationSpec







_Appears in:_
- [SwitchFRRMigration](#switchfrrmigration)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `switchRef` _[NetworkSwitchReference](#networkswitchreference)_ |  |  |  |
| `managementPolicy` _[NetworkManagementPolicy](#networkmanagementpolicy)_ |  | Observe | Enum: [Observe Manage] <br /> |
| `mode` _string_ | Mode selects the target framework for an empty-routing switch. Change mode<br />on the same resource; each transition requires a fresh approved preflight.<br />Traditional explicitly sets false/separated metadata, rather than restoring absent fields. |  | Enum: [Traditional Unified] <br /> |
| `approvedDigest` _string_ | ApprovedDigest approves exactly the snapshot published as observed.adoptionDigest.<br />Omit it for read-only preflight. A new Ensure requires a matching digest. |  | MaxLength: 64 <br />Pattern: `^[a-f0-9]\{64\}$` <br /> |


#### SwitchInterface



SwitchInterface is the Schema for the switchinterfaces API





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `sonic.networking.metal.ironcore.dev/v1alpha1` | | |
| `kind` _string_ | `SwitchInterface` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[SwitchInterfaceSpec](#switchinterfacespec)_ | spec defines the desired state of SwitchInterface |  |  |
| `status` _[SwitchInterfaceStatus](#switchinterfacestatus)_ | status defines the observed state of SwitchInterface |  |  |


#### SwitchInterfaceSpec



SwitchInterfaceSpec defines the desired state of SwitchInterface



_Appears in:_
- [SwitchInterface](#switchinterface)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `handle` _string_ | Handle uniquely identifies this interface on the switch. |  |  |
| `nativeName` _string_ | NativeName is the native name of the interface on the switch (e.g., "Ethernet0"). |  |  |
| `switchRef` _[LocalObjectReference](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#localobjectreference-v1-core)_ | SwitchRef is a reference to the Switch this interface is connected to. |  |  |
| `adminState` _[AdminState](#adminstate)_ | AdminState represents the desired administrative state of the interface. |  |  |


#### SwitchInterfaceState

_Underlying type:_ _string_





_Appears in:_
- [SwitchInterfaceStatus](#switchinterfacestatus)

| Field | Description |
| --- | --- |
| `Pending` |  |
| `Initializing` |  |
| `Ready` |  |
| `Failed` |  |


#### SwitchInterfaceStatus



SwitchInterfaceStatus defines the observed state of SwitchInterface.



_Appears in:_
- [SwitchInterface](#switchinterface)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `adminState` _[AdminState](#adminstate)_ | AdminState represents the desired administrative state of the interface. |  |  |
| `operationalState` _[OperationState](#operationstate)_ | OperationalState represents the actual operational state of the interface. |  |  |
| `state` _[SwitchInterfaceState](#switchinterfacestate)_ | State represents the high-level state of the SwitchInterface. |  |  |
| `neighbor` _[Neighbor](#neighbor)_ | Neighbor is a reference to the connected neighbor device, if any. |  |  |
| `macAddress` _string_ | MacAddress is the MAC address assigned to this interface. |  |  |
| `aliasName` _string_ | AliasName is the alias name of the interface. |  |  |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#condition-v1-meta) array_ | The status of each condition is one of True, False, or Unknown. |  |  |


#### SwitchL3Interface









| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `sonic.networking.metal.ironcore.dev/v1alpha1` | | |
| `kind` _string_ | `SwitchL3Interface` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[SwitchL3InterfaceSpec](#switchl3interfacespec)_ |  |  |  |
| `status` _[NetworkResourceStatus](#networkresourcestatus)_ |  |  |  |


#### SwitchL3InterfaceSpec







_Appears in:_
- [SwitchL3Interface](#switchl3interface)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `switchRef` _[NetworkSwitchReference](#networkswitchreference)_ |  |  |  |
| `managementPolicy` _[NetworkManagementPolicy](#networkmanagementpolicy)_ |  | Observe | Enum: [Observe Manage] <br /> |
| `name` _string_ |  |  | MaxLength: 32 <br />Pattern: `^(Ethernet(0\|[1-9][0-9]*)\|PortChannel(0\|[1-9][0-9]\{0,3\})\|Vlan[1-9][0-9]\{0,3\})$` <br /> |
| `vrf` _[NetworkVRFName](#networkvrfname)_ |  | default | MaxLength: 15 <br />Pattern: `^(default\|Vrf[A-Za-z0-9_-]\{1,12\})$` <br /> |
| `addresses` _[NetworkInterfaceAddress](#networkinterfaceaddress) array_ | Addresses retain host bits; removals are not supported. |  | MaxItems: 64 <br />MaxLength: 49 <br />MinItems: 1 <br /> |


#### SwitchPortBreakout



SwitchPortBreakout manages a parent port layout. Deletion leaves hardware
unchanged; this resource deliberately has no device-cleanup finalizer.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `sonic.networking.metal.ironcore.dev/v1alpha1` | | |
| `kind` _string_ | `SwitchPortBreakout` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[SwitchPortBreakoutSpec](#switchportbreakoutspec)_ |  |  |  |
| `status` _[SwitchPortBreakoutStatus](#switchportbreakoutstatus)_ |  |  |  |


#### SwitchPortBreakoutChild



SwitchPortBreakoutChild is an observed native child, independent of agent types.



_Appears in:_
- [SwitchPortBreakoutStatus](#switchportbreakoutstatus)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ |  |  |  |
| `lanes` _string_ |  |  |  |
| `speed` _string_ |  |  |  |
| `adminState` _[AdminState](#adminstate)_ |  |  |  |
| `mtu` _string_ |  |  |  |


#### SwitchPortBreakoutReference



SwitchPortBreakoutReference identifies a cluster-scoped Switch.



_Appears in:_
- [SwitchPortBreakoutSpec](#switchportbreakoutspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ |  |  | MaxLength: 253 <br />MinLength: 1 <br /> |


#### SwitchPortBreakoutSpec



SwitchPortBreakoutSpec requests an exact platform-supported port layout.



_Appears in:_
- [SwitchPortBreakout](#switchportbreakout)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `switchRef` _[SwitchPortBreakoutReference](#switchportbreakoutreference)_ | SwitchRef is immutable. Target UID and endpoint are bound before writes. |  |  |
| `port` _string_ | Port is the immutable canonical native parent, not an alias or handle. |  | Pattern: `^Ethernet(0\|[1-9][0-9]*)$` <br /> |
| `mode` _string_ | Mode must exactly match one of status.supportedModes. |  | MaxLength: 128 <br />MinLength: 1 <br /> |
| `managementPolicy` _[BreakoutManagementPolicy](#breakoutmanagementpolicy)_ | Manage also requires both manager and agent write gates. | Observe | Enum: [Observe Manage] <br /> |
| `childAdminState` _[AdminState](#adminstate)_ | ChildAdminState seeds only newly created device children. Existing<br />SwitchInterface desired state and unaffected device attributes are retained. | Down | Enum: [Up Down] <br /> |


#### SwitchPortBreakoutStatus



SwitchPortBreakoutStatus reports configuration, runtime and save proof, not
carrier or forwarding health. Failed mutations never authorize inventory pruning.



_Appears in:_
- [SwitchPortBreakout](#switchportbreakout)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ |  |  |  |
| `targetIdentity` _string_ | TargetIdentity mirrors the durable metadata binding; it is not authority. |  |  |
| `mode` _string_ | Mode is the latest observed CONFIG_DB mode, not necessarily the desired mode. |  |  |
| `supportedModes` _string array_ |  |  |  |
| `children` _[SwitchPortBreakoutChild](#switchportbreakoutchild) array_ |  |  |  |
| `previousChildren` _[SwitchPortBreakoutChild](#switchportbreakoutchild) array_ | PreviousChildren retains the pre-operation inventory across interrupted<br />attempts. Only a subsequent confirmed operation can authorize its cleanup. |  |  |
| `configurationVerified` _boolean_ |  |  |  |
| `runtimeVerified` _boolean_ | RuntimeVerified confirms APPL_DB and kernel layout, not cable/link health. |  |  |
| `persistenceVerified` _boolean_ |  |  |  |
| `pending` _boolean_ | Pending indicates an unresolved operation; recovery must not blindly rerun CLI. |  |  |
| `message` _string_ |  |  |  |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#condition-v1-meta) array_ | Ready, ConfigurationReady, RuntimeReady, PersistenceReady and Progressing<br />describe this generation independently. |  |  |


#### SwitchPortChannel



SwitchPortChannel leaves device configuration intact on deletion.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `sonic.networking.metal.ironcore.dev/v1alpha1` | | |
| `kind` _string_ | `SwitchPortChannel` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[SwitchPortChannelSpec](#switchportchannelspec)_ |  |  |  |
| `status` _[NetworkResourceStatus](#networkresourcestatus)_ |  |  |  |


#### SwitchPortChannelSpec



SwitchPortChannelSpec requests an additive LACP port channel.



_Appears in:_
- [SwitchPortChannel](#switchportchannel)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `switchRef` _[NetworkSwitchReference](#networkswitchreference)_ |  |  |  |
| `managementPolicy` _[NetworkManagementPolicy](#networkmanagementpolicy)_ |  | Observe | Enum: [Observe Manage] <br /> |
| `name` _string_ |  |  | MaxLength: 15 <br />Pattern: `^PortChannel(0\|[1-9][0-9]\{0,3\})$` <br /> |
| `members` _string array_ |  |  | MaxItems: 256 <br />MinItems: 1 <br />items:MaxLength: 32 <br />items:Pattern: ^Ethernet(0\|[1-9][0-9]*)$ <br /> |
| `minLinks` _integer_ |  | 1 | Maximum: 256 <br />Minimum: 1 <br /> |
| `lacpMode` _string_ |  | active | Enum: [active] <br /> |
| `fastRate` _boolean_ |  | false |  |
| `mtu` _integer_ |  | 9100 | Maximum: 9216 <br />Minimum: 1280 <br /> |
| `adminState` _[AdminState](#adminstate)_ |  | Up | Enum: [Up Down] <br /> |


#### SwitchSpec



SwitchSpec defines the desired state of Switch



_Appears in:_
- [Switch](#switch)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `hostname` _string_ | Hostname is configured on the switch by --ztp-mode=generated. If omitted,<br />the generated script uses the Switch object name. |  | MaxLength: 253 <br />Pattern: `^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$` <br /> |
| `management` _[Management](#management)_ |  |  |  |
| `ztp` _[ZTP](#ztp)_ | ZTP identifies the switch while it requests its initial provisioning script. |  |  |
| `containers` _[Container](#container) array_ | Containers are started with host networking and Docker's unless-stopped<br />restart policy by --ztp-mode=generated. |  |  |
| `volumes` _[Volume](#volume) array_ | Volumes are named storage sources available to containers. Generated ZTP<br />currently supports hostPath volumes only. |  |  |
| `nextBootMode` _[NextBootMode](#nextbootmode)_ | NextBootMode declares the desired behavior of the next boot. The default<br />is None. It is configured by --ztp-mode=generated. |  | Enum: [None InstallOS] <br /> |
| `macAddress` _string_ | MacAddress is the MAC address assigned to this interface. |  |  |
| `ports` _[PortSpec](#portspec) array_ | Ports the physical ports available on the Switch. |  |  |


#### SwitchState

_Underlying type:_ _string_

SwitchState represents the high-level state of the Switch.



_Appears in:_
- [SwitchStatus](#switchstatus)

| Field | Description |
| --- | --- |
| `Pending` |  |
| `Ready` |  |
| `Failed` |  |


#### SwitchStaticRoute









| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `sonic.networking.metal.ironcore.dev/v1alpha1` | | |
| `kind` _string_ | `SwitchStaticRoute` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[SwitchStaticRouteSpec](#switchstaticroutespec)_ |  |  |  |
| `status` _[NetworkResourceStatus](#networkresourcestatus)_ |  |  |  |


#### SwitchStaticRouteSpec







_Appears in:_
- [SwitchStaticRoute](#switchstaticroute)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `switchRef` _[NetworkSwitchReference](#networkswitchreference)_ |  |  |  |
| `managementPolicy` _[NetworkManagementPolicy](#networkmanagementpolicy)_ |  | Observe | Enum: [Observe Manage] <br /> |
| `vrf` _[NetworkVRFName](#networkvrfname)_ |  | default | MaxLength: 15 <br />Pattern: `^(default\|Vrf[A-Za-z0-9_-]\{1,12\})$` <br /> |
| `prefix` _[NetworkPrefix](#networkprefix)_ |  |  | MaxLength: 49 <br /> |
| `nextHops` _[StaticRouteNextHop](#staticroutenexthop) array_ |  |  | MaxItems: 64 <br />MinItems: 1 <br /> |


#### SwitchStatus



SwitchStatus defines the observed state of Switch.



_Appears in:_
- [Switch](#switch)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `state` _[SwitchState](#switchstate)_ | State represents the high-level state of the Switch. |  |  |
| `ports` _[PortStatus](#portstatus) array_ | Ports represents the status of each port on the Switch. |  |  |
| `macAddress` _string_ | MACAddress is the MAC address assigned to this switch. |  |  |
| `firmwareVersion` _string_ | FirmwareVersion is the firmware version running on this switch. |  |  |
| `sku` _string_ | SKU is the stock keeping unit of this switch. |  |  |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#condition-v1-meta) array_ | The status of each condition is one of True, False, or Unknown. |  |  |


#### SwitchVLAN



SwitchVLAN manages Layer-2 VLAN configuration. Additive is the safe default;
authoritative ownership requires explicit gates and a cleanup finalizer.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `sonic.networking.metal.ironcore.dev/v1alpha1` | | |
| `kind` _string_ | `SwitchVLAN` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[SwitchVLANSpec](#switchvlanspec)_ |  |  |  |
| `status` _[SwitchVLANStatus](#switchvlanstatus)_ |  |  |  |


#### SwitchVLANMember



SwitchVLANMember declares a Layer-2 membership.



_Appears in:_
- [SwitchVLANSpec](#switchvlanspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `interfaceName` _string_ | InterfaceName is the canonical SONiC Ethernet or PortChannel name, not an alias. |  | Pattern: `^(Ethernet(0\|[1-9][0-9]*)\|PortChannel(0\|[1-9][0-9]\{0,3\}))$` <br /> |
| `taggingMode` _string_ | TaggingMode can replace an existing mode only under Authoritative policy. |  | Enum: [tagged untagged] <br /> |


#### SwitchVLANObservedMember



SwitchVLANObservedMember includes unmanaged members, which may use interface
names outside the Ethernet/PortChannel scope allowed in spec.



_Appears in:_
- [SwitchVLANStatus](#switchvlanstatus)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `interfaceName` _string_ |  |  |  |
| `taggingMode` _string_ |  |  |  |


#### SwitchVLANReference



SwitchVLANReference identifies the cluster-scoped Switch to configure.



_Appears in:_
- [SwitchVLANSpec](#switchvlanspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name is the name of an existing Switch. |  | MaxLength: 253 <br />MinLength: 1 <br /> |


#### SwitchVLANSpec



SwitchVLANSpec declares a VLAN and the members that must exist.



_Appears in:_
- [SwitchVLAN](#switchvlan)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `switchRef` _[SwitchVLANReference](#switchvlanreference)_ | SwitchRef is immutable. Only one CR may claim a switch/VLAN pair. |  |  |
| `vlanID` _integer_ | VLANID is immutable and excludes reserved VLAN IDs. |  | Maximum: 4094 <br />Minimum: 1 <br /> |
| `managementPolicy` _[VLANManagementPolicy](#vlanmanagementpolicy)_ | ManagementPolicy defaults to observation. Manage also requires both the<br />controller's observe-only gate and the agent's read-only gate to be disabled. | Observe | Enum: [Observe Manage] <br /> |
| `reconcilePolicy` _[VLANReconcilePolicy](#vlanreconcilepolicy)_ | ReconcilePolicy defaults to Additive. Authoritative owns the entire VLAN<br />membership, pruning omitted members and replacing tagging modes. | Additive | Enum: [Additive Authoritative] <br /> |
| `deletionPolicy` _[VLANDeletionPolicy](#vlandeletionpolicy)_ | DeletionPolicy defaults to Orphan. Delete applies only to agent-confirmed<br />ownership by this CR UID, with all authoritative write gates enabled. | Orphan | Enum: [Orphan Delete] <br /> |
| `adoptionDigest` _string_ | AdoptionDigest approves the exact agent snapshot for first takeover of an<br />existing VLAN. Review status.adoptionDigest; newly created VLANs need none. |  | Pattern: `^[a-f0-9]\{64\}$` <br /> |
| `members` _[SwitchVLANMember](#switchvlanmember) array_ | Members are additive by default, or the complete set under Authoritative. |  |  |


#### SwitchVLANStatus



SwitchVLANStatus reports configuration, not dataplane or forwarding health.



_Appears in:_
- [SwitchVLAN](#switchvlan)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | ObservedGeneration is the generation last attempted by the controller. |  |  |
| `adoptionDigest` _string_ | AdoptionDigest is the latest agent snapshot digest for explicit review. |  |  |
| `ownerID` _string_ | OwnerID is the last confirmed agent owner UID, never a grant of ownership. |  |  |
| `targetIdentity` _string_ | TargetIdentity binds ownership to the Switch UID and explicit endpoint. |  |  |
| `runtimeVerified` _boolean_ | RuntimeVerified confirms CONFIG_DB only, not ASIC state or forwarding. |  |  |
| `persistenceVerified` _boolean_ | PersistenceVerified confirms the agent's durable configuration save. |  |  |
| `exists` _boolean_ | Exists is unset when existence could not be determined in this attempt. |  |  |
| `members` _[SwitchVLANObservedMember](#switchvlanobservedmember) array_ | Members is the latest successful observation, including unmanaged members. |  |  |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#condition-v1-meta) array_ | Ready and Synced are true only after confirming the requested configuration. |  |  |


#### SwitchVRF



SwitchVRF manages a non-management VRF without a VNI.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `sonic.networking.metal.ironcore.dev/v1alpha1` | | |
| `kind` _string_ | `SwitchVRF` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.35/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[SwitchVRFSpec](#switchvrfspec)_ |  |  |  |
| `status` _[NetworkResourceStatus](#networkresourcestatus)_ |  |  |  |


#### SwitchVRFSpec







_Appears in:_
- [SwitchVRF](#switchvrf)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `switchRef` _[NetworkSwitchReference](#networkswitchreference)_ |  |  |  |
| `managementPolicy` _[NetworkManagementPolicy](#networkmanagementpolicy)_ |  | Observe | Enum: [Observe Manage] <br /> |
| `name` _string_ |  |  | MaxLength: 15 <br />Pattern: `^Vrf[A-Za-z0-9_-]\{1,12\}$` <br /> |


#### VLANDeletionPolicy

_Underlying type:_ _string_

VLANDeletionPolicy selects release-only or guarded deletion for owned VLANs.

_Validation:_
- Enum: [Orphan Delete]

_Appears in:_
- [SwitchVLANSpec](#switchvlanspec)

| Field | Description |
| --- | --- |
| `Orphan` |  |
| `Delete` |  |


#### VLANManagementPolicy

_Underlying type:_ _string_

VLANManagementPolicy controls whether VLAN configuration may be changed.

_Validation:_
- Enum: [Observe Manage]

_Appears in:_
- [SwitchVLANSpec](#switchvlanspec)

| Field | Description |
| --- | --- |
| `Observe` |  |
| `Manage` |  |


#### VLANReconcilePolicy

_Underlying type:_ _string_

VLANReconcilePolicy selects additive assertions or entire VLAN membership.

_Validation:_
- Enum: [Additive Authoritative]

_Appears in:_
- [SwitchVLANSpec](#switchvlanspec)

| Field | Description |
| --- | --- |
| `Additive` |  |
| `Authoritative` |  |


#### Volume



Volume represents a named storage volume made available to Switch containers.
It follows the Kubernetes Pod volume model. Generated ZTP currently supports
hostPath volumes only.



_Appears in:_
- [SwitchSpec](#switchspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name is the stable volume identity referenced by Container.VolumeMounts. |  | MaxLength: 63 <br />Pattern: `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` <br /> |
| `hostPath` _[HostPathVolumeSource](#hostpathvolumesource)_ | HostPath represents a pre-existing file or directory on the SONiC host. |  |  |


#### VolumeMount



VolumeMount describes a volume mounted into a Switch container. It follows
the Kubernetes Pod volumeMount API.



_Appears in:_
- [Container](#container)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ |  |  |  |
| `mountPath` _string_ |  |  |  |
| `readOnly` _boolean_ |  |  |  |


#### ZTP



ZTP defines how a switch is identified while it is requesting its initial
ZTP script. SourceAddress is the address observed by the provisioning server,
which can differ from the management address used after provisioning.



_Appears in:_
- [SwitchSpec](#switchspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `sourceAddress` _string_ |  |  |  |
| `scriptRef` _[ZTPConfigMapReference](#ztpconfigmapreference)_ | ScriptRef identifies the complete script served when --ztp-mode=configmap.<br />It is not used by --ztp-mode=generated. |  |  |


#### ZTPConfigMapReference



ZTPConfigMapReference identifies the ConfigMap entry containing a switch's
complete ZTP script. The referenced ConfigMap may be in a provisioning
namespace chosen by the cluster administrator.



_Appears in:_
- [ZTP](#ztp)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `namespace` _string_ |  |  |  |
| `name` _string_ |  |  |  |
| `key` _string_ |  |  |  |


