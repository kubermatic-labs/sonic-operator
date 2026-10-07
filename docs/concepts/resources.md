# Resources

sonic-operator defines the custom resources below in the API group
`sonic.networking.metal.ironcore.dev/v1alpha1`. All of them are
**cluster-scoped** except `SwitchArtifact`, which is namespaced.

For the full schema of every resource, see the [API Reference](/api-reference/api).

## Core resources

### Switch

Represents a physical switch and its management connectivity.

Spec fields:

- `management.host`: switch management host or IP address.
- `management.port`: management port (string).
- `management.credentials`: reference to a `SwitchCredentials` resource.
- `macAddress`: MAC address assigned to the switch.
- `ports[]`: declared list of physical port names.
- `ztp`: optional custom ZTP script selection, used with `--ztp-mode=configmap`
  (see [Provisioning](/usage/provisioning)).

Status fields:

- `state`: `Pending`, `Ready`, or `Failed`.
- `macAddress`: observed switch MAC address.
- `firmwareVersion`: observed SONiC OS version.
- `sku`: observed hardware SKU.
- `ports[]`: observed ports and interface references.

### SwitchInterface

Represents a single interface and its admin and operational state. The
controller creates these from discovered interfaces.

Spec fields:

- `handle`: interface handle on the device, for example `Ethernet0`.
- `switchRef`: reference to the owning `Switch`.
- `adminState`: desired admin state (`Up`, `Down`, `Unknown`).

Status fields:

- `adminState`: observed admin state.
- `operationalState`: observed operational state.
- `neighbor`: neighbor details, when available.

### SwitchCredentials

Credentials for accessing switches. The schema mirrors `core/v1.Secret`:

- `data` / `stringData`: secret payload.
- `type`: secret type.
- `immutable`: optional immutability flag.

## Feature resources

| Resource | Purpose | Documentation |
| --- | --- | --- |
| `SwitchVLAN` | Layer-2 VLAN and its members on one switch | [Layer-2 VLANs](/usage/vlans), [Authoritative VLANs](/usage/vlan-authoritative) |
| `SwitchPortBreakout` | Breakout mode of one parent port | [Port breakout](/usage/breakout) |
| `SwitchSystem` | Switch system settings | [Network resources](/usage/network-resources) |
| `SwitchManagement` | Management-plane settings | [Network resources](/usage/network-resources) |
| `SwitchVRF` | VRF | [Network resources](/usage/network-resources) |
| `SwitchPortChannel` | Port channel (LAG) | [Network resources](/usage/network-resources), [LAG and Layer 3](/usage/lag-l3-mappings) |
| `SwitchL3Interface` | Layer-3 interface addressing | [Network resources](/usage/network-resources), [LAG and Layer 3](/usage/lag-l3-mappings) |
| `SwitchStaticRoute` | Static route | [Network resources](/usage/network-resources) |
| `SwitchBGP` | BGP instance | [BGP and DHCP relay](/usage/bgp-relay) |
| `SwitchBGPPeer` | BGP neighbor | [BGP and DHCP relay](/usage/bgp-relay) |
| `SwitchDHCPRelay` | DHCP relay | [BGP and DHCP relay](/usage/bgp-relay) |
| `SwitchFRRMigration` | Migration of routing between `bgpcfgd` and unified `frrcfgd` modes | [FRR mode migration](/usage/frr-migration) |
| `SwitchACLPolicy` | ACL policy | [ACL and QoS](/usage/traffic-policy) |
| `SwitchACLBinding` | Binding of an ACL policy to interfaces | [ACL and QoS](/usage/traffic-policy) |
| `SwitchQoSMap` | QoS map | [ACL and QoS](/usage/traffic-policy) |
| `SwitchQoSBinding` | Binding of QoS settings to interfaces | [ACL and QoS](/usage/traffic-policy) |
| `SwitchScheduler` | QoS scheduler | [ACL and QoS](/usage/traffic-policy) |
| `SwitchBufferPool` | Buffer pool | [Buffers](/usage/buffers) |
| `SwitchBufferProfile` | Buffer profile | [Buffers](/usage/buffers) |
| `SwitchBufferPG` | Priority-group buffer binding | [Buffers](/usage/buffers) |
| `SwitchBufferQueue` | Queue buffer binding | [Buffers](/usage/buffers) |
| `SwitchMLAG` | MLAG pairing | [Redundancy](/usage/redundancy), [MLAG](/usage/mlag) |
| `SwitchEVPN` | EVPN instance | [EVPN/VXLAN](/usage/evpn-vxlan) |
| `SwitchEVPNPeer` | EVPN peer | [EVPN/VXLAN](/usage/evpn-vxlan) |
| `SwitchVXLANTunnel` | VXLAN tunnel endpoint | [EVPN/VXLAN](/usage/evpn-vxlan) |
| `SwitchVLANVNI` | VLAN-to-VNI mapping | [EVPN/VXLAN](/usage/evpn-vxlan) |
| `SwitchArtifact` (namespaced) | Content-addressed agent and bootstrap artifacts (agent settings, bootstrap baseline, MAC hooks) referenced from ConfigMaps | [API Reference](/api-reference/api) |
