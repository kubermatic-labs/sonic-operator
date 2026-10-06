# MLAG and L2 EVPN/VXLAN resources

Four cluster-scoped resources manage MLAG pairs and L2 EVPN/VXLAN overlays: `SwitchMLAG`, `SwitchVXLANTunnel`, `SwitchVLANVNI` and `SwitchEVPNPeer`. They use the shared additive network controller, with independent configuration, runtime and persistence conditions, durable request binding, and Orphan deletion.

See the [Observe-only samples](../../config/samples/redundancy.yaml) for complete examples. The samples are validated against the generated CRDs in envtest.

## Write gates and recovery

| Component | Requirement |
| --- | --- |
| Manager | `--observe-only=false --allow-network-config=true --allow-redundancy=true` (`--allow-redundancy` defaults to `false`) |
| Resource | `managementPolicy: Manage` |
| Agent | Its network, redundancy and write gates enabled |

- These gates apply to both Ensure and recovery. Observation works with writes disabled.
- Deleting a resource only recovers a recorded pending operation. Device configuration and ownership stay in place.
- Disabling gates keeps the recovery finalizer. Changing immutable selectors blocks recovery.

## MLAG

### Spec

| Field | Rules |
| --- | --- |
| `peerSwitchRef.name` | Peer Switch. Immutable. |
| `domainID` | 1–4095. Immutable. |
| `localAddress`, `peerAddress` | Distinct unicast IPv4 addresses |
| `peerLink` | `PortChannelN`; cannot also be a member |
| `members` | Non-empty list of `PortChannelN` |
| `keepaliveInterval` | Seconds, 1–60, default 1 |
| `sessionTimeout` | Seconds, 2–3600, default 30; at least 3 × `keepaliveInterval` |

The local `switchRef` is also immutable.

### Reciprocal checks

You create one `SwitchMLAG` per switch in the pair. Before a local Ensure, the controller reads the referenced peer Switch and the reciprocal `SwitchMLAG` directly from the API server (uncached). It requires:

- both are live, with distinct Switch UIDs and normalized agent endpoints;
- matching domains and timers, reversed addresses and reciprocal switch references;
- both MLAG resources set to `Manage`;
- no competing claims.

Peer intent and endpoints are checked again after the agent read and immediately before Ensure. Peer Switch changes requeue affected local claims; peer MLAG changes are also picked up by the periodic one-minute reconciliation.

### Peer preflight

The controller calls the peer's read-only `GetNetworkResource` with the peer's UID and normalized desired MLAG spec. Both the local and peer observations must explicitly contain `preflightEligible: true`. The backend derives this from current native consumer and daemon evidence, existing peer-link and member LAGs, local address assignment, and data-plane reachability to the peer address.

- Missing or false evidence blocks Manage.
- In Observe mode, the resource reports `PeerNotReady` and keeps the local observation.
- The management interface `eth0` cannot be an MLAG member or the keepalive path.

### Staging and runtime

- Neither switch needs `ConfigurationReady` before the other side stages. Each switch stages independently; this is **not** an atomic cross-device transaction.
- Runtime readiness requires actual daemon, STATE_DB and teamd evidence. It is never inferred from CONFIG_DB.
- The backend requires a separately reviewed consumer manifest. No fingerprints are shipped in the repository.

The native read-only backend has been tested on a three-switch setup, including failure and recovery observations. See [native MLAG verification](mlag.md) for the manifest contract, results, the peer-link failure limitation and the cleanup-order finding.

## EVPN/VXLAN

| Resource | Spec | Immutable target identity |
| --- | --- | --- |
| `SwitchMLAG` | Reciprocal pair and timers (above) | `MLAG\|domainID` |
| `SwitchVXLANTunnel` | `name`, IPv4 `sourceAddress`, `evpnNVO` | `VXLANTunnel\|name` |
| `SwitchVLANVNI` | `tunnel`, `vlanID` 1–4094, `vni` 1–16777215, `routeDistinguisher`, non-empty `importRouteTargets` and `exportRouteTargets` | `VLANVNI\|tunnel\|vlanID` |
| `SwitchEVPNPeer` | `vrf: default` only, IP `address`, nonzero uint32 `remoteASN`, same-family IP `localAddress`, `adminState` (default `Down`) | `EVPNPeer\|default\|canonicalAddress` |

All `switchRef` values are immutable.

### Route distinguishers and route targets

- RD and RT values accept `ASN:number` and `IPv4:number`, with native 16-bit and 32-bit component bounds.
- Route targets are sets; duplicates are rejected.
- On a single switch (including endpoint aliases), competing VLAN/VNI, RD or overlapping RT claims are rejected. Cross-VNI route leaking is not supported.
- Corresponding VNIs on different switches can use matching RTs.

### Staging order

1. Stage the underlay, the source loopback/L3 address, the VLAN, the tunnel and the VLAN/VNI mappings. The backend verifies native VXLAN SAI support and the actually applied dependencies.
2. Stage a `SwitchBGPPeer` with `managementPolicy: Manage` for the EVPN endpoint, with matching remote ASN and local address and `adminState: Down`. See [BGP and DHCP relay](./bgp-relay.md).
3. Create the `SwitchEVPNPeer`. The controller reads the BGP neighbor through the agent and requires current configuration and persistence proof before EVPN Ensure.

Ownership between the two peer resources:

- `SwitchEVPNPeer` owns only the `l2vpn_evpn` address-family fields.
- `SwitchBGPPeer` keeps ownership of the neighbor's ASN, source address and admin fields.
- Incompatible shared-neighbor fields are rejected in both reconciliation directions, including for deleting claims and endpoint aliases.

### Admin state

`SwitchEVPNPeer.adminState` controls the address-family intent. `Up` is currently rejected (fail-closed) until verified native per-peer export isolation is available. While an EVPN claim exists, the controller also prevents the shared BGP neighbor from being set to Up.

Not included: ESI, EVPN multihoming, L3VNI and IRB.

## Test coverage

Controller tests cover default-off write and recovery gates, normalized identities, invalid specs, reciprocal staging without a readiness deadlock, absent or stale peers, alias endpoints, shared BGP field conflicts, mapping isolation and Orphan recovery. `TestRedundancySchema` checks API-server defaulting, validation, immutable targets, status preservation and the samples.

Hardware activation and live redundancy behavior have not been verified by these tests and depend on your topology.
