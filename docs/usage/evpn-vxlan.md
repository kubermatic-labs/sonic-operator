# EVPN/VXLAN (L2)

The EVPN/VXLAN resources let you build a Layer 2 overlay: a VXLAN tunnel endpoint (VTEP) on each leaf, VLAN-to-VNI mappings with explicit route distinguishers (RDs) and route targets (RTs), and BGP EVPN sessions between leaves and spines with explicit RT filters. Use them when you need to stretch access VLANs across a routed IPv4 underlay.

> **Status: not hardware-qualified.** The API and planners are complete and covered by off-switch tests. On the hardware tested so far, the switch ASIC rejected VLAN/VNI map creation, so no end-to-end forwarding has been demonstrated. Treat the activation sequence below as the intended procedure, not a proven deployment recipe. See [EVPN/VXLAN hardware compatibility](evpn-hardware-qualification.md).

For the design rationale, see the [operational L2 EVPN design](../operational-l2-evpn-design.md).

## Resources

All resources use the common `switchRef` and `managementPolicy` fields. Start with `Observe`. Managing these resources requires:

- the controller and agent `--allow-redundancy` gates,
- the existing network-write gates, and
- `managementPolicy: Manage`.

| Resource | Immutable target identity | Spec fields |
| --- | --- | --- |
| `SwitchVXLANTunnel` | `name` | `name`, `sourceAddress` (IPv4), `evpnNVO` |
| `SwitchVLANVNI` | `tunnel` / `vlanID` | `tunnel`, `vlanID` (1–4094), `vni` (1–16777215), `routeDistinguisher`, non-empty `importRouteTargets` and `exportRouteTargets` (max 64 each) |
| `SwitchEVPN` | one per switch; `tunnel` is immutable | `tunnel`, `mappingRefs` (max 64), `adminState` (`Down` default) |
| `SwitchEVPNPeer` | `vrf` / `address` | `role` (`Leaf` default, or `Transit`), `vrf` (`default` only), `address`, non-zero `remoteASN`, `localAddress`, `mappingRefs` or `importRouteTargets`/`exportRouteTargets`, `adminState` (`Down` default) |

### Naming and encoding rules

- Tunnel and NVO names start with a letter, are at most 32 characters, and contain only letters, digits, underscores and hyphens.
- RDs and RTs use canonical `ASN:number` or `IPv4:number` encoding:
  - a two-byte ASN allows a 32-bit assigned number;
  - a four-byte ASN or an IPv4 administrator allows a 16-bit assigned number.
- `auto`, wildcards, duplicate list entries and empty RT lists are rejected.
- An RT that appears in both the import and export lists becomes a single native `both` row.
- Unknown JSON fields are rejected rather than ignored.

### SwitchVXLANTunnel and SwitchVLANVNI

Example mapping:

```yaml
apiVersion: sonic.networking.metal.ironcore.dev/v1alpha1
kind: SwitchVLANVNI
metadata:
  name: tenant-a
spec:
  switchRef:
    name: leaf-01
  managementPolicy: Observe
  tunnel: vtep1
  vlanID: 10
  vni: 100
  routeDistinguisher: "65001:100"
  importRouteTargets: ["65001:100"]
  exportRouteTargets: ["65001:100"]
```

The VLAN and the tunnel/NVO must exist before the mapping. VNIs and VLAN mappings must be unique on a switch, and local VNIs cannot share an RD or RT.

### SwitchEVPN

`SwitchEVPN` owns global L2 EVPN advertisement (`advertise-all-vni`) on one switch. It lists the mappings that are allowed to exist locally. `adminState: Up` requires at least one mapping reference.

```yaml
apiVersion: sonic.networking.metal.ironcore.dev/v1alpha1
kind: SwitchEVPN
metadata:
  name: leaf-01-evpn
spec:
  switchRef: {name: leaf-01}
  managementPolicy: Observe
  tunnel: vtep1
  mappingRefs: [{name: tenant-a}]
  adminState: Down
```

Global advertisement cannot be enabled while undeclared local mappings exist or while any peer lacks a verified policy.

### SwitchEVPNPeer

`SwitchEVPNPeer` extends an existing `SwitchBGPPeer` with the L2VPN EVPN address family. Both roles also require the `switchRef`, `address`, `remoteASN` and `localAddress` fields.

Leaf peer (local VTEP): RT sets are derived from the referenced `SwitchVLANVNI` resources, which must be on the same switch and use `Manage`. Leaf peers cannot set RT lists directly.

```yaml
role: Leaf
mappingRefs:
  - name: tenant-a
adminState: Down
```

Transit peer (spine): requires explicit import and export RT sets and forbids mapping references. It needs no local VNI, preserves the originating VTEP next hop (`neighbor PEER attribute-unchanged next-hop`) and does not enable route reflection or AS-path rewriting.

```yaml
role: Transit
importRouteTargets: ["65000:100"]
exportRouteTargets: ["65000:100"]
adminState: Down
```

For each direction, the operator renders a native route map that matches only the explicit RT set and ends in an unconditional deny.

Peers without explicit policy (no mapping references and no RT sets) remain `Down`-only. `Up` is rejected for them before any write.

## Ownership

Ownership between the BGP and EVPN resources is strict:

| Owner | Owns |
| --- | --- |
| `SwitchBGPPeer` | Neighbor identity, ASN, update source and neighbor shutdown (`BGP_NEIGHBOR.admin_status`) |
| `SwitchEVPNPeer` | The EVPN AF state (`BGP_NEIGHBOR_AF\|default\|ADDRESS\|l2vpn_evpn.admin_status`), its route maps and extended-community sets, and extended-community transport |
| `SwitchEVPN` | Global `BGP_GLOBALS_AF` default/l2vpn_evpn advertisement fields |

`adminState: Down` on an EVPN peer renders `no neighbor ADDRESS activate` in the EVPN AF. It never changes the parent neighbor's shutdown, ASN, update source or unicast AFs. Enabling the parent `SwitchBGPPeer` does not enable a disabled EVPN AF.

## Prerequisites

1. **Unified FRR.** Migrate to unified FRR with the existing migration workflow. Configure `SwitchBGP` with an explicit router ID, default IPv4 unicast disabled and default neighbor shutdown. Stage each `SwitchBGPPeer` as `Down` before any overlay work. Its ASN, update source and shutdown must be durably owned by the operator.
2. **Source address.** Use an existing default-VRF Loopback, Ethernet or PortChannel IPv4 address that exists both in CONFIG_DB and on the local interface. Management sources, ambiguous addresses and addresses in another VRF are rejected.
3. **Underlay path.** For the default-VRF BGP neighbors of the source's address family, `ip -j route get PEER from SOURCE` must select a configured, carrier-up data-plane Ethernet or PortChannel egress. An `eth0` default route, a lookup without the source, or a configured interface without carrier is not sufficient.
4. **Supported stack.** Preflight checks the FRR version, the running daemons (`frrcfgd`, `bgpd`, `zebra`, `vxlanmgrd`, `orchagent`), the actual FRR configuration, and the hashes of the native consumer and schema files. Unknown builds fail closed. The hashes are compatibility checks, not SAI capability checks:

   ```text
   frrcfgd.py        5f01eac72568c1f2483621d61cbeb8d98abf5ddad632ac2cf23377c237a4b9a8
   sonic-vxlan.yang  827c1321e96690d9d49c3f8893f48bedaf00523c93a6ef36e24e08f9a26a1d90
   ```

## Deployment order

Each step is journaled independently. There is no atomic transaction across resources or switches.

1. Configure the underlay and stage BGP peers `Down`.
2. Create the `SwitchVXLANTunnel` (tunnel and NVO).
3. Create the `SwitchVLANVNI` resources.
4. Set the `SwitchEVPN` to `Up`. This performs local-only initialization (`advertise-all-vni`) while every neighbor is shutdown and every EVPN AF is disabled.
5. Let the mappings apply, and verify hardware maps and RD/RT configuration.
6. Create `SwitchEVPNPeer` resources with `adminState: Down`.
7. Set the EVPN peers to `Up` (enables the EVPN AF while the parent neighbor is still shut down).
8. Set the parent `SwitchBGPPeer` resources to `Up`.

Why initialization comes before mapping verification: FRR 10.4.1 ignores per-VNI RD/RT commands until `advertise-all-vni` is enabled. The `SwitchEVPN` can therefore be `ConfigurationReady` and `PersistenceReady` while it waits for mapping runtime.

Safeguards during this sequence:

- After initialization, only the recorded mapping UIDs with the exact recorded VLAN/VNI/RT intent can be staged, and only while all neighbors are shut down. The declaration cannot be replaced implicitly.
- EVPN AF activation and parent BGP activation each independently recheck hardware maps, RD/RTs and peer filters.
- Changing RDs/RTs, remapping an existing VLAN/VNI, or replacing policy is not an additive update. It requires the affected peers to be administratively down.
- Native consumers (`vxlanmgrd`, `orchagent`, `frrcfgd`) apply CONFIG_DB changes asynchronously. A successful save does not prove they have been applied, which is why neighbors stay shut down until runtime is verified.

## Readiness

`ConfigurationReady`, `PersistenceReady` and `RuntimeReady` are reported independently.

- **Tunnel runtime** requires the chain `COUNTERS_TUNNEL_NAME_MAP` → exact VXLAN tunnel OID → underlay router interface → matching P2MP termination that points back to the tunnel. Tunnel, interface and termination each need `VIDTORID` evidence. A staged tunnel can be configuration- and persistence-ready while it waits for its first mapping, because SONiC may create the tunnel hardware only when a mapping is added.
- **Mapping runtime** also requires the exact VNI, RD and import/export RTs in the correct FRR instance and VNI scope, plus a translated VLAN/VNI map entry linked through this tunnel's `SAI_TUNNEL_ATTR_DECAP_MAPPERS`. Entries on another tunnel, L3 mappers, the wrong VLAN or untranslatable OIDs do not count.
- **Peer `Down` runtime** means the FRR neighbor is shut down, its EVPN AF is disabled, and the ASN and update source match. It does not claim session establishment, reachability or forwarding.
- **Peer `Up` runtime** requires FRR state `Established`, the expected ASN and local source, and EVPN capability both advertised and received.
- Missing name/OID correlation leaves runtime unverified. CONFIG_DB equality, daemon presence, ASIC vendor strings and kernel VXLAN support never count as runtime success on their own. Redis and command failures are reported as errors.

Diagnostics:

- Local Type-2/Type-3 RIB counts are diagnostic only. They do not prove that a peer originated or received routes. Zero routes is valid when no remote endpoint exists.
- Mapping observation reports remote APPL_DB FDB and replication entries and, where available, exact FDB-to-VLAN/tunnel correlation.
- `forwardingTested` is always `false`. Only physical packet tests can demonstrate forwarding.

## Native SONiC 202511 mapping

The operator writes these CONFIG_DB rows. Support was verified against the installed `frrcfgd.py` handlers, because the community BGP YANG models do not describe the unified EVPN tables.

| Native target | Field / consumer |
| --- | --- |
| `VXLAN_TUNNEL\|NAME` | `src_ip`; `sonic-vxlan.yang`, `vxlanmgrd`, `VxlanTunnelOrch` |
| `VXLAN_EVPN_NVO\|NAME` | `source_vtep`; the schema permits one NVO |
| `VXLAN_TUNNEL_MAP\|TUNNEL\|map_VNI_VlanID` | `vlan=VlanID`, `vni=VNI` |
| `BGP_GLOBALS_EVPN_VNI\|default\|l2vpn_evpn\|VNI` | `route-distinguisher`; frrcfgd emits `rd VALUE` under the VNI |
| `BGP_GLOBALS_EVPN_VNI_RT\|default\|l2vpn_evpn\|VNI\|RT` | `route-target-type` = `import`, `export` or `both`; frrcfgd emits `route-target TYPE RT` under the VNI |
| `BGP_NEIGHBOR_AF\|default\|ADDRESS\|l2vpn_evpn` | `admin_status`; frrcfgd emits `[no] neighbor ADDRESS activate` |

Notes:

- There are no `route_target` or `route_distinguisher` (underscore) fields in these rows, and RD/RT fields do not belong on the EVPN peer.
- SONiC 202511 does not publish a usable VXLAN create capability (see `queryTunnelCapability` in [sonic-swss 202511 vxlanorch.cpp](https://github.com/sonic-net/sonic-swss/blob/202511/orchagent/vxlanorch.cpp)). The tunnel name/OID relationship comes from counter registration. `VxlanTunnelMapOrch::addOperation` creates the decapsulation map and may create the tunnel hardware only at mapping time, so an unreferenced CONFIG_DB tunnel may have no ASIC object.
- FRR readback accepts native extended-community-list `seq` numbers (positive, canonical, unique per list) and route-map `exit` delimiters. FRR 10.4.1 sends extended communities by default; an omitted setting is accepted only together with the exact AF policy attachments. Explicitly disabling extended communities (or all/both) and peer-group inheritance are rejected.

## Recovery and safety

- The existing network journal, additive field ownership, compare-and-swap (CAS) and save recovery apply. Preflight is repeatable before CAS, including during pre-state recovery.
- Post-state save recovery completes the durable request without enabling a peer.
- Restart recovery verifies persisted configuration and re-established runtime; it does not blindly replay activation.
- **L2-only invariant:** creating a mapping is rejected if the VLAN has an SVI, and creating an SVI is rejected if the VLAN has a VXLAN mapping, regardless of the mapping's name or owner. Both checks are repeated when pending requests are replanned, including recovery before CAS and between CAS and save.
- Existing extra RD/RT fields, conflicting global EVPN advertisement settings and conflicting AF settings are rejected, not replaced.
- Deleting a resource follows the existing orphan/manual-cleanup behavior: device configuration is left in place. Use `adminState: Down` to withdraw.

## Not supported

- Gateway/IRB, SVIs on mapped VLANs, L3VNI and VRF mapping
- ESI/multihoming and MLAG/EVPN coexistence
- Route reflection, multihop overlay BGP and dynamic peer groups
- Automatic route-target allocation
- IPv6 VTEP addresses and non-default VRF transport

## Tests

Off-switch tests cover consumer/version failures, source-specific routing, management-path rejection, carrier loss, FRR AF/VNI scope, export isolation, ASIC name/OID/termination/mapper/RID correlation, and the journal/CAS engine against real Redis (failures before write, foreign neighbors, native RT encoding, AF-only ownership, interrupted saves, pre-mapping initialization, changed declarations, missing hardware, and both SVI/mapping creation orders).

```sh
go test ./internal/agent/sonic -run '^TestEVPN' -count=1
go test -tags=integration ./internal/agent/sonic -run '^TestEVPN' -count=1
```

These tests do not exercise switch hardware or packet forwarding.
