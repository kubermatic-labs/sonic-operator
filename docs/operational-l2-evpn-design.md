# Operational L2 EVPN/VXLAN design

This document explains the design of the L2 EVPN/VXLAN feature: what it aims to deliver, how ownership is split between resources, and why activation happens in a fixed order. For usage, see [EVPN/VXLAN](usage/evpn-vxlan.md). For hardware status, see [EVPN/VXLAN hardware compatibility](usage/evpn-hardware-qualification.md).

## Goals

Starting from a supported switch without VXLAN configuration, an operator should be able to:

- create a VTEP and map access VLANs to VNIs,
- establish EVPN sessions and exchange Type-2 (MAC/IP) and Type-3 (inclusive multicast) routes,
- forward Ethernet frames between remote access endpoints,
- isolate unrelated VNIs through explicit policy,
- withdraw advertisements by administrative shutdown, and
- recover from interrupted operations and daemon restarts using durable configuration and observed runtime state.

## Scope

Target stack: SONiC 202511 with FRR 10.4.1. Qualification is specific to a tested image and SAI combination. It is never inferred from vendor strings or kernel VXLAN support.

In scope:

- IPv4 VTEP addresses and default-VRF transport
- Directly connected EVPN eBGP peers
- Ingress replication using EVPN-learned remote VTEPs
- Single-homed access ports
- IPv4 or IPv6 payload inside the Ethernet frames
- Leaf/spine topology: leaves are VTEPs; spines carry RT-filtered EVPN transit without local VNIs and preserve the originating leaf's VTEP next hop

Out of scope (may be added separately later): route reflection, multihop overlay BGP, L3VNI, tenant routing, IRB/anycast gateways, ESI/multihoming and MLAG coexistence.

The existing foundations still apply: `Observe` by default, independent agent and controller write gates, UID-bound ownership, full-snapshot CAS, journals, and orphan-on-delete. Deleting a resource leaves device configuration in place; explicit shutdown is the way to withdraw.

## Resources and ownership

### SwitchVXLANTunnel

Keeps the existing `name`/`sourceAddress`/`evpnNVO` contract. Preflight checks a supported native stack, an unambiguous configured data-plane source address, its kernel assignment and compatibility with existing configuration.

Creating a tunnel must not depend on an existing hardware tunnel. A staged tunnel can be `ConfigurationReady` and `PersistenceReady` while it waits for its first mapping. `RuntimeReady` stays false until the native consumer creates the correlated SAI objects. Because the first mapping is what triggers hardware creation, the mapping controller must not wait for tunnel runtime readiness.

### SwitchVLANVNI

Keeps explicit VLAN, VNI, RD and import/export RTs, and requires a configured VLAN and tunnel/NVO. Readiness requires the tunnel-linked decapsulation map, matching encapsulation evidence where instantiated, and the exact RD/RT in the FRR VNI scope. A mapping on another tunnel cannot satisfy readiness. The L2-only and local isolation checks still apply.

### SwitchEVPN

One resource per switch owns global L2 EVPN advertisement. Its spec contains `switchRef`, `managementPolicy`, a tunnel reference, an explicit set of `SwitchVLANVNI` references and `adminState` (`Down` by default). References resolve only to resources on the same switch; alias endpoints count as the same device.

It exclusively owns the `BGP_GLOBALS_AF` default/l2vpn_evpn advertisement fields, including `advertise-all-vni`. It rejects unmanaged local VNIs before enabling global advertisement. SVI, default-gateway and IP-prefix origination are disabled. Every connected peer needs a verified policy before advertisement starts, and an empty mapping set cannot be activated.

Existing tunnel, mapping and `Down` peer resources remain valid and can be observed or staged without opting into activation.

### SwitchEVPNPeer

The peer references the local mappings it may carry. These references resolve to a bounded policy snapshot (identities, VNIs and RT sets). The controller checks resource UID, generation and endpoint freshness before dispatch, and the agent independently checks the snapshot against current configuration and ownership. A peer without a resolved policy cannot be activated.

The peer owns only its EVPN AF fields plus deterministic per-peer route maps and extended-community sets. It never owns the neighbor's ASN, source or shutdown. Inbound filters permit the declared import RTs, outbound filters permit the declared export RTs, and both end in an explicit deny. Wildcard permits, route-map call chains and unicast prefix lists are not used as EVPN RT policy. A matching RT does not prove local origination, and the design makes no such claim.

Peers have a role:

- **Leaf** (default): carries local mapping references.
- **Transit**: uses bounded explicit import/export RT sets, forbids mapping references and requires `unchanged_nexthop=true`, rendered as `neighbor PEER attribute-unchanged next-hop`. Transit peers need no local tunnel, mapping hardware or global advertisement owner, but require the same verified filters, AF state, parent identity and ownership as leaf peers. Route reflection and AS-path rewriting are not enabled.

Leaves should use distinct ASNs and advertise their VTEP /32 addresses into the underlay so that EVPN next hops resolve through either spine.

### SwitchBGPPeer

Keeps ownership of neighbor identity and shutdown. A neighbor shared with EVPN can go `Up` only after its EVPN AF, policy and switch-level dependencies are configured, durably recorded and verified in FRR. This check must not require an established session, otherwise activation would deadlock.

Unicast AF policy is still enforced independently. The BGP and EVPN reconcilers must accept the exact supported live configuration and reject conflicting ownership or unsafe policy changes regardless of which reconciles first.

## Activation sequence

### Why initialization comes first

FRR 10.4.1 ignores per-VNI RD/RT commands until `advertise-all-vni` is enabled. Requiring verified RD/RTs before global advertisement would therefore be a circular dependency. Instead, setting `SwitchEVPN` to `Up` first performs local-only initialization while every CONFIG_DB and FRR neighbor is shut down and every EVPN AF is disabled. This step does not wait for mapping hardware or RD/RT acknowledgement, so configuration and persistence can be ready while runtime is not.

The declared mapping snapshots are recorded in the global owner's journal and cannot be replaced implicitly. Referenced mapping resources must exist before initialization, but their device rows need not. Later mapping creation must match a recorded mapping UID and its exact VLAN/VNI/RT intent, with all sessions still shut down. AF and parent activation both require converged hardware and RD/RT state plus verified policy.

### Steps

1. Verify the supported stack. Create the routed underlay and source addresses. Stage the BGP instance and shared neighbors `Down` with the existing unicast safeguards.
2. Configure the tunnel/NVO, declare the mapping resources, initialize the global owner with all sessions shut down, then apply the VLAN/VNI mappings. Observe hardware and RD/RT convergence without inferring it from CONFIG_DB.
3. Stage per-peer import/export filters and disabled EVPN AFs. Verify the exact FRR definitions, attachments, default deny and extended-community transport.
4. Verify that the switch-level resource reaches runtime readiness once its declared mappings converge. Reject unknown active neighbors, unmanaged VNIs and dynamic peer groups.
5. Enable the EVPN AF while the parent neighbor is still shut down. Verify the applied AF configuration without requiring a session.
6. Enable the parent BGP neighbor. Observe negotiated EVPN capability, `Established` state and correct peer identity, then remote route and FDB installation.

Each step is journaled independently; there is no atomic transaction across resources or switches. Because CONFIG_DB consumers apply changes asynchronously, definitions and policy attachments must be acknowledged before any step that permits advertisements.

Replacing mappings, RTs or policy requires the affected peers to be administratively down with native shutdown evidence. The lifecycle does not perform destructive remaps or implicit deletion. A `Down` request keeps filters and ownership and only disables the relevant AF or advertisement.

## Native implementation boundaries

- Persistent configuration goes through native CONFIG_DB consumers. The installed frrcfgd handler supports `route_map_in`, `route_map_out`, `send_community`, `match_ext_community`, `EXTENDED_COMMUNITY_SET`, `ROUTE_MAP` and `advertise-all-vni`. That shows handler support only, not startup ordering, key grammar, policy semantics or forwarding.
- Before each native write is implemented, its complete table/key/field contract and startup rendering are verified against pinned source and captured device output. If a consumer change is needed, it is implemented and qualified as a prerequisite. Ad hoc `vtysh` writes are not used, and verification is never removed to make a resource appear ready.
- Bootstrap eligibility is separate from post-create hardware proof. When native creation fails, the operator records unsupported, failed or pending evidence. It does not retry disruptive commands or delete uncertain hardware automatically.
- Code is separated by responsibility: native compatibility and bootstrap, policy planning and readback, activation coordination, and operational observation. Shared engine dispatch and allowlists are extended narrowly.

## Status and failure recovery

`ConfigurationReady`, `PersistenceReady` and `RuntimeReady` keep distinct meanings. For `Up` peers, `RuntimeReady` requires an established session with EVPN capability. Zero learned routes is valid when no remote endpoint exists; route counts and observed entries are reported as diagnostics.

Status explains why a dependency is pending, unavailable or unsupported. Remote FDB evidence is tied to the correct MAC, VLAN/VNI, remote VTEP and native tunnel objects. Packet delivery is never claimed from route counts or ASIC_DB entries alone.

Before writes and pending-operation recovery, the operator revalidates intent, ownership, peer policy and configuration snapshots. `Down`/`Up` changes only durably owned admin fields. Restart recovery verifies persisted configuration and re-established runtime and does not replay activation blindly. Observation errors keep any independently valid evidence and block new writes.

## Acceptance criteria

### Off-switch tests

- Admission and defaulting, immutable identities, duplicate and alias claims
- Staging on an empty VXLAN state succeeds; unknown stacks fail explicitly
- The first mapping creates hardware without a tunnel/mapping readiness cycle
- Foreign, wrong-source or untranslated hardware cannot produce readiness
- Correct import/export filters, default deny, attachments and community mode
- No AF or neighbor activation before policy acknowledgement; stale mapping references or parent-neighbor changes block activation
- Shared unicast/EVPN reconciliation in both orders, including live operation
- Interrupted CAS/save, restart recovery, explicit shutdown and orphan deletion
- Captured native output fixtures, malformed or partial output, command deadlines
- Full race and integration suite, generated artifacts, vet and builds

### Hardware tests

- Use two VTEPs with two truly separate access endpoints. Do not bridge the endpoints locally, which would bypass VXLAN. Use two VNIs to test both delivery and isolation.
- Run through the Kubernetes controller and mTLS agents.
- Capture Type-3 replication state, learned Type-2 routes, remote MAC/VTEP correlation and bidirectional traffic.
- Verify encapsulation and decapsulation with packet captures, cold MAC learning and unknown-unicast/broadcast behavior.
- Test cross-VNI and undeclared-RT rejection, endpoint removal and route withdrawal, underlay loss and recovery, AF shutdown and peer restart persistence.
- Verify next-hop preservation through transit, transit via both spines and single-spine failure.
- Report measured packet loss and convergence times.

Before testing, back up running and saved configuration, journal hashes and link state. Afterwards, restore the intended configuration: remove overlay hardware in native dependency order before deleting interfaces, and check for leftover SAI objects instead of relying on CONFIG_DB equality. If normal cleanup cannot finish, a disruptive reload or reboot requires an explicit decision.

Qualification requires evidence of packet delivery and negative isolation, not just passing mocks or established BGP sessions. If endpoint access or native capability prevents a test, the blocker is reported and the feature stays unqualified.
