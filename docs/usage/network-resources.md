# Network Resources

The operator provides cluster-scoped resources that describe additive network
configuration on a SONiC switch: port channels, VRFs, L3 interfaces, static
routes, BGP, BGP peers and DHCP relay. An additional resource,
`SwitchFRRMigration`, switches the FRR management framework on switches with
empty routing state.

Every resource requires `spec.switchRef.name` and defaults to
`spec.managementPolicy: Observe`. Applying a resource in `Observe` mode does not
configure the switch. The resources express desired intent; whether a given
SONiC image supports a field is still subject to backend capability checks and
runtime verification.

Related APIs are documented in [traffic policy](traffic-policy.md) and
[MLAG / EVPN / VXLAN redundancy](redundancy.md). Each has its own default-off
write gates and staging requirements.

## Resource kinds

| Kubernetes kind | Agent kind | Duplicate claim key within a switch |
| --- | --- | --- |
| `SwitchPortChannel` | `PortChannel` | `name` |
| `SwitchVRF` | `VRF` | `name` |
| `SwitchL3Interface` | `L3Interface` | `name`, regardless of VRF |
| `SwitchStaticRoute` | `StaticRoute` | `vrf` + canonical `prefix` |
| `SwitchBGP` | `BGP` | `vrf` |
| `SwitchBGPPeer` | `BGPPeer` | `vrf` + normalized `address` |
| `SwitchDHCPRelay` | `DHCPRelay` | `vlanID`, regardless of VRF |
| `SwitchFRRMigration` | `FRRMigration` | Legacy opaque `unified` identity, regardless of requested mode |

Duplicate claims are detected with uncached API reads. Switch objects that use
the same normalized management endpoint are treated as aliases. DNS aliases
that resolve to the same device cannot be detected at the API level; the
agent's durable owner-UID journal is the final ownership boundary.

## Enabling writes

Writes happen only when all of the following are true:

1. The manager runs with `--observe-only=false --allow-network-config=true`.
2. The resource sets `managementPolicy: Manage`.
3. The agent allows writes and network configuration through its corresponding
   flags, and has a private, persistent `--network-journal-dir`.
4. The resource is valid, its dependencies are compatible, and no competing
   claim exists for the same target.

`SwitchFRRMigration` additionally requires `--allow-frr-migration=true` on both
manager and agent, a fresh eligible preview matching the requested mode, and
the exact `approvedDigest` for each new transition. See
[FRR migration](./frr-migration.md).

### Target binding

Before the first device write, the controller stores a hash that binds the CR
UID, Switch UID, management settings and network target in the
`sonic.networking.metal.ironcore.dev/network-target` annotation.

- The reconciliation that writes this annotation does not touch the device.
- The next attempt re-reads claims, the CR and the Switch directly from the API
  before calling Ensure.
- If the bound Switch identity or endpoint changes, writes are blocked. Restore
  the original target; do not remove the annotation.
- Before Ensure, the controller records the exact request in
  `sonic.networking.metal.ironcore.dev/network-request` and adds the
  `sonic.networking.metal.ironcore.dev/network-recovery` finalizer.

### Ownership and timeouts

- Device requests carry `OwnerID` set to the CR UID. A resource recreated with
  the same name has a new UID and does not inherit device ownership.
- The spec is sent as structured JSON, not as shell commands or a generic
  CONFIG_DB table API.
- Observation calls time out after 15 seconds; Ensure and recovery calls after
  120 seconds. An earlier caller deadline takes precedence.

## Recovery and deletion

The agent must implement the `NetworkRecoveryClient.RecoverNetworkResource`
capability; the controller requires it before the first Ensure. Recovery only
completes an operation already recorded in the agent journal. It does not apply
new intent, remove device state or release ownership.

- While the recovery finalizer exists, reconciliation first recovers the
  recorded request, then handles newer intent.
- Deletion also recovers the recorded request, even if the current spec has
  changed or become invalid.
- A successful recovery means pending persistence completed or nothing was
  pending. A "nothing pending" response may have empty configuration, runtime
  and persistence flags; it does not mean current intent is ready.
- After successful recovery and fresh CR/endpoint checks, deletion removes only
  the recovery finalizer. Device configuration and the journal owner record are
  left in place (orphaned).
- Recovery errors, a missing capability, target changes or disabled write gates
  (manager, resource or agent) keep the finalizer and report readiness as
  `Unknown`. Restore the gates and the original endpoint to finish recovery.

## Fields and defaults

| Resource | Fields and defaults |
| --- | --- |
| Port channel | `name: PortChannel0..9999`; unique `members: [EthernetN]`; `minLinks: 1`; `lacpMode: active` (only supported mode); `fastRate: false`; `mtu: 9100`; `adminState: Up` |
| VRF | `name: VrfNAME` (maximum 15 characters); no VNI; does not create the management or default VRF |
| L3 interface | `name: EthernetN`, `PortChannelN`, `VlanN` or `LoopbackN`; `vrf: default`; unique dual-stack `addresses` in CIDR notation, retaining host bits |
| Static route | `vrf: default`; canonical network `prefix`; `nextHops` with IP `address`, optional `interfaceName`, and `distance: 1`; next-hop family must match the prefix |
| BGP | `vrf: default`; `mode: Unified`; nonzero `localASN`; IPv4 `routerID`; `prefixes: []` (no implicit redistribution or advertisements) |
| BGP peer | `vrf: default`; IP `address`; nonzero `remoteASN`; optional same-family `localAddress`; `addressFamilies: [ipv4Unicast, ipv6Unicast]` (at least one); `adminState: Down`; `maxPrefixes: 1000` |
| DHCP relay | `vlanID: 1..4094`; `vrf: default`; independent `ipv4Servers` and `ipv6Servers`; at least one server is required in both Observe and Manage |
| FRR migration | Required mutable `mode: Unified` or `Traditional`; optional lowercase SHA256 `approvedDigest` from the fresh preview for that target |

Validation rules:

- Switch references, target identifiers and VRF bindings are immutable.
- Names must be canonical native names, not aliases.
- L3 addresses keep host bits (`192.0.2.1/24`); route and BGP prefixes must be
  canonical networks (`192.0.2.0/24`).
- CRD CEL validation enforces IP families, canonical prefixes and immutable
  fields. Lists and strings are bounded. The controller and backend validate
  requests again before writing.
- ASN and maximum-prefix fields are unsigned 32-bit values, exposed with
  OpenAPI `int64` format and the range 1..4294967295.

`SwitchFRRMigration.spec.mode` is mutable intent for a single device-wide
target. Edit the existing CR (keeping its UID and binding) instead of creating
a second one. Recovery uses the originally recorded mode and approval before
considering a new target. `Traditional` explicitly sets the framework metadata
to `false`/`separated` rather than removing the fields. Both directions require
empty routing and restart `bgp.service`.

### Sample

[`config/samples/network-features.yaml`](https://github.com/ironcore-dev/sonic-operator/blob/main/config/samples/network-features.yaml)
contains the seven network resources. It assumes a Switch named `leaf` and an
existing VLAN 10.

- The dual-stack SVI, IPv4/IPv6 static routes, BGP instance, peer and relay all
  use `vrf: default`.
- `VrfBlue` is an independent named-VRF example; no other sample resource binds
  to it.
- All resources stay in `Observe`, the peer stays `Down`, and `prefixes: []`
  requests no BGP origination.

## BGP and DHCP relay activation

### BGP backend

The default `Unified` backend requires `frrcfgd` to be provisioned and active
before management, with
`DEVICE_METADATA|localhost.frr_mgmt_framework_config=true`. Traditional
`bgpcfgd` is not supported for the unified export-policy and maximum-prefix
behavior; a narrowly qualified `Traditional` backend is described in
[Qualified traditional BGP](#qualified-traditional-bgp).

The BGP reconciler never migrates the FRR management mode or flips this
setting. For switches with empty routing state, use
[SwitchFRRMigration](./frr-migration.md). Translating existing routing
configuration is not supported, and setting the metadata flag on a running
traditional-mode switch is not a migration.

### Peer activation

Peers are activated in two steps:

1. Manage the peer with `adminState: Down` and its complete address-family,
   export-filter and maximum-prefix policy.
2. Change only `adminState` to `Up`.

Before activation, the backend verifies the staged policy and shutdown state in
the running FRR configuration. Creating a peer directly as `Up`, or changing
policy and activating in the same edit, is rejected. See
[BGP and DHCP Relay](./bgp-relay.md) for details.

### DHCP relay

- IPv6 relay is supported only in the default VRF.
- Named-VRF relay is supported only by the native DHCPv4 consumer. Legacy IPv4
  and IPv6 named-VRF requests are rejected.
- The SVI must be in the requested VRF and have an address for each relay
  family.
- At least one server is required, even in `Observe`.
- Legacy IPv4 and IPv6 relay management activates changes through a journaled
  restart of the shared `dhcp_relay.service`, followed by startup and runtime
  checks. **This restart interrupts all relay instances in the container,
  including unmanaged VLANs.**
- Native IPv4 uses its dynamic consumer. Applied-configuration readback is not
  available for native IPv4-only relay, so its runtime state is reported as
  unverified.

## Status

`status.observed` holds the agent's JSON object, including unknown nested
fields. `exists` is reported separately from configuration, runtime and
persistence verification. `observedGeneration` and each condition's observed
generation identify which spec was evaluated.

| Condition | Meaning |
| --- | --- |
| `ConfigurationReady` | The agent verified the desired configuration |
| `RuntimeReady` | The agent verified the corresponding runtime consumer; never inferred from CONFIG_DB alone |
| `PersistenceReady` | The agent verified durable persistence |
| `Synced` | Configuration and persistence are verified |
| `Ready` | The resource exists and all three verification dimensions are true |

Notes:

- BGP runtime verification checks administrative configuration, not peer
  session establishment.
- IPv6 relay runtime verification ties the journaled restart and fresh daemon
  launch to unchanged configuration and generated service configuration. It
  does not provide per-destination forwarding telemetry.
- No condition proves packet forwarding, DHCP leases or end-to-end
  reachability.
- An observation failure reports `Unknown`, not that the device is down.
- Configuration can match while runtime is unverified. A runtime failure alone
  does not trigger repeated Ensure calls if configuration and persistence
  already match.
- A failed Ensure has an unknown outcome. The next attempt consults the agent
  journal instead of assuming nothing was changed.

## Limitations

- **Deletion orphans device state.** No finalizer deletes configuration,
  withdraws routes, disables peers, removes relay servers or releases journal
  ownership. The recovery finalizer can delay deletion until pending saves are
  resolved.
- Changes are additive and preserve unknown or unmanaged configuration.
  Removing members, addresses, routes or relay servers is not supported.
- LAG members must exist, have compatible speed and MTU, and not belong to
  another LAG, VLAN or routed interface. Declare dependencies explicitly.
- L3 bindings require the VLAN or port channel and the VRF to exist. DHCP relay
  requires an SVI address for each enabled family in the matching VRF.
- The management interface `eth0` cannot be used.
- Ordinary network writes never replace the whole `frr.conf`. FRR migration
  validates the generated empty startup configuration and restarts only
  `bgp.service`. No whole-switch reload is requested.
- LACP supports active mode only; passive requests are rejected.
- Default-mode BGP requires the unified consumer. IPv6 relay requires the
  default VRF. A field existing in the CRD does not mean every SONiC image
  supports it.
- Enabling a peer is a separate `adminState: Up` edit. Test with a controlled
  peer before advertising prefixes, and verify DHCP forwarding with real
  clients for IPv4 and IPv6 separately.
- Controller and schema tests do not cover hardware forwarding, peer sessions,
  route advertisement or DHCP client behavior.

## Port fields and loopbacks

### Port speed, MTU and FEC

`SwitchInterface.spec.managementPolicy` controls the optional `speed`, `mtu`
and `fec` fields. It defaults to `Observe`. Physical admin state is managed
separately through its own annotation. Results are reported in
`status.portConfiguration`, independent of inventory and carrier state.

```yaml
apiVersion: sonic.networking.metal.ironcore.dev/v1alpha1
kind: SwitchInterface
metadata:
  name: existing-interface-resource
spec:
  switchRef:
    name: mgmt-01
  handle: existing-handle
  nativeName: Ethernet0
  managementPolicy: Observe
  speed: 1000
  mtu: 9100
```

- Use the existing resource name, handle and UID. Declare only values you have
  freshly verified on the device.
- Omitted MTU/FEC fields stay unowned; do not fill in defaults.
- Supported values: speed 1000, 10000, 25000 or 100000 Mbit/s; MTU 1280..9216;
  FEC `none`, `rs` or `fc`, only when already present on the port.
- `Manage` adopts equal values and repairs drift back to them. Changing an
  adopted value requires separate platform qualification and is rejected.
- Lane or layout changes block repair.
- Autonegotiated speed/FEC and MACsec MTU are out of scope.

Breakout interaction:

- A destructive breakout is refused if it affects typed port declarations,
  including `Observe` declarations and retained network bindings or recovery
  finalizers, unless the admin opts in.
- Durable Port journal records block topology changes even after the API
  object is deleted.
- Exact no-op breakout adoption and ordinary admin-state management remain
  compatible. Inventory cleanup never deletes a typed declaration to resolve a
  conflict.

Verification:

- Runtime compares APPL_DB with SAI port speed, MTU and FEC. A down carrier
  does not prevent configuration or persistence readiness.
- Persistence requires both the durable owner journal and a readback of
  `/etc/sonic/config_db.json`.
- Saved lanes, index, subport, autoneg and MACsec context must match the live
  context recorded in the journal. These are unowned context, not writable
  fields. A save that keeps a different layout stays pending until the saved
  configuration matches the adopted live layout.

### Loopbacks

`SwitchL3Interface` accepts canonical `Loopback0` through `Loopback4095`:

```yaml
apiVersion: sonic.networking.metal.ironcore.dev/v1alpha1
kind: SwitchL3Interface
metadata:
  name: mgmt-01-loopback0
spec:
  switchRef:
    name: mgmt-01
  managementPolicy: Observe
  name: Loopback0
  addresses:
    - 10.1.0.1/32
```

Loopbacks use native `LOOPBACK_INTERFACE` entries. Runtime verification
requires matching APPL_DB address rows and non-tentative kernel addresses on
the dummy interface, with the expected VRF binding. Saved-state readback is
checked independently. Deletion follows the usual orphan and recovery
behavior.

### Agent upgrade and rollback compatibility

Port records, `port_layout` and `LOOPBACK_INTERFACE` records are stored in the
shared network journal. Older agent versions that predate these record types
cannot load the journal, including pending operations. This applies to every
agent that writes network configuration on the switch. Adopting traditional
BGP adds another journal record type and raises the minimum compatible agent
version again.

Before enabling `Manage` for these resources:

- Make sure both the deployed agent and your rollback agent are built from a
  release that supports these journal records (and traditional BGP records, if
  you use that backend), including the fixes that preserve unmanaged daemon
  credentials, hostname and logging, the complete Loopback0 STATE_DB source
  check, saved port context checks, and the breakout/inventory fencing for
  typed ports.
- Bind each candidate to an immutable binary or image digest; a version label
  alone is not sufficient.
- Verify that the rollback candidate can load confirmed **and pending** Port,
  loopback and BGP journal records and complete failed-save recovery.
- Enforce this check before replacing the running agent, including during
  emergency rollback. A recovery artifact from before adoption does not qualify
  just because it starts.

Do not delete journals, drop unknown records, strip `port_layout`, transfer
UIDs or bypass recovery finalizers to make an older agent run. If no compatible
rollback artifact is available, do not adopt. This controller does not manage
agent lifecycle; enforce these checks in your deployment tooling.

## Qualified traditional BGP

`SwitchBGP.spec.mode` selects a backend; it is **not a routing-mode
migration**. It defaults to `Unified`. `Traditional` is an immutable opt-in for
a peerless LeafRouter on SONiC 202411 with FRR 10.0.1:

```yaml
apiVersion: sonic.networking.metal.ironcore.dev/v1alpha1
kind: SwitchBGP
metadata:
  name: mgmt-01-bgp
spec:
  switchRef:
    name: mgmt-01
  managementPolicy: Observe
  mode: Traditional
  vrf: default
  localASN: 65100
  routerID: 10.1.0.1
  prefixes:
    - 10.1.0.1/32
```

### Requirements

- The native `DEVICE_METADATA` ASN and LeafRouter type must match exactly; the
  backend adopts them.
- Declare Loopback0 separately with `SwitchL3Interface`. It must contain the
  single default-VRF /32 router ID.
- The complete Loopback0 STATE_DB address set must contain exactly the declared,
  ready /32. Additional IPv4 or IPv6, malformed or not-yet-ready rows block
  runtime qualification and activation. The operator does not delete these
  unowned entries. The set is checked during observation/preflight and again
  right before restart.
- Current daemon credentials, hostname and logging must match the native
  rendered baseline. These are unowned, so a mismatch blocks regeneration
  instead of being overwritten. The check repeats right before restart. Their
  values stay in memory and never appear in the API, journal or error messages.

### How it works

- Traditional bgpd templates generate the router ID, `network` statement and
  `PL_LoopbackV4` from Loopback0.
- The bgpcfgd `ZebraSetSrc` consumer generates `RM_SET_SRC` from intfmgr's
  STATE_DB readiness. This route-map is absent from the persisted zebra output
  by design and is verified in the running configuration.
- Generated `/etc/frr` files are startup outputs, not a raw replacement API.
  They are regenerated with the unmodified installed startup path.
- The qualified source digest pins the native consumer, FRR binaries, templates
  and constants. A different build needs qualification before writes.

### Behavior

- Initial adoption and equal-state reconciliation do not restart FRR.
- `Manage` can restore the recorded ASN/type and regenerate missing owned
  runtime policy using the durable restart journal. An unready Loopback0 blocks
  the restart.
- Failed or uncertain dispatches are not replayed; recovery requires exact
  runtime evidence.
- Changes to adopted ASN/type, peers, other routing policy, split/unified mode,
  unsupported startup mounts and unqualified native bundles are rejected.
- Readiness checks the running policy with empty neighbors, the saved inputs
  and their native rendered policy.
- This backend does not verify forwarding or neighbor establishment. Verify on
  the device after deploying a compatible agent.

## CONFIG_DB ownership reference

| CONFIG_DB scope | Owner |
|---|---|
| Typed network, VLAN, port and breakout fields | The network resources on this page and `SwitchInterface`. Omitted fields stay unowned. |
| Management addresses, routes and explicit MAC | `SwitchManagement`. An omitted MAC is retained with `macOwned: false`; the observed MAC is reported separately. |
| Supported NTP and SNMP fields | `SwitchSystem`. Credentials are not included in published artifacts. |
| `AUTO_TECHSUPPORT`, `BANNER_MESSAGE`, `CRM`, `FEATURE`, `FLEX_COUNTER_TABLE`, `KDUMP`, `LOGGER` | Not covered. Not owned and not verified against image defaults. |
| Password hardening, `SYSLOG_CONFIG`, `SYSTEM_DEFAULTS`, `VERSIONS` | Not covered. Not owned and not verified against image defaults. |

The presence of a table does not indicate whether its values are image
defaults. Existing network and artifact endpoint bindings are kept after a
management address change; rebinding to a new endpoint is not supported by
this flow. See also [site artifacts](../site-artifacts.md).
