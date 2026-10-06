# BGP and DHCP Relay

Use `SwitchBGP`, `SwitchBGPPeer` and the DHCP relay resources to manage a minimal, explicit BGP configuration and DHCPv4/DHCPv6 relay on SONiC switches. The operator writes native CONFIG_DB entries and relies on the shared network writer for ownership, snapshot compare-and-swap (CAS), persistence and the activation journal.

- **Observe** mode performs read-only probes only.
- **Manage** mode requires the manager and agent `--allow-network-config` opt-in and a private, persistent network journal.

::: warning DHCP relay restarts
Managing legacy IPv4 or IPv6 relay restarts the shared `dhcp_relay.service`. This interrupts **all** relay instances in that container, including VLANs the operator does not manage. There is no separate per-resource restart flag.
:::

The ordinary BGP and relay backend never restarts SONiC, replaces `frr.conf`, changes the FRR management mode, or accepts arbitrary command text.

## Capabilities and mapping

| Feature | Native mapping and behavior |
| --- | --- |
| Unified BGP IPv4/IPv6 | `BGP_GLOBALS|<vrf>`: `local_asn`, `router_id`, `default_ipv4_unicast=false`, `default_shutdown=true`. Requires an existing `DEVICE_METADATA.frr_mgmt_framework_config=true`. |
| Explicit prefixes | `BGP_GLOBALS_AF_NETWORK|<vrf>|ipv4_unicast\|ipv6_unicast|<prefix>`, `backdoor=false`. Canonical networks only, no redistribution. An empty list originates nothing. FRR only originates a network if a matching route exists. |
| Export filters | `PREFIX_SET.mode=IPv4\|IPv6` and `PREFIX.action=permit\|deny`. Exact permits for the requested prefixes, followed by deny-all at sequence 4294967295. Names are `SONIC_OPERATOR_<VRF hash>_<AF>`. |
| Peers | `BGP_NEIGHBOR|<vrf>|<IP>`: `asn`, optional `local_addr`, `admin_status`. IPv4 or IPv6 transport. Default admin state is Down. |
| Peer address families | `BGP_NEIGHBOR_AF|<vrf>|<IP>|ipv4_unicast\|ipv6_unicast`: `admin_status=up`, `prefix_list_out`, `send_default_route=false`. One or both unicast AFs, independent of the transport family. |
| Prefix limit | Per-AF `max_prefix_limit`, default 1000 and nonzero, with `max_prefix_warning_threshold=100`. An existing warning-only or automatic-restart policy is rejected. |
| Traditional BGP | Not supported for ordinary BGP writes. Traditional templates automatically originate loopback/VLAN networks and do not provide this maximum-prefix and export-policy contract. Switches with empty routing configuration can use the [FRR migration workflow](./frr-migration.md). Translating a populated router is not supported. |
| Legacy DHCPv4 | `VLAN|VlanN.dhcp_servers@`. Create/update, then a journaled relay restart and verification of the actual per-VLAN process arguments. |
| Native DHCPv4 | `DHCPV4_RELAY|VlanN.dhcpv4_servers@` when `has_sonic_dhcpv4_relay=True`. Dynamic consumer; supports default and non-default VRFs on the same SVI. Native applied-configuration readback is not available, so runtime stays unverified rather than inferred from process presence. |
| DHCPv6 | `DHCP_RELAY|VlanN.dhcpv6_servers@`. Default VRF only. Create/update, then a journaled restart and startup-configuration verification. Non-default VRFs are rejected. |

The `@` suffix is raw Redis list serialization. YANG models and consumers use the field names without it. IPv6 destinations are not written to `VLAN.dhcpv6_servers`, because the SONiC IPv6 relay consumer reads `DHCP_RELAY`.

### Switching between Unified and Traditional

The [FRR migration workflow](./frr-migration.md) moves a switch with empty routing configuration between Unified and Traditional mode. Key points:

- Reverse a migration by editing **the same** `SwitchFRRMigration` resource (for example `switch-a-unified`) to `mode: Traditional`. Keep its UID and binding, and replace the old approval only after reviewing a fresh Traditional preview. Do not apply a second resource for the opposite direction.
- Pending work recovers its original mode first.
- Traditional mode explicitly writes `frr_mgmt_framework_config=false` and `docker_routing_config_mode=separated`, even if those fields were absent before.
- Both directions require empty routing in CONFIG_DB and at runtime (including peers), and restart `bgp.service`, which causes a routing-service outage.
- Migrating to Traditional does not enable ordinary BGP management in Traditional mode.

## Staged peer activation

Peers are activated in two separate requests:

1. Create `SwitchBGP` with the desired explicit prefixes (default: empty).
2. Create the peer with `adminState: Down` and its complete address-family, limit and filter policy.
3. Change only `adminState` to `Up`. The peer must already exist with every other desired field matching CONFIG_DB, and the shared engine must own its admin field.
4. Preflight reads the actual FRR configuration and requires the staged peer to be shut down, with matching ASN and source address, exact AF activation, hard maximum-prefix, explicit networks and exact outbound prefix lists. Missing or stale evidence blocks the write. Only then does the engine CAS the owned admin field to Up.

During recovery, preflight runs again before a pending pre-state CAS. A pending post-state does not require the peer to go Down again. Runtime verification checks the resulting FRR configuration independently of CONFIG_DB. The peer does not need to establish a session to prove its administrative configuration.

Rules for policy changes:

- Global BGP policy changes require all CONFIG_DB peers to be Down, no dynamic groups, **and** all runtime neighbors in the target instance to be shut down in FRR. Runtime-only neighbors count too.
- Peer policy writes also check actual FRR shutdown.
- You cannot shut down an Up peer and edit its policy in the same request.
- New peers created as Up, and requests that change policy and set Up together, are rejected.

```yaml
# SwitchBGP spec (switchRef and managementPolicy omitted)
vrf: default
localASN: 65000
routerID: 192.0.2.1
prefixes: []
```

```yaml
# SwitchBGPPeer spec; change only adminState to Up after staging
vrf: default
address: 2001:db8::2
remoteASN: 65001
localAddress: 2001:db8::1
addressFamilies: [ipv4Unicast, ipv6Unicast]
adminState: Down
maxPrefixes: 1000
```

### Validation rules

- The optional `localAddress` must exist on an L3 interface in the same VRF and have the same family as the transport.
- ASNs are nonzero uint32. Changing the local ASN is not supported by the SONiC consumer.
- `routerID` must be a unicast IPv4 address.
- `vrf` is `default` or an existing `VrfNAME` of at most 15 characters.
- The following are rejected: prefix removal, prefix reordering, inherited peer-group policy, conflicting unmanaged origination or import policy, and extra operator-reserved prefix-list entries.
- Unrelated fields are left untouched. The export filter only protects peers that reference it.

## DHCP relay

```yaml
vlanID: 100
vrf: default
ipv4Servers: [192.0.2.2]
ipv6Servers: [2001:db8::2]
```

Requirements:

- The VLAN/SVI must exist, belong to the requested VRF, and have an address for each requested family.
- Server addresses are parsed strictly by version. Duplicate, IPv4-mapped, multicast, link-local, interface-scoped, unspecified, loopback and limited-broadcast addresses are rejected. Private IPv4 and IPv6 ULA addresses are allowed.
- At least one server list must be non-empty.
- Non-default VRFs are supported only for native IPv4 relay.
- DualToR, VNET and source/server-VRF overrides are not supported. The DHCP server feature conflicts with IPv4 relay management.

### Activation

Before the CAS, the shared engine records the original request, the expected fields, and full pre/post CONFIG_DB fingerprints. It records the activation as `Prepared`, then `Dispatched`, before running exactly:

```text
systemctl restart dhcp_relay.service
```

The restart callback is kept when replanning against the post-state, so recovery does not lose a required restart. Owned destination-list updates are allowed only when the durably recorded old value still matches; foreign values and drift are rejected. Removing a family's fields is not part of the additive lifecycle.

### Startup verification

The relay container's `docker_init.sh` renders its supervisor configuration from CONFIG_DB on every container start (IPv6 destinations do not appear in that file). To verify startup, the backend checks that:

- the desired fields and the full CONFIG_DB fingerprint are unchanged across the restart;
- the container ID and start timestamp differ from the recorded pre-launch identity;
- the installed supervisor configuration equals a fresh read-only render;
- the required relay process exists with the recorded PID, start time and argv;
- for legacy IPv4, the actual downstream VLAN and exact server arguments match;
- for IPv6, the program is present in the generated configuration and its process is running.

### Launch receipt

A private receipt at `<network-journal-dir>/relay-runtime/launch.json` records the expected relay configuration and pre-launch identity before the restart, and the verified container, generated-config hash and process hash afterwards.

- It is written by atomic rename with file and directory fsync, inside the network journal's writable persistent path (including under systemd `ProtectSystem`).
- Ensure preflight creates and validates the storage and probes write, file fsync, rename, cleanup and directory fsync before any CAS or activation dispatch. Existing launch evidence is preserved.
- Invalid, symlinked, malformed or read-only storage fails before any CONFIG_DB change or pending activation record. Reads never create storage.
- It contains fingerprints and identities only, not unrelated configuration or credentials.

Transaction and runtime fingerprints have different scopes:

- The engine checks the **full** CONFIG_DB for the pre/post CAS and for stability during activation.
- Long-lived receipts hash only relay configuration and its dependencies: relay tables and options, VLAN/member/SVI and upstream/loopback addressing, referenced VRFs, relay feature/mode metadata and port aliases. Unrelated static routes, unused VRFs and BGP settings do not invalidate `RuntimeReady` or trigger a restart. Generated-config and process/container identity checks still apply.

### Recovery

- After a lost response or agent crash, the engine does not replay a dispatched restart.
- Runtime verification can bind a fresh launch to the pre-dispatch receipt and unchanged relay inputs, or use a completed receipt.
- Failed or stale generation, missing processes, an unchanged container, or transaction DB drift keep the activation pending.
- No-op runtime proof avoids restarting an already verified relay.
- If dispatch happened before launch evidence could be recorded, recovery fails closed and requires operator inspection.

### What "verified" means

- IPv6 `RuntimeVerified` means **startup configuration and activation evidence**, not per-destination telemetry or forwarding success.
- A mixed native IPv4/IPv6 restart can prove shared startup with both processes; the observation still states that native IPv4 applied-config readback is unavailable.
- Native IPv4-only dynamic updates stay runtime-unverified until such readback exists.
- A process-only observation is never presented as a forwarding test.

## Runtime commands

All read-only commands are fixed. No request field is passed into argv, and no shell is evaluated.

```text
docker exec bgp supervisorctl status
docker exec bgp vtysh -c "show running-config"
docker exec bgp vtysh -c "show bgp vrf all summary json"
docker exec dhcp_relay ps -eo args=
docker inspect --format <fixed identity JSON template> dhcp_relay
docker exec dhcp_relay cat /etc/supervisor/conf.d/docker-dhcp-relay.supervisord.conf
docker exec dhcp_relay sonic-cfggen -d -t /usr/share/sonic/templates/docker-dhcp-relay.supervisord.conf.j2
docker exec dhcp_relay python3 -c <fixed read-only numeric /proc PID/argv/start-time query>
```

| Operation | Limit |
| --- | --- |
| Each read | 4-second deadline, bounded output, bounded by the caller's deadline |
| Relay restart | 60-second deadline |
| Activation | 100-second budget, bounded by the engine deadline |

Raw FRR configuration and stderr are never returned, because they can contain credentials. Structured observations contain verification flags, peer states and `forwardingTested=false`.

## Tested hardware and known limitations

| Item | Value |
| --- | --- |
| Platform | Dell Z9100 |
| SONiC | `SONiC.202511.1217682-4784cca11` |
| FRR | 10.4.1 |

The switch was inspected read-only. It ran traditional `bgpcfgd`, with the unified consumer installed but inactive, and had no BGP instance or relay forwarding configured. No configuration was deployed to it.

Automated coverage: unit tests cover strict parsing, native mappings, both BGP AFs, FRR preflight, stale Redis-only shutdown, exact limits and filters, the relay command sequence, launch-receipt durability and drift. Integration tests run the real planners and shared engine against a disposable Redis, replacing only fixed external command execution. They cover staged Down-to-Up, stale-policy rejection, Observe without restart, legacy IPv4/IPv6/dual-stack create and update, recovery from a lost restart response without replay, no-op behavior, relay readiness surviving an unrelated VRF change without restart, and malformed or read-only receipt storage causing no CONFIG_DB change and no pending dispatch.

Not tested on hardware: live peer advertisements, DHCP lease exchange, traffic or VRF isolation, service restarts and live persistence. Configuration evidence and forwarding tests are separate.

Not supported:

- translating populated traditional BGP configuration;
- advanced routing and relay options;
- BGP authentication;
- IPv6 relay in a non-default VRF;
- per-target applied-config telemetry for native dynamic IPv4 relay;
- destructive cleanup;
- automatic replay of uncertain commands.

### SONiC behavior notes

These SONiC 202511 behaviors shaped the implementation:

- The unified `frrcfgd` handles global, neighbor-AF, network and prefix-set fields dynamically and renders the same fields on restart (`bgpd.conf.db*.j2`).
- Traditional `bgpcfgd` subscribes to a limited set of updates, and its `bgpd.main.conf.j2` template automatically originates networks.
- `dhcp_relay.service` runs `dhcp_relay.sh`; the container's `docker_init.sh` regenerates supervisor config with `sonic-cfggen -d` and then starts supervisor.
- The DHCPv6 relay loads `DHCP_RELAY` at startup. The native DHCPv4 relay consumes `DHCPV4_RELAY` dynamically and defaults the server VRF to the SVI VRF. (Based on the upstream [sonic-dhcp-relay](https://github.com/sonic-net/sonic-dhcp-relay) release branch, not on verification of the installed binary.)
- The host `config` CLI plugin for DHCP relay writes the supported tables and restarts the service, except for native IPv4. The legacy `config vlan dhcp_relay add` command writes IPv6 servers into `VLAN`, which the IPv6 template does not read, and mixed-family batches depend on the family of the last address. The operator does not use this CLI.
- FRR 10.4.1 renders a `shutdown` line for a shut-down peer but no explicit `no neighbor ... shutdown` for an enabled peer.
