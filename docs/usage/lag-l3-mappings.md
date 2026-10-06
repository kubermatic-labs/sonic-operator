# LAG and L3 Consumer Mappings

This page describes how port channel (LAG) and static route resources map to
SONiC CONFIG_DB tables and the daemons that consume them. The mappings were
verified against SONiC `202511.1217682-4784cca11`.

## LACP

Only **active LACP** is supported. SONiC's `teammgrd` always builds the teamd
runner with `active: true`, and there is no CONFIG_DB field for passive mode.
Passive requests are rejected rather than written as inert data.

| Table | Fields |
| --- | --- |
| `PORTCHANNEL` | `admin_status`, `mtu`, `min_links`, `fast_rate` |
| `PORTCHANNEL_MEMBER` | Physical membership |

`min_links` and `fast_rate` are only applied when the LAG is created. Changing
them on an existing LAG is rejected.

## Static routes

Both consumers read `STATIC_ROUTE|<vrf>|<canonical-prefix>` with
comma-separated, positionally aligned `nexthop`, optional `ifname` and
`distance` fields.

| Consumer | Selected when | `advertise` field | Runtime tag |
| --- | --- | --- | --- |
| Traditional `bgpcfgd` | `frr_mgmt_framework_config` absent or `false` | Written as `advertise=false` | 2 |
| Unified `frrcfgd` | `frr_mgmt_framework_config=true` | Omitted (not consumed) | 0 |

### Unified (`frrcfgd`) behavior

- The `STATIC_ROUTE` event handler enters the route's VRF and does not require a
  BGP ASN.
- The startup template (`/usr/local/sonic/frrcfgd/staticd.db.conf.j2`) checks
  that **every** field has the same number of entries. A scalar
  `advertise=false` on a multi-next-hop route would break startup rendering.
  The operator therefore omits `advertise` and rejects routes that already
  contain unsupported fields such as `advertise`, instead of removing them.
- The dynamic handler and the startup template produce identical commands for
  IPv4 ECMP and IPv6 VRF routes, with tag 0.
- Existing redistribution configuration in the target VRF is rejected. The
  operator does not create redistribution and does not rely on `advertise` to
  suppress it. BGP `network` statements are managed separately.

Runtime verification reads FRR JSON and checks the consumer-specific tag,
static protocol, distance and active next hops.

Changing the `frr_mgmt_framework_config` flag alone is not a supported way to
switch consumers on a running switch. Use [FRR migration](./frr-migration.md).

## Coexistence with other configuration

The port dependency checker understands the `PREFIX_SET`, `PREFIX`,
`DHCPV4_RELAY` and `DHCP_RELAY` schemas. It validates prefix identity,
sequence, family and mask ranges, relay VLAN identity, server families and
known option fields. Unknown fields and opaque selectors are rejected. A
relay's `source_interface` that references a physical port or LAG counts as a
dependency.

### Supported mode combinations

| Routing feature | `frr_mgmt_framework_config` | Routing config mode |
| --- | --- | --- |
| Static routes and BGP (unified) | `true` | absent, `separated` or `unified` |
| Static routes (traditional) | absent or `false` | absent or `separated` |

The BGP planner requires the unified framework (see
[Network Resources](./network-resources.md#qualified-traditional-bgp) for the
separately qualified traditional backend).

### Test coverage

- Planner tests cover BGP, peers, DHCP relay, LAG, physical and LAG L3
  interfaces and dual-stack static routes applied in both dependency-respecting
  orders, followed by re-planning the full configuration.
- Full fixtures cover dual-stack relay in the default VRF and native IPv4 relay
  in a named VRF, each combined with BGP, LAG/L3 and dual-stack static routes.
- Tests against a disposable Redis exercise field merging, journaling and
  preservation of unmanaged data.
- Service activation and hardware runtime are mocked. These tests do not cover
  live deployment or forwarding.

## Limitations

- Passive LACP is not supported.
- `min_links` and `fast_rate` cannot be changed after LAG creation.
- IPv6 DHCP relay in a named VRF is not supported, so a named-VRF IPv6 relay
  declaration is not a supported configuration.
