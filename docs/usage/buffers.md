# Buffers and TC-to-priority-group mappings

Typed buffer resources describe SONiC buffer pools, buffer profiles, and the priority-group (PG) and queue bindings that reference them. Together with the `TCToPriorityGroup` QoS map type they let you declare and observe a switch's buffer configuration, and, once native qualification is available, adopt and repair it.

::: warning Native ownership is not available yet
On the tested SONiC builds, the buffer consumers do not expose an independent configured-name-to-OID mapping or a pending-removal lifecycle acknowledgement. Without that evidence the agent cannot prove which configured object a PG or queue is bound to. It therefore returns an explicit producer-instrumentation capability error, never reports `RuntimeVerified` for buffer resources and does not enable buffer writes. Use these resources with `managementPolicy: Observe` for now.
:::

## Resources

All resources are cluster-scoped, share the [network resource lifecycle](./network-resources.md) and default to `managementPolicy: Observe`. Native references are SONiC names on the target switch, not Kubernetes object references.

| Kubernetes kind | Native table and key | Declared fields |
| --- | --- | --- |
| `SwitchBufferPool` | `BUFFER_POOL\|name` | `type`, `mode`, `size`, optional `xoff` |
| `SwitchBufferProfile` | `BUFFER_PROFILE\|name` | `pool`, `size`, exactly one of `dynamicThreshold`/`staticThreshold`, optional `xon`, `xoff`, `xonOffset` |
| `SwitchBufferPG` | `BUFFER_PG\|interfaceName\|range` | `profile` |
| `SwitchBufferQueue` | `BUFFER_QUEUE\|interfaceName\|range` | `profile` |
| `SwitchQoSMap` with `type: TCToPriorityGroup` | `TC_TO_PRIORITY_GROUP_MAP\|name` | explicit TC-to-PG entries |
| `SwitchQoSBinding` with `tcToPriorityGroup` | `PORT_QOS_MAP\|interfaceName` | `tc_to_pg_map` |

### Field rules

- Pool `type` is `ingress` or `egress`; `mode` is `static` or `dynamic`.
- Sizes, headroom and static thresholds are in bytes. An explicit zero reserved profile size is preserved.
- `dynamicThreshold` is a signed integer from -8 to 7.
- PG profiles must reference ingress pools and queue profiles must reference egress pools. A profile's threshold mode must match its existing pool.
- Buffer names have up to 32 letters, digits, underscores and hyphens, and begin with a letter or digit.
- Bindings use a canonical `EthernetN` name and one index or an inclusive ascending range such as `0-7`. The exact native range is kept rather than expanded into possibly overlapping keys.
- Schema bounds are PG 0–7, queue 0–255 and, for TC-to-PG maps, TC 0–15 and PG 0–7. These are schema limits, **not hardware capability claims**.
- A grouped native port selector or a range that intersects the requested target is a conflict, even if it uses the same profile.
- Missing or unsupported native dependencies stop planning before any journaled change.

`switchRef`, resource names and binding interface/range targets are immutable. A pool's `type` (direction) is mutable intent; its name is its identity.

### Example

See [`config/samples/buffers.yaml`](https://github.com/kubermatic-labs/sonic-operator/blob/main/config/samples/buffers.yaml) for a pool, profile, PG and queue. A PG binding looks like this:

```yaml
apiVersion: sonic.networking.metal.ironcore.dev/v1alpha1
kind: SwitchBufferPG
metadata:
  name: leaf-01-ethernet8-pg0
spec:
  switchRef:
    name: leaf-01
  managementPolicy: Observe
  interfaceName: Ethernet8
  range: "0"
  profile: ingress_lossy_profile
```

## Ownership and repair

Only explicitly declared fields are reserved. In particular, `tcToPriorityGroup` does not own or change `pfc_enable`, `pfcwd_sw_enable` or other `PORT_QOS_MAP` fields.

- **Adoption** requires current values equal to the declaration. Matching observed native state is not an ownership claim, and observation never creates a journal record.
- **Repair** restores qualified, non-deletion value drift of owned fields. It never creates objects or changes buffer allocations. It requires independent producer identity and lifecycle evidence, in addition to CONFIG_DB, APPL_DB, COUNTERS topology, native attributes and VIDTORID.
- **Conflicts:** foreign owner claims, changed desired values, field removals, changed unowned dependencies and replacement native identities all block reconciliation.
- **TC maps** are compared as validated semantic mappings, independent of JSON order. During repair only owned TC entries may differ. The standalone port path accepts only a `tc_to_pg_map` row and requires every other QosOrch-managed mapping on that port to be unset.

### Controller repair contract

The agent sets `NetworkResult.bufferRepairEligible` only for an owned, non-pending record after a fresh, complete repair preflight succeeds. Qualified value non-convergence then reports `RuntimeVerified=false` without a probe error, which lets the controller call Ensure even though configuration and persistence already match. Unknown probe errors, identity or lifecycle differences, unowned drift, deletions and unsupported PG/queue reapplication keep returning errors and never authorize writes. Other resource kinds cannot use this flag, and all controller freshness and write gates still apply.

### Qualified consumer builds

The read-only probe hashes `/proc/<pid>/exe` in the `swss` container and requires exactly one running instance of each consumer:

| Executable | SHA256 |
| --- | --- |
| `orchagent` | `fed521d9700df9b79a22696d5b50f2308e1e7cf1bfccda59b458e7f59c7d2939` |
| `buffermgrd` | `682a6b8bbe3b2b0ed132ba26eaad7c2b0992ef68866542336fc8083b698398bb` |

A different consumer build, dynamic buffer management, replacement native identities, new unbound objects, new values or changes to native create-only attributes need renewed qualification and fail closed.

## Known limitations

- **PG and queue rebinding:** SONiC's BufferOrch skips a SET when its cached profile name is unchanged. Pure out-of-band ASIC binding drift with unchanged CONFIG_DB therefore cannot be repaired by rewriting the same value; the agent reports a capability failure instead of issuing an ineffective write.
- **Deleted rows:** if an owned CONFIG_DB or APPL_DB field is deleted, the consumed DEL may leave a referenced object pending removal or remove PG counters, and a later equal SET cannot safely cancel that. Deleted-row repair, unbind/rebind, native object recreation and daemon restarts are not supported.
- **Hardware:** new consumer builds or buffer allocations need their own read-only qualification and hardware validation.

## Writes and recovery

Writes need the network and traffic-policy gates on both the manager and the agent (`--allow-network-config=true`, `--allow-traffic-policy=true`), the agent's `--read-only=false`, its private durable network journal, and `managementPolicy: Manage`. Native graph and consumer qualification are checked before every write, including during recovery.

- Recovery uses the saved request, independent of later edits to profile, threshold or pool direction.
- Pending repair saves keep the original request and proof across agent restarts. A successful compare-and-swap is not repeated just because saving was interrupted.
- Deleting a declaration does not delete native configuration or transfer ownership. The finalizer is released only after recorded pending persistence is resolved.
- The journal records include native qualification evidence that older agents cannot parse. Upgrade all agents before creating buffer records, and do not roll back below a release that understands them.
