# ACL and QoS traffic policy

Five cluster-scoped resources manage ingress ACLs and QoS maps, schedulers and port bindings on SONiC switches. They use the shared [network-resource lifecycle](./network-resources.md). Each requires `switchRef.name` and defaults to `managementPolicy: Observe`.

The examples on this page are Observe-only intent. They do not show that a switch supports or has applied the policy.

| Kubernetes kind | Agent kind | Immutable target on a switch |
| --- | --- | --- |
| `SwitchACLPolicy` | `ACLPolicy` | `name` |
| `SwitchACLBinding` | `ACLBinding` | `policy` |
| `SwitchQoSMap` | `QoSMap` | `type` + `name` |
| `SwitchScheduler` | `Scheduler` | `name` |
| `SwitchQoSBinding` | `QoSBinding` | `interfaceName` |

- `switchRef` is also immutable.
- References to policies, maps and schedulers use native SONiC names on the switch, not Kubernetes object names.
- Endpoint aliases share duplicate-claim checks. The agent's owner-UID journal is the final ownership boundary.

## Write gates and recovery

Writes require all of the following:

| Component | Requirement |
| --- | --- |
| Manager | `--observe-only=false --allow-network-config=true --allow-traffic-policy=true` |
| Resource | `managementPolicy: Manage` |
| Agent | Write, network-configuration and traffic-policy gates enabled, plus a private, persistent network journal |
| Preflight | Fresh claim and endpoint checks, supported capabilities, compatible existing configuration, verified dependencies |

- The manager's `--allow-traffic-policy` defaults to **false** and gates both Ensure and Recover. Get observations work with write gates closed.
- Once a request is bound to the journal, closing a gate blocks recovery and keeps the finalizer, including during deletion.
- Before Ensure, the controller records the original Switch identity and endpoint, the resource target and the exact request, and persists the network recovery finalizer. Recovery completes the recorded operation before considering newer intent.
- Deleting a resource leaves device configuration and durable ownership in place. The finalizer is removed only after recovery and fresh identity checks succeed.
- Removing annotations or finalizers does not roll back a policy.

## ACL policies and bindings

An ACL policy creates an **unbound ingress** table plus an explicit priority-1 catchall rule from the required `defaultAction: Permit|Drop`. `rules` is required; use `[]` for a catchall-only policy. Up to 256 explicit rules are accepted.

Rule fields:

- Policy and rule names start with a letter and contain up to 64 letters, digits, underscores or hyphens. The rule name `DEFAULT` is reserved for the catchall.
- `family` is `IPv4` or `IPv6`. Optional `source` and `destination` are canonical network CIDRs of that family.
- Rule names and priorities are unique. Explicit priorities are `2..999999`.
- `action` is `Permit` or `Drop`. Optional `protocol` is `1..143`.
- Optional `sourcePort` and `destinationPort` are `0..65535` and require `protocol: 6` (TCP) or `protocol: 17` (UDP). `0` is a real value, not "absent".

Ownership and activation:

- The policy owns the table and rule fields. The binding owns only the table's `ports@` field. Policy staging never writes an empty `ports@` field.
- Binding requires consumer support for unbound tables and complete applied table, rule and counter evidence. Missing or unsupported evidence blocks activation.
- Binding `interfaces` are unique `EthernetN` or `PortChannel0..9999` names, up to 256.

```yaml
apiVersion: sonic.networking.metal.ironcore.dev/v1alpha1
kind: SwitchACLPolicy
metadata:
  name: example-ingress
spec:
  switchRef:
    name: leaf
  managementPolicy: Observe
  name: ExampleIngress
  family: IPv4
  defaultAction: Drop
  rules:
    - name: PermitHTTPS
      priority: 100
      action: Permit
      source: 192.0.2.0/24
      protocol: 6
      destinationPort: 443
---
apiVersion: sonic.networking.metal.ironcore.dev/v1alpha1
kind: SwitchACLBinding
metadata:
  name: example-ingress-port
spec:
  switchRef:
    name: leaf
  managementPolicy: Observe
  policy: ExampleIngress
  interfaces:
    - Ethernet0
```

Recommended order: manage the unbound policy first, confirm its complete applied evidence, then manage the binding. The binding does not install missing policies or rules. Conflicting existing policy fields are preserved; the additive lifecycle never replaces them destructively.

## QoS maps, schedulers and bindings

::: warning Current limitation: QoS bindings are blocked
The SONiC consumer does not provide a reliable acknowledgement that maps a profile name to its applied OID. As a result:

- Unreferenced maps and schedulers can be staged, but their runtime stays unverified.
- QoS bindings are blocked.
- Matching ASIC attributes or VIDTORID entries alone do not prove a named profile was processed.
- Creating or extending a profile that already has references (including dangling ones) is rejected, to avoid accidental activation.

Verified queue shaping and classification are therefore not available yet. No hardware packet or rate tests have been performed.
:::

`TCToPriorityGroup` maps and standalone `tcToPriorityGroup` bindings use the conditional ownership path described in [Buffers](./buffers.md). That path also needs native producer identity and lifecycle evidence that the tested SONiC builds do not provide, so it fails closed as well.

### Maps

Profile names contain 1..32 letters, digits, underscores or hyphens and start with a letter or digit. Map `type` is one of:

| Type | `entries[].from` | `entries[].to` |
| --- | --- | --- |
| `DSCPToTC` | DSCP `0..63` | Traffic class |
| `Dot1pToTC` | Dot1p `0..7` | Traffic class |
| `TCToQueue` | Traffic class | Queue index |
| `TCToPriorityGroup` | Traffic class `0..15` | PG `0..7`, also checked against the native port topology |

Each map has 1..256 entries with unique `from` values. Traffic class and queue values are uint32 in the API; agent preflight enforces the tighter native storage limits and the device's actual capabilities and queue maps. Passing schema validation does not mean the hardware supports a value.

### Schedulers

- `algorithm`: `STRICT`, `WRR` or `DWRR`. Weighted algorithms require `weight: 1..100`; `STRICT` forbids `weight`.
- `meterType`: `Bytes` (default) or `Packets`.
- Optional positive `committedRate`, `peakRate`, `committedBurst` and `peakBurst` are uint64 values capped by the API at `9223372036854775807` (signed int64 maximum). Omitted values stay absent.

Shaping rules:

- Rates are **bytes per second** or **packets per second**, not bits per second.
- Bursts are bytes or packets, matching `meterType`.
- `peakRate` requires `committedRate` and must be at least `committedRate`.
- `committedBurst` requires `committedRate`; `peakBurst` requires `peakRate`.
- If both bursts are set, `peakBurst` must be at least `committedBurst`.
- Native schemas and capabilities may impose tighter bounds, such as uint32 burst limits. Unsupported values are rejected before writing.

### Bindings

A QoS binding targets one physical `EthernetN` port. It must set at least one of `dscpToTC`, `dot1pToTC`, `tcToQueue`, `tcToPriorityGroup`, or a non-empty `queues` list. Queue indices are unique (up to 256 entries) and each queue references a named scheduler. Referenced maps and schedulers must already exist and be verified as applied.

```yaml
apiVersion: sonic.networking.metal.ironcore.dev/v1alpha1
kind: SwitchQoSMap
metadata:
  name: example-dscp
spec:
  switchRef:
    name: leaf
  managementPolicy: Observe
  name: ExampleDSCP
  type: DSCPToTC
  entries:
    - from: 0
      to: 0
    - from: 46
      to: 5
---
apiVersion: sonic.networking.metal.ironcore.dev/v1alpha1
kind: SwitchQoSMap
metadata:
  name: example-tc-queue
spec:
  switchRef:
    name: leaf
  managementPolicy: Observe
  name: ExampleTCQueue
  type: TCToQueue
  entries:
    - from: 0
      to: 0
    - from: 5
      to: 5
---
apiVersion: sonic.networking.metal.ironcore.dev/v1alpha1
kind: SwitchScheduler
metadata:
  name: example-scheduler
spec:
  switchRef:
    name: leaf
  managementPolicy: Observe
  name: ExampleWeighted
  algorithm: DWRR
  weight: 10
  meterType: Bytes
---
apiVersion: sonic.networking.metal.ironcore.dev/v1alpha1
kind: SwitchQoSBinding
metadata:
  name: example-qos-port
spec:
  switchRef:
    name: leaf
  managementPolicy: Observe
  interfaceName: Ethernet0
  dscpToTC: ExampleDSCP
  tcToQueue: ExampleTCQueue
  queues:
    - index: 5
      scheduler: ExampleWeighted
```

These samples assume the switch supports the listed traffic classes and queues; the agent verifies this. Bindings affect only the selected port and queues. PFC, WRED, buffer configuration and ACL policer actions are not exposed.

## Status and verification

- `ConfigurationReady`, `RuntimeReady` and `PersistenceReady` report independent agent evidence.
- `Synced` requires configuration and persistence. `Ready` also requires existence and runtime verification.
- CONFIG_DB alone is never treated as runtime proof. Applied evidence comes from supported STATE_DB, ASIC and SAI observations.
- If a probe is unsupported or unavailable, the result is an error or unverified runtime, never assumed readiness.
- None of this proves end-to-end packet forwarding.
