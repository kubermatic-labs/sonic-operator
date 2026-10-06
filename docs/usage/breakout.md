# Port breakout

Use `SwitchPortBreakout` to split a parent port into child ports, or merge
them back, by setting a platform-supported breakout mode.

`SwitchPortBreakout` is a cluster-scoped claim for one canonical SONiC parent
port, such as `Ethernet0`. `switchRef.name` and `port` are immutable. `mode` is
an exact platform capability string, not a speed inferred from port numbering.
Read `status.supportedModes` before enabling management.

## Observe first

The API defaults `managementPolicy` to `Observe` and `childAdminState` to `Down`.
The manager defaults to `--observe-only=true --allow-breakout=false`.
Observation performs no device mutations and never prunes inventory.

```yaml
apiVersion: sonic.networking.metal.ironcore.dev/v1alpha1
kind: SwitchPortBreakout
metadata:
  name: leaf-01-ethernet0
spec:
  switchRef:
    name: leaf-01
  port: Ethernet0
  mode: 4x25G
  managementPolicy: Observe
```

The referenced Switch must have a live UID and explicit management host/port.
The controller uses the existing mTLS client factory and its
`SONIC_AGENT_TLS_CERT_FILE`, `SONIC_AGENT_TLS_KEY_FILE`,
`SONIC_AGENT_TLS_CA_FILE`, and optional `SONIC_AGENT_TLS_SERVER_NAME` settings.
It does not provide an insecure fallback.

## Enable management

All gates must permit writes:

- CR: `spec.managementPolicy: Manage`.
- Manager: `--observe-only=false --allow-breakout=true`.
- Agent: read-only disabled, `--allow-breakout=true`, and a private, persistent,
  absolute `--breakout-journal-dir` configured.

`childAdminState: Up` or `Down` (uppercase in the API, lowercase on the wire)
applies only to newly created device children. It is not a continuous admin-state
policy. Existing `SwitchInterface.spec` values are never overwritten, including
desired `Up` on `Ethernet0` when that native interface survives split/merge.

Before the first operation, the controller persists a metadata target binding
covering the claim UID, Switch UID, endpoint and identity. It also records prior
children in status before a mutation. A changed/recreated Switch, changed endpoint,
missing binding, stale spec or deletion during reconciliation blocks further writes.
Do not remove the `sonic.networking.metal.ironcore.dev/breakout-target` annotation
to bypass a target mismatch; investigate and restore the original target.

## Safety checks

The controller uses uncached API reads to reject competing claims on the same
endpoint/parent or overlapping observed lanes, VLAN specs referencing affected
interfaces, admin-management annotations, foreign/user-owned interface resources,
and owned interface references. References to nonexistent interfaces fail closed:
they might name future children whose lane scope cannot yet be established.
An interface's desired admin state alone is not a conflict.

The agent remains responsible for complete live device preflight, including routed
interfaces, LAGs, VLAN membership, ACLs and unknown dependencies. Kubernetes has no
routed-interface spec in the current API. Neither controller nor agent removes
these dependencies automatically. There is no force mode or reload/reboot fallback.

After an agent-confirmed operation, new children are discovered from the live
interface inventory. Existing native-interface CRs are left untouched even if
the observed abstract handle differs. Cleanup can remove only previously seen
children absent from both the confirmed result and successful live inventory.
Their CRs must have the exact Switch controller owner UID/name/kind/API version,
generated name/handle identity, no additional owners, and **no** manage-admin-state
annotation (even `false`). Deletes use UID and resourceVersion preconditions.
An empty/partial discovery or failed operation never authorizes broad pruning.

## Status and recovery

- `observedGeneration`: the spec generation evaluated in this attempt.
- `mode`, `supportedModes`, `children`: latest valid observation, with child lanes,
  speed, admin state and MTU represented by Kubernetes API types.
- `configurationVerified` / `ConfigurationReady`: backend verification confirms
  the child layout, lanes and speeds, and the observed mode matches the requested
  mode. A matching mode string alone is not proof; layout diagnostics remain in
  status and condition messages.
- `runtimeVerified` / `RuntimeReady`: agent proof of CONFIG_DB/APPL_DB and kernel
  layout. This does not require carrier on an unconnected port.
- `persistenceVerified` / `PersistenceReady`: agent proof of a durable save.
- `pending` / `Progressing`: unresolved or uncertain operation outcome.
- `Ready`: desired configuration, runtime and persistence confirmed without a
  pending operation or reconciliation error. This is not forwarding/link health.
- `previousChildren`: persisted pre-operation cleanup scope retained across
  failures/restarts until successful confirmation and inventory reconciliation.

The write RPC is bounded to 180 seconds. A timeout can mean the operation happened
but the response was lost. The agent journal, not controller retries, determines
whether a subsequent reconcile can finish saving or requires manual inspection.
No-op requests still ask the agent to confirm persistence. A pending/partial or
foreign layout must not trigger a blind second native CLI invocation or rollback.
Check `status.message` and agent logs; preserve journals while investigating.

Deleting a `SwitchPortBreakout` does **not** restore the original layout, delete
device children, or prune interface CRs. There is no breakout finalizer. To merge
back, explicitly change `spec.mode` to the supported original mode with write
gates still enabled, confirm runtime/save status, then remove the claim if desired.

## Development verification

Controller tests use fake clients and no hardware:

```sh
go test ./internal/controller -run '^TestSwitchPortBreakout' -count=1
go test -race ./internal/controller -run '^TestSwitchPortBreakout' -count=1
```

Run the deepcopy/CRD/RBAC code generation (`make generate manifests`) before
compiling after API changes. The schema integration test additionally requires generated CRDs and
envtest binaries; fake clients do not enforce defaults or CEL immutability.
These tests do not exercise real hardware.
