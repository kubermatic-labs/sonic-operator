# Layer-2 VLANs

Use `SwitchVLAN` to observe or manage a Layer-2 VLAN and its member ports on a
switch. By default, management is additive: the operator adds what you declare
and never removes anything else.

`SwitchVLAN` is a cluster-scoped resource describing one VLAN on one `Switch`.
It supports VLAN IDs 1-4094 and explicit canonical SONiC Ethernet members, such
as `Ethernet0` or `Ethernet129`. Aliases, abstract handles, `Ethernet00`, and
`PortChannel` interfaces are not accepted in the desired member list. Every
member requires `taggingMode: tagged` or `taggingMode: untagged`.

This feature manages Layer-2 configuration only. It does **not** configure VLAN
IP addresses, SVIs, DHCP relay, routing, or dataplane health checks.

`reconcilePolicy` defaults to `Additive`; the additive behavior below remains the
default. For automatic full membership pruning and tagging-mode replacement,
see [authoritative VLANs](vlan-authoritative.md). That policy requires separate
controller and agent opt-ins plus explicit adoption of existing VLANs.
`deletionPolicy` defaults to `Orphan`.

## Start with observation

Keep the controller's `--observe-only=true` and the agent's read-only mode
enabled during adoption. The sample does not authorize device changes:

```yaml
apiVersion: sonic.networking.metal.ironcore.dev/v1alpha1
kind: SwitchVLAN
metadata:
  name: switch-sample-vlan100
spec:
  switchRef:
    name: switch-sample
  vlanID: 100
  managementPolicy: Observe
  members:
    - interfaceName: Ethernet0
      taggingMode: untagged
    - interfaceName: Ethernet129
      taggingMode: untagged
```

Use the name of your existing `Switch` in `switchRef.name`. The controller uses
the existing Switch agent factory and its mTLS settings; no separate plaintext
VLAN connection is opened. An older agent/client without VLAN support produces
an error condition, not a false success.

`managementPolicy` defaults to `Observe`. Observe never calls `EnsureVLAN`, even
when the global write gate is disabled. The controller polls every 60 seconds
after successful observations and uses controller-runtime error backoff for
failures. It never rewrites the desired spec based on discovery.

## Read status

```sh
kubectl get switchvlans
kubectl get switchvlan switch-sample-vlan100 -o yaml
```

- `status.observedGeneration` identifies the spec generation last attempted.
- `status.exists: true` means the latest valid observation found the VLAN.
- `status.exists: false` means the agent explicitly reported the VLAN missing.
- An absent `status.exists` means existence is unknown for this attempt, such
  as after a failed read or an uncertain write. It is not proof of absence.
- `status.members` contains the latest successful observation, including
  members not requested in spec. It is cleared when there is no valid current
  observation or when a write's outcome is uncertain.
- `Ready=True` means the request was processed successfully and configuration
  was confirmed. A successful read of missing or mismatching configuration is
  **not** Ready. It does not imply link, forwarding, or end-to-end connectivity.
- `Synced=True` means the VLAN exists and every requested member has the desired
  mode under Additive policy. Extra unmanaged members do not prevent additive synchronization. Missing VLANs,
  missing members, mode conflicts, duplicate claims, and errors report
  `Synced=False`. Check condition reasons and messages for the cause.

Both conditions carry `observedGeneration`. Do not treat a condition from an
older generation as confirmation of the current spec. A Kubernetes status-write
failure can leave old status in place; the reconciler returns the failure.

## Guarded management

Device writes require **all three** opt-ins:

1. The individual resource has `managementPolicy: Manage`.
2. The controller is explicitly started with `--observe-only=false`.
3. The agent is explicitly configured with read-only mode disabled.

Disabling the controller's global `--observe-only` gate also affects other
controllers and provisioning behavior, so check the whole deployment before
enabling writes. Keep provisioning explicitly off with
`--disable-static-config=true`, even when disabling observe-only for a VLAN
rollout.

With the controller write gate disabled, Manage calls the additive `EnsureVLAN`
operation on every valid, conflict-free reconciliation, even when Redis already
matches. Matching configuration needs no VLAN/member mutation, but Ensure still
saves the configuration to confirm persistence. The controller does not call a
separate save operation. This retries a failed save after Redis was updated,
including after controller or agent restarts, without pruning or replacing
unrelated fields. Repeated save failures keep `Ready=False` and `Synced=False`;
only successful persistence and confirmation allow Manage to report success.
Observe (including Manage under the global observe-only guard) checks running
configuration only and never calls Ensure or confirms on-disk persistence.
Agent-side validation rejects unknown ports, LAG members, routed interfaces,
and conflicting untagged VLAN membership.

Existing tagging modes are never silently replaced. If `Ethernet0` is already
tagged and spec requests untagged, reconciliation fails without calling ensure.
Use the separately opted-in Authoritative policy for a planned migration
(consider its traffic impact), or migrate outside this additive API.

## Ownership and migration

Only one CR may claim a given `switchRef.name` and `vlanID`, including Observe
resources. A competing claim fails closed; neither policy grants precedence.
Remove the unwanted CR before proceeding. Terminating claims still block until
they disappear. The manager uses an uncached API read and repeats the claim and
spec/deletion checks immediately before a device write.

These checks are not an atomic reservation across Kubernetes and the device.
Avoid concurrent creation of competing claims during write-enabled rollout;
use leader election when running multiple manager replicas. A claim created
after the final check is detected on a subsequent reconcile, but cannot undo an
already in-flight additive operation.

`switchRef` and `vlanID` are immutable. To move to another switch or VLAN, create
a separate Observe resource for the new target and check its status. To
rename a resource for the same target, first delete the old CR to avoid competing
claims, then create the replacement in Observe mode. Check status before any
later switch to Manage.

Under Additive policy there is no pruning and no device cleanup on CR deletion. Removing a member from
spec stops requiring it; it does **not** remove that member from SONiC. Deleting
the CR leaves the VLAN and all memberships intact, without a finalizer. Any
destructive cleanup or tagging-mode migration requires the explicit Authoritative
workflow. An owned/finalized authoritative VLAN cannot downshift to Additive;
release it using Orphan deletion first. The agent's additive EnsureVLAN operation
enforces ownership and pending-operation guards itself; the controller does not
require the authority RPC or its full configuration snapshot for additive writes.
