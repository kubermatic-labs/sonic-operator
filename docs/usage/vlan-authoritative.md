# Authoritative VLANs

Use the Authoritative policy when the operator should own the complete
membership of a VLAN, including removing members and changing tagging modes.
It requires explicit opt-ins on the controller, the agent and each resource.

`SwitchVLAN.spec.reconcilePolicy: Authoritative` declares the **entire VLAN
membership**, not a subset. After explicit takeover, removing a member from spec
removes it from SONiC; changing its mode replaces that mode. `members: []` prunes
every member but retains the VLAN. Ordinary spec edits reconcile automatically;
there is no separate change CR or per-edit confirmation step.

Defaults remain `managementPolicy: Observe`, `reconcilePolicy: Additive`, and
`deletionPolicy: Orphan`. Nothing in this workflow enables a live controller,
agent, provisioning server, or device setting automatically.

## Preview and adoption

1. Start from `config/samples/networking_v1alpha1_switchvlan_authoritative.yaml`,
   keeping `managementPolicy: Observe` and all live write guards enabled.
2. Reference an existing Switch with a stable UID and explicit management host
   and port. Implicit localhost endpoints are rejected for authority operations.
3. Compare `status.members`, existence, and `status.adoptionDigest` against the
   complete desired member set and the expected traffic impact.
4. For an existing unowned VLAN, explicitly set `spec.adoptionDigest` to that
   exact lowercase SHA256 digest. A changed snapshot invalidates adoption. A new,
   absent VLAN needs no digest. Status is only a preview; it does not adopt anything.
5. When you are ready to roll out, set `managementPolicy: Manage` and
   enable all required process gates. Later edits need no fresh adoption digest
   while ownership remains bound to the same CR UID.

Read-only inspection:

```sh
kubectl get switchvlan switch-sample-vlan200 -o yaml
```

Writes require all of the following:

- The CR has `managementPolicy: Manage` and `reconcilePolicy: Authoritative`.
- The controller has `--observe-only=false` and `--allow-authoritative-vlans=true`.
- The agent has `--read-only=false` and `--allow-authoritative-vlans=true`.
- The agent has an explicit private persistent `--vlan-authority-journal-dir`.
- Provisioning remains explicitly disabled using `--disable-static-config=true`.

Both authority flags default to false. Agent guards apply to ownership release
as well as reconcile. A snapshot read never creates a journal or mutates VLAN
configuration. Do not enable a production rollout just to clear a finalizer.

Without a configured, validated persistent authority journal, the agent may
return configuration and a digest for preview but reports `OwnershipKnown=false`.
The controller retains that preview, reports `Ready=False` and `Synced=False`
with an ownership error, and blocks adoption, writes, release and finalizer
removal. An empty owner ID is not evidence of no owner when ownership is unknown.
This also protects deletion after an agent restart with the journal option
omitted. Restore the original journal; do not replace it with an empty directory
to force cleanup. A validated configured journal can positively confirm no owner,
including when the VLAN itself is absent.

## Ownership and status

Before the first device write, the controller persists the `vlan-authority`
finalizer and a target-binding annotation, then requeues. The binding includes
the CR UID, VLAN ID, Switch UID, endpoint and identity fields. `status.targetIdentity`
exposes its digest. A changed/recreated Switch or changed endpoint fails closed,
including during deletion. Restore the original target and investigate rather
than removing the binding. Hostname/DNS reuse and endpoint reassignment must be
controlled operationally; Kubernetes endpoint metadata alone is not hardware
attestation. Maintain mTLS trust and stable Switch identity.

`status.ownerID` records the last confirmed agent owner UID. Every reconcile
reads agent ownership again; status alone never permits pruning or deletion.
Ownership cannot transfer silently between CRs, including a recreated CR with
the same name. Duplicate switch/VLAN claims fail closed, including terminating
claims and Switch objects referencing the same literal endpoint.

`Ready` and `Synced` require exact membership, not additive subset matching. For
write-enabled reconciliation, both runtime and persistence verification are
required. `status.runtimeVerified` requires CONFIG_DB and APPL_DB VLAN/member
convergence, not ASIC forwarding, bridge PVID verification or atomic traffic
migration. `status.persistenceVerified` reports the agent's
durable-save proof. A write error clears configuration confirmation and leaves
conditions false. A concurrent API/status conflict returns an error; existing
status can remain stale until the next successful reconcile.

The agent rejects unsafe dependencies and concurrent CONFIG_DB changes. It uses
a durable pending-operation journal to recover interrupted apply/save operations;
matching Redis state alone cannot skip a pending save. No blind rollback is
performed. Unknown fields, routed/LAG ports, second untagged VLAN membership and
ambiguous dependency state block destructive operations.

Membership mode changes use a durable pre/intermediate/post journal. The agent
removes mode-changing and pruned members, waits for APPL_DB to observe removal,
then adds the recorded desired membership with a full-CONFIG_DB snapshot CAS.
Each convergence wait is capped at 10 seconds or the request deadline, whichever
is earlier. Timeouts keep the journal pending and do not save an intermediate
configuration. Restarts resume only an exact recorded snapshot; conflicting
changes require deliberate recovery. All authoritative writes, including deletes,
wait for APPL_DB convergence before saving and again before journal completion.

A confirmed CONFIG_DB no-op still checks APPL_DB. Stale runtime membership is
reported as unverified, not repaired by silently replaying the change. Do not erase the
ownership journal to force recovery.

## Deletion and recovery

- `Orphan` (default): release this UID's ownership only. No VLAN/member mutation
  and no configuration save. Pending persistence must be recovered first.
- `Delete`: require the same agent owner UID and all write gates, remove the VLAN
  and its members through the authoritative operation, confirm persistence, then
  release ownership and remove the finalizer. An already absent VLAN with a
  pending save still requires recovery and confirmation.
- Confirmed unowned VLAN: no device deletion or release, even with `Delete`.
  Remove the controller finalizer only after a successful authority read proves
  `OwnershipKnown=true` and no owner, and live API/target checks pass.
- Unknown/foreign owner, disabled guards, changed target, dependency conflict,
  failed save or failed release: retain the finalizer with an actionable error.

Never manually remove the finalizer merely because deletion is blocked. Restore
the original target and gates only as part of a deliberate recovery procedure, resolve
pending persistence, then retry. Authoritative-to-Additive downshift is blocked
while owned/finalized. Restore Authoritative, choose Orphan, delete the old CR,
and create a new Observe CR after confirmed release if additive management is
desired. Preserve the journal across agent restarts and never erase it to force
adoption; a lost or mismatched ownership record requires deliberate recovery.
