# FRR migration (empty routing)

`SwitchFRRMigration` switches a SONiC 202511 device between the traditional `bgpcfgd` routing framework and the unified `frrcfgd` framework. Use it to prepare a switch with **no routing configuration** for [BGP management](./bgp-relay.md), which requires Unified mode, or to return it to Traditional mode.

## Overview

- Cluster-scoped, handled by the shared network reconciler and journal.
- `mode` is `Unified` or `Traditional` and is mutable. `switchRef` is immutable.
- `managementPolicy` defaults to `Observe`.
- Change direction by editing the **same** resource (same name and UID), keeping its target binding and owner. The device-wide identity `FRRMigration|unified` is the same in both directions, so a second resource conflicts even if it requests the other mode.

### Scope

- Only empty routing configuration is supported. Existing peers, routes, policies and advertisements are not translated.
- Split and split-unified custom modes, and foreign configurations that are already unified, are not adopted automatically.
- Preflight must recognize the CONFIG_DB and runtime baseline, find no routing configuration in CONFIG_DB or at runtime (including peers), and confirm that the generated target configuration is empty.
- Reverse migration validates the separated `bgpd`, `zebra` and `staticd` startup outputs instead of the unified `frr.conf`.

## Before you start

- Take off-switch backups of CONFIG_DB, the migration-related `DEVICE_METADATA|localhost` keys, and the FRR configuration files.
- Keep full command output and backups private. FRR configuration can contain passwords.
- Plan a maintenance window. The routing service restarts during each transition.

## Preview

Apply the Observe-only sample:

```sh
kubectl apply -f config/samples/frr-migration.yaml
kubectl get switchfrrmigration switch-a-unified -o yaml
```

```yaml
apiVersion: sonic.networking.metal.ironcore.dev/v1alpha1
kind: SwitchFRRMigration
metadata:
  name: switch-a-unified
spec:
  switchRef:
    name: switch-a
  managementPolicy: Observe
  mode: Unified
```

Omit `approvedDigest` entirely rather than setting it to an empty string. When present, it must be exactly 64 lowercase hexadecimal characters.

The agent publishes a sanitized preflight result in `status.observed`:

| Key | Meaning |
| --- | --- |
| `mode` | Requested target mode, `Unified` or `Traditional` |
| `preflightEligible` | Whether the observed baseline is eligible for migration |
| `adoptionDigest` | SHA256 approval fingerprint binding configuration, runtime baseline and target |
| `classification` | Fixed classification of the observed migration state |

Notes:

- Observe never runs Ensure. The initial preview works without a configured journal and does not create journal files.
- A preview does not prove that the target is running or saved.
- `ConfigurationReady`, `RuntimeReady` and `PersistenceReady` report independent evidence. `Ready` requires all three plus existence.

## Approve and migrate to Unified

All write gates must be enabled:

| Component | Required setting |
| --- | --- |
| Controller | `--observe-only=false --allow-network-config=true --allow-frr-migration=true` |
| Agent | `--read-only=false --allow-network-config=true --allow-frr-migration=true`, plus a writable, durable network journal directory |
| Resource | `managementPolicy: Manage` and `approvedDigest` set to `status.observed.adoptionDigest` |

Both `--allow-frr-migration` flags default to `false`.

After checking that the preview is eligible, edit the resource and set the policy and digest together:

```sh
kubectl edit switchfrrmigration switch-a-unified
```

Approval checks:

- Before a new Ensure, the controller requests a fresh agent observation and requires `preflightEligible: true`, the target mode, and an exact digest match. Previously published status cannot authorize a write.
- If the snapshot changed, you must review and approve the new digest.
- The agent enforces the approval independently before changing configuration.

The forward migration sets:

```text
DEVICE_METADATA|localhost.frr_mgmt_framework_config = true
DEVICE_METADATA|localhost.docker_routing_config_mode = unified
```

Activation restarts only `bgp.service`. It does not reboot the switch or reload configuration, but routing is unavailable during the restart. No `BGP_GLOBALS`, peers or advertisements are created. Runtime verification checks the target framework, the restart identity and the empty routing state. Persistence is confirmed by a checked D-Bus save after runtime verification.

## Return to Traditional

Reverse migration has the same empty-routing restriction, approval requirement, write gates and routing-service outage as forward migration. It returns the switch to a supported, empty traditional framework. It is not general configuration translation and does not restore an earlier backup byte for byte.

1. Make sure any pending forward operation can finish, with all write gates enabled.
2. Edit the **existing** resource. Keep its name, UID, `switchRef`, annotations and finalizer. Do not create a separate `switch-a-traditional` resource, and do not delete and recreate the resource.

   ```sh
   kubectl edit switchfrrmigration switch-a-unified
   ```

3. Set `mode: Traditional` and remove the old `approvedDigest`. Keep `managementPolicy: Manage`: the recovery finalizer requires Manage to finish the previous journal entry before a new preview is published. Without approval, no new Ensure runs, but recovery can still finish already approved work.

   [`config/samples/frr-reverse-migration.yaml`](https://github.com/ironcore-dev/sonic-operator/blob/main/config/samples/frr-reverse-migration.yaml) shows the target fields for this edit:

   ```yaml
   apiVersion: sonic.networking.metal.ironcore.dev/v1alpha1
   kind: SwitchFRRMigration
   metadata:
     name: switch-a-unified
   spec:
     switchRef:
       name: switch-a
     managementPolicy: Manage
     mode: Traditional
   ```

4. Read the new preview:

   ```sh
   kubectl get switchfrrmigration switch-a-unified -o yaml
   ```

   Wait for `status.observed.mode: Traditional` and `preflightEligible: true`. An `ApprovalRequired` condition is expected while the digest is absent.

5. Edit the same resource again and set `approvedDigest` to the new `adoptionDigest`. Never reuse the forward digest. The controller checks a fresh, mode-matching preview before Ensure; any drift requires a new approval.

The Traditional target explicitly writes:

```text
DEVICE_METADATA|localhost.frr_mgmt_framework_config = false
DEVICE_METADATA|localhost.docker_routing_config_mode = separated
```

Both fields stay present even if they were absent before the original forward migration; reverse migration does not restore their absence. Activation runs exactly `systemctl restart bgp.service`, verifies the traditional daemons, the separated startup files and the empty runtime, and then performs the checked save.

To migrate forward again, edit the same resource to `mode: Unified`, remove the reverse approval, review a fresh Unified preview, and approve its digest. Repeated cycles keep the owner and binding. A target that is already verified does not need another restart.

## Pending operations and recovery

- Before Ensure, the controller persists the target binding, the original request and the network recovery finalizer.
- An interrupted operation is recovered through `RecoverNetworkResource`, using the original request and the device journal, before any new intent is evaluated or a deleting resource is released.
- If `mode` changed while a restart or save was pending, recovery uses the recorded **old** mode and approval. Successful recovery of the old mode does not prove or authorize the new target; the new transition waits for its own fresh approval.
- After metadata has changed, the original preflight digest may no longer match current state. Recovery of the original journal entry does not need fresh approval and does not replace the recorded digest with a newly edited one.
- Recovery still requires all write gates, including `--allow-frr-migration`, and `managementPolicy: Manage`. Disabling a gate blocks recovery and keeps the finalizer.

### Deletion

Deleting the resource orphans the device configuration after any pending recovery completes. It does not revert the framework. Do not remove the finalizer to bypass an uncertain restart or save.

If recovery reports an unresolved post-stage failure, inspect the journal and your private backups. Restarting the service blindly is not a general recovery procedure. Transition-scoped immutable receipts preserve evidence from earlier transitions across later cycles.

### Restoring a backup manually

Restoring arbitrary backed-up configuration is an operator-managed procedure:

1. Stop new desired changes.
2. Verify fingerprints and confirm no unrelated configuration has changed. If it has, reconcile the backup with those changes first.
3. Restore the backed-up framework metadata and FRR files using your maintenance procedure for the switch.
4. Restart the affected routing service and verify the original empty runtime.
5. Save the configuration only after validation.

## Tested hardware and known limitations

| Item | Value |
| --- | --- |
| Platform | Dell Z9100 |
| SONiC | `202511.1217682-4784cca11` |
| FRR | 10.4.1 |
| Sequence | `Unified -> Traditional -> Unified` on a single resource and owner UID |

Results:

- Each transition required a fresh eligible preview and its exact approved digest.
- Both directions verified the expected configuration daemon, empty all-VRF BGP summaries and neighbors, saved mode fields, and a completed journal.
- After the full cycle, CONFIG_DB exactly matched the original unified snapshot.
- Only `bgp.service` was restarted; `swss` and `syncd` kept running. Neighboring devices and active links were not affected.

Not covered by this test: migration of a populated router, forwarding under traffic, and full-switch power loss. Interruption and save/restart failure recovery are covered by race-enabled integration tests with simulated failures.
