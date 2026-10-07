# Management and system settings

`SwitchManagement` and `SwitchSystem` let you manage host-level settings of a SONiC
switch from Kubernetes:

- `SwitchManagement` owns the eth0 management addresses and gateways and, when you
  specify it, a management-only MAC override.
- `SwitchSystem` owns configured NTP inputs and the SNMP location, contact and
  read-only community settings.

Use them when you want management networking, time and SNMP settings declared and
verified alongside the rest of your switch configuration.

## Overview

| Property | Behavior |
| --- | --- |
| Default policy | `Observe` for both kinds. `Observe` never reports managed Ready. |
| Resources per switch | One `SwitchManagement` and one `SwitchSystem` may claim a Switch. |
| Claim binding | Bound to the Kubernetes object UID and the Switch UID. The controller also verifies the switch's base MAC through the authenticated device-information RPC. |
| Deletion | Orphan. Native configuration is left in place. |
| Not provided | Command execution, raw database replacement, ownership transfer, delete RPC. |

## Prerequisites

To use `managementPolicy: Manage`, enable host writes on both components:

| Component | Required flags |
| --- | --- |
| Manager | `--observe-only=false --allow-host-config` |
| Agent | `--read-only=false --allow-host-config` |

You also need:

- A qualified host profile installed on the switch (see
  [Qualified native inputs](#qualified-native-inputs)).
- The switch-local recovery service installed (see
  [Switch-local management recovery](#switch-local-management-recovery)).

## Status

Status reports configuration, native runtime, persistence and recovery separately.

**Management runtime** checks:

- kernel addresses
- source policy rules
- connected and default routes in SONiC's `default` policy table
- the active MAC, when managed
- gateway reachability

Saved CONFIG_DB and the generated `/etc/network/interfaces` are checked
independently.

## NTP

NTP supports the chrony and NTPsec image families.

The operator reconciles these NTP global inputs and the configured server set:
`admin_state`, `authentication`, `dhcp`, `server_role`, `src_intf`, `vrf`.

Native readiness requires all of:

- the qualified generated config
- an active service
- the daemon's actual configured sources
- proof that the running daemon consumes the declared generated file

An NTPsec DHCP-file override or a chrony alternate-config argument cannot satisfy
this proof.

**Qualified configuration.** The current image profiles qualify:

- NTP enabled
- DHCP enabled
- server role disabled
- authentication disabled
- eth0/default source routing

Other global transitions, authenticated NTP, pools and per-server options fail
closed.

**Server names.** NTPsec source readback requires numeric server addresses. NTPsec
hostnames are rejected in image-specific preflight, before any CAS, generated-file
write or activation. chrony supports the original server names.

Configured-source convergence is separate from synchronization with a peer, so an
empty server set is valid.

## SNMP

- Communities come from namespaced Kubernetes Secret key references. Omitting the
  reference declares an empty community set.
- An empty contact leaves the native contact input unowned.
- SNMPv3 or read-write community coexistence is rejected by this profile.
- Secret values never appear in status, events, logs, annotations or recovery
  journals. Native command stderr is discarded, and RPC/controller errors use fixed
  messages.

**Runtime proof** compares the generated config, checks a durable causal activation
receipt and, when a community exists, performs an authenticated SNMP GET for the
configured location and contact.

### `/etc/sonic/snmp.yml`

The SNMP startup chain imports `/etc/sonic/snmp.yml` before rendering CONFIG_DB.
`SwitchSystem` therefore also owns this file: it verifies existing YAML semantically
and atomically writes its typed, JSON-compatible YAML with mode 0600 before
activation. This prevents a removed community from being reimported on restart. No
other tool may own the content of this file.

### Daemon identity checks

Both qualified SNMP images use the compiled default config path rather than `-c`.
Read-only host-root probes verify the exact native argv, executable identity, mapped
Net-SNMP library bytes and the absence of configuration overrides. These probes need
permission to read the target's `/proc` environment and `map_files`; if proof is
missing, the check fails closed. Comparing mapped bytes handles the overlayfs
device-ID difference on the older image without accepting a replaced or deleted
loaded library.

### Activation receipts

Daemon load proof does not compare file times against a reconstructed process start
time. Instead, private activation records under `native-runtime/` in the host
journal directory bind the owner, target, revision and profile identity to the boot
ID, PID, boot-relative start ticks and opaque file identity.

- File timestamps are compared only for equality, so clock steps in either
  direction cannot certify an unrestarted rewrite or invalidate an unchanged receipt.
- Credentials and credential-derived config digests are never stored in receipts.
- A daemon that is already running without a receipt reports
  `RuntimeVerified=false`. `Manage` performs a qualified activation to establish
  proof. A reboot, a different process or a modified config requires a fresh
  activation. `Observe` cannot create this proof from matching files or Redis.

### Stopped SNMP container

A stopped SNMP container is inspected, and its fixed consumer files are hash-checked
using bounded `docker cp` archive reads. Its candidate template is validated with
host `cfggen` from a private temporary file.

- Only that qualified existing container ID may be started. No image is pulled and
  no container is created.
- A failed start is retried in the next Get/Ensure cycle.
- Unknown entrypoints, unqualified consumer bytes and malformed archives stay blocked.

## Switch-local management recovery

Management changes can cut off connectivity, so rollback runs on the switch itself,
independently of the agent and Kubernetes.

### Installation

1. Build and install `sonic-operator-host-recovery` separately from the agent.
2. Install and enable the service and timer from `config/agent/`.
3. Do not include it in agent self-updates. It must keep running while the agent is
   down.
4. Create its configuration at `/etc/sonic/sonic-operator-host-recovery.json`,
   owned by root with mode 0600:

```json
{
  "journalDir": "/host/sonic-operator-host-journal",
  "redisAddress": "127.0.0.1:6379",
  "vlanJournalDir": "/host/sonic-operator-vlan-journal",
  "breakoutJournalDir": "/host/sonic-operator-breakout-journal",
  "networkJournalDir": "/host/sonic-operator-network-journal"
}
```

Requirements for this configuration:

- These paths (the FleetHostV1 layout) must match every reader and writer. Keep all
  cooperating journals.
- The host journal directory must already exist as a private, root-owned directory.
- The agent requires exactly the same configuration before it enables host writes.
- Keep `--host-journal-dir` configured on every cooperating agent after first use.
- Overlapping journal locations are rejected.
- Existing data in `/var/lib/sonic-operator/host` needs a deliberate migration. It is
  never adopted, copied or removed automatically.

The standalone command uses `NewRecoveryEngine(RecoveryConfig, backend)` to bind the
host journal and every configured dependency journal before creating the native
backend and engine, so dependency recovery uses the same host path even when the
agent is absent.

### Writer exclusion

Host mutation acquires locks in this order, and holds them through snapshot,
publication and dispatch:

1. config mutex
2. VLAN journal
3. breakout journal
4. network journal
5. host journal

While management has a pending transaction, other network, VLAN, breakout and
interface writers are blocked. Your deployment tooling must keep these shared guards
in place. A writer that is already pending prevents host intent publication.

For legacy state where two transactions are pending, the local watchdog may finish
one already-recorded dependency under all locks and the host baseline/candidate
scope, using its existing fingerprint and activation checks. It never substitutes a
new desired operation. Multiple conflicting dependencies, or a native breakout that
is already ambiguous, stay `RecoveryBlocked` instead of being replayed.

`CheckPending(dir)` does not acquire a reverse host lock. It syncs the directory,
reads an authenticated record while keeping its open-file identity, syncs again, and
then confirms the directory entry still has that identity before accepting
completion or absence. A changed entry or a failed post-read sync keeps the fence in
place. A configured directory that is missing or inaccessible is an error, not
evidence that nothing is pending.

### Rollback

Before activation, the host engine fsyncs a typed rollback record with the previous
working management configuration, active MAC, owner, target, transaction ID and
deadline.

- On Linux, deadlines use boot ID and uptime, so NTP clock corrections cannot
  postpone recovery.
- A reboot invalidates the old deadline, and the previous state is restored at the
  next watchdog run. Process restarts keep the transaction.
- The timer checks every five seconds. Recovery is bounded by the service timeout,
  and candidate activation is bounded inside the rollback window.

### Confirmation

A change is confirmed only with:

- a new authenticated TCP connection
- fresh native readback
- gateway reachability
- a one-use challenge bound to the transaction and that connection

An old connection, stale challenge or expired transaction cannot confirm. After
confirmation, the controller CAS-updates the Switch agent endpoint if the old IP was
removed. Existing network-resource endpoint bindings may then need to be rebound by
your deployment tooling.

### Behavior on lost connectivity

- The switch rolls back locally, without Kubernetes.
- A rolled-back generation is latched so the link does not flap through repeated
  retries. Fix the cause and change the declaration generation before trying again.
- Recovery can resume after partial native dispatch. Both the before and candidate
  states remain durable removal authority until restoration is verified, even if
  Redis has already reverted.
- Recovery restores only typed management fields, regenerates native interfaces,
  restores the MAC and policy routes, and verifies the save.
- For active-MAC drift repair, `ObservedActiveMAC` records the actual pre-dispatch
  MAC, while the before state's active MAC records the intended restoration target.
  Only these recorded values and the candidate are allowed intermediate states; any
  other active MAC stays blocked.
- Immediate recovery detaches RPC cancellation but keeps the held writer-exclusion
  context, so it never waits on its own non-reentrant config mutex.

## Qualified native inputs

### Host profile

Install the image and template qualification as
`/etc/sonic/sonic-operator-host-profile.json` using your artifact tooling. Without a
matching qualification, the corresponding native ownership claim is refused.

| Field | Content |
| --- | --- |
| `imageSHA256` | Exact bytes of `sonic_version.yml` |
| `interfacesSHA256` | Interfaces template |
| `ntpBackend` | `chrony` or `ntpsec` |
| `chronySHA256` / `ntpsecSHA256` | NTP template for the selected backend |
| `snmpSHA256` | The SNMP container's `/usr/share/sonic/templates/snmpd.conf.j2` |
| `consumerSHA256` | Map of fixed consumer names to hashes (below) |

`consumerSHA256` keys identify the installed generators, startup programs and native
consumers. Their paths are fixed in code.

| Area | Keys |
| --- | --- |
| Interfaces | `interfaces-generator` |
| NTP | `ntp-generator`, `ntp-startup`, `ntp-daemon` |
| SNMP | `snmp-init`, `snmp-startup`, `snmp-importer`, `snmp-supervisor-template`, `snmp-daemon`, `snmp-library` |

The two profiles in `config/agent/profiles/` contain hashes measured read-only on the
supported image families:

| SONiC image | NTP backend | Template |
| --- | --- | --- |
| `202411.1216684-48c2d4c3e` | NTPsec | `ntp.conf.j2` |
| `202511.1217682-4784cca11` | chrony | `chrony.conf.j2` |

Rules for profiles:

- If a switch still has a legacy MAC activation, generate a new immutable profile
  that adds its `legacyMACHooks` entry from measured import metadata. Never patch the
  live profile or the measured base profile.
- The [release and source workflow](../site-artifacts.md#building-a-release-and-sources)
  binds builds and published source UIDs. Offline output is not installation or boot
  qualification.
- Every recovery reader must understand `macOwned`, `observedActiveMAC`, causal
  receipts and artifact reservations before publication.
- Ordinary agent/TLS recovery does not replace the independent host recovery service.

### Artifact updates

Artifact activation that can change these native consumers or the profile must
respect `host.CheckPending(hostJournalDir)` and your per-switch exclusion. Durability
failures remain fenced. `DeferForRecordedRecovery` is only for completing a validated
existing journal under the complete lock set; it is not an artifact bypass. Artifact
sync must not overwrite the native-runtime receipt directory.

### Legacy MAC hooks

If a switch already has a management MAC helper, your artifact tooling must first
import it unchanged. A `legacyMACHooks` entry then allows adoption of the equal
state while the old boot hook stays in place.

| Field | Description |
| --- | --- |
| `kind` | `management-mac-python` or `management-mac-shell` (deprecated legacy names: `dc-management-only`, `set-management`) |
| `hookSHA256` | Exact hook hash |
| `helperSHA256` | Exact helper hash |
| `baseMAC` | Switch base MAC |
| `mac` | Management MAC set by the hook |
| `addresses` | Original typed address list |
| `hostname` | Required for `management-mac-python`, optional for the legacy `dc-management-only`; must not be set for the shell helper |

- `management-mac-python` requires `hostname` because that helper selects its MAC by
  hostname. Qualification fails unless the switch reports that hostname.
- All executable paths are fixed by the kind. The profile cannot supply a command or
  path.
- Address and MAC changes stay blocked while a conflicting legacy activation exists.
- Equal-state adoption writes the equivalent typed boot input and the new fixed
  drop-in without changing the active MAC or cycling eth0. Only after that should the
  old hook be removed.

### Managed boot files

| File | Purpose |
| --- | --- |
| `/etc/sonic/sonic-operator-management.json` | Typed management boot input |
| `interfaces-config.service.d/90-sonic-operator-management.conf` | Fixed systemd drop-in that activates it |

Both are generated from the resource. If you omit the MAC, that field is not owned.
The local boot helper restores management policy-table routes after an actual MAC
link cycle. Device, base and front-panel MAC values are never changed.

## Testing

Unit tests cover closed validation, credential redaction, no-op adoption, native
drift, partial-dispatch recovery, wall-clock changes and reboots, fresh-connection
confirmation and blocked retry. Native fixture tests distinguish Redis, generated
files, addresses, routes and MAC. Controller tests cover Secret resolution and
new-connection endpoint confirmation; the envtest suite validates installed CRD
schemas.

Local integration tests use a disposable Redis fixture with per-child ACL identity,
independent kernel and saved-file state, and real worker termination at 13 rollback
boundaries. They cover field-delta CAS, gateway-less NULL rows, legacy dependency
recovery and publication interleavings.

### Read-only qualification against real switches

`TestNativeReadOnlyQualification` is opt-in and skipped by default. It runs the real
native backend through a command-allowlisted SSH adapter, verifies the current
management runtime and system configuration/persistence, and rejects an unapplied
synthetic declaration. The profile is supplied in memory. The test never installs a
profile or calls mutation, save, restart or CAS methods. System runtime adoption
stays unproven without a causal activation receipt.

It reads its targets from these environment variables (see the test for details):

| Variable | Purpose |
| --- | --- |
| `SONIC_HOST_READONLY_QUALIFY` | Set to `1` to enable the test |
| `SONIC_HOST_READONLY_TARGETS` | Switches to inspect |
| `SONIC_HOST_SSH_ROOT` | Workspace root; the SSH configuration references its identity key relative to it |
| `SONIC_HOST_SSH_CONFIG` | SSH configuration to use |
| `SONIC_HOST_READONLY_MAC_HOOKS` | Legacy MAC hook declarations for the targets |

```sh
SONIC_HOST_READONLY_QUALIFY=1 \
SONIC_HOST_SSH_ROOT=/path/to/sonic \
GOMAXPROCS=3 go test -p 2 ./internal/agent/host \
  -run '^TestNativeReadOnlyQualification$' -v -count=1
```
