# MLAG

The MLAG backend configures and verifies a SONiC MCLAG domain between two peer
switches using the native `iccpd` consumer. Use it when you want a downstream device
to dual-home a PortChannel across two switches.

## Support status

- **Native configuration and runtime verification** are available only for an
  `iccpd` build that you explicitly trust through a build manifest (see
  [Trusted build manifest](#trusted-build-manifest)).
- No build fingerprints ship with the project. Preflight fails until you provide a
  manifest.
- Hardware testing found that a peer-link failure did not keep all SVIs reachable.
  See [Tested hardware and known limitations](#tested-hardware-and-known-limitations).

## How it works

The planner `planNetworkMLAG(db, request)` produces a read-only plan for kind `MLAG`
with identity `MLAG|<domainID>`. The shared network engine applies it using its
field-ownership journal, full-snapshot CAS, save and recovery protocol. The planner
does not install or restart services; only the existing native CONFIG consumer
applies changes.

## Prerequisites

- An `iccpd` container running `iccpd` and `mclagsyncd`, whose files match a trusted
  build manifest.
- On each peer: the peer-link and member PortChannels already exist with Ethernet
  members, and the local address is configured and reachable to the peer.
- Two reciprocal MLAG resources, one per peer, both with `managementPolicy: Manage`.
- The manager and agent redundancy write gates enabled.

## Configuration

```json
{
  "kind": "MLAG",
  "ownerID": "resource-uid",
  "spec": {
    "switchRef": {"name": "switch-a"},
    "managementPolicy": "Observe",
    "domainID": 1,
    "peerSwitchRef": {"name": "switch-b"},
    "localAddress": "192.0.2.1",
    "peerAddress": "192.0.2.2",
    "peerLink": "PortChannel100",
    "members": ["PortChannel10"],
    "keepaliveInterval": 1,
    "sessionTimeout": 30
  }
}
```

| Field | Rules |
| --- | --- |
| `domainID` | Integer 1–4095. Immutable identity. |
| `localAddress`, `peerAddress` | Distinct unicast IPv4 addresses. The local address must exist on exactly one default-VRF data L3 interface or loopback and be assigned in the kernel. A peer address configured locally is rejected. |
| `peerLink`, `members` | Canonical existing `PortChannelN` names (0–9999) supported by the LAG planner, each with existing Ethernet physical members. Management interfaces, duplicate LAGs, the peer link as a member, and shared physical members are rejected. |
| `members` | Use `[]` for a domain-only stage; add members in a later request. |
| `keepaliveInterval` | 1–60 seconds, default 1. |
| `sessionTimeout` | 1–3600 seconds, default 30, at least three times the keepalive interval. |

Explicit zero or null timer values are invalid. Unknown fields, case aliases,
duplicate fields at any depth, null values, non-object specs, trailing JSON and wrong
JSON types are rejected.

### Validation and ownership

- `Observe` can report absent local dependencies.
- Dependency checks run in preflight against a fresh CONFIG snapshot, before every
  CAS attempt, including pre-state recovery.
- Only one domain per switch is supported.
- Existing native member rows that you did not request are a conflict and need
  manual inspection.
- All fields use additive ownership. Conflicting existing values, timer or address
  replacement and member removal are rejected. There is no automatic cleanup or
  destructive replacement.

### Controller requirements

The controller requires reciprocal peer resources, distinct switch UIDs and
endpoints, symmetric domain, addresses and timers, both policies set to `Manage`, and
the manager and agent redundancy write gates. Each agent validates only its own
switch; there is no cross-switch atomic transaction.

## Native mapping

| Purpose | Value |
| --- | --- |
| Kind | `MLAG` |
| Planner | `planNetworkMLAG(db, r)` |
| Identity | `MLAG\|<domainID>` (canonical decimal 1–4095) |
| Domain key | `MCLAG_DOMAIN\|<domainID>` |
| Domain fields | `source_ip peer_ip peer_link keepalive_interval session_timeout` |
| Member key | `MCLAG_INTERFACE\|<domainID>\|<PortChannelN>` |
| Member fields | `if_type` only, set to `PortChannel` |

| Spec field | CONFIG_DB field |
| --- | --- |
| `localAddress` | `source_ip` |
| `peerAddress` | `peer_ip` |
| `peerLink` | `peer_link` |
| `keepaliveInterval` | `keepalive_interval` (decimal seconds) |
| `sessionTimeout` | `session_timeout` (decimal seconds) |
| each `members[]` entry | member row with `if_type=PortChannel` |

`switchRef`, `peerSwitchRef` and `managementPolicy` are selectors and are never
written natively. The planner writes no `enabled`, `admin_status`, peer-health or sync
field, and its `Activate` step is nil.

## Preflight

Read-only probes run with fixed argv. Request strings are passed as separate argv
values, never through a shell.

1. `docker exec iccpd timeout 4 python3 -c <fixed probe> <trusted-hashes-json>`
   checks consumer and schema fingerprints and the running `iccpd` and `mclagsyncd`
   executables. `iccpd.sh` starts both processes in the `iccpd` container.
2. `ip -j -4 address show dev <configured-source-interface>` confirms the local IPv4
   address is assigned.
3. `ip -j -4 route get <peerAddress> from <localAddress>` confirms a unicast route
   with the exact source and destination through an existing default-VRF data
   interface (main table when explicit), without dead or linkdown flags. Routes via
   `eth0`, blackholes, missing routes and malformed output fail preflight.

The keepalive route may use the peer link or a separate data-plane path. The
interface the kernel actually selects is checked, and management routing is not
accepted. A route shows reachability, not that the peer receives traffic.

Native JSON is checked for duplicates, nulls and trailing data. Fields used as
evidence are type-checked; unrelated iproute2 fields are tolerated.

### Trusted build manifest

Set `SONIC_MLAG_CONSUMER_MANIFEST=/etc/sonic-mlag-build.json` in the **agent's**
environment. There is no command-line flag for this.

- The path must be absolute and clean.
- The file and every parent directory must be root-owned, not group- or
  world-writable, and not symlinks.
- Mount the manifest into the agent separately from the `iccpd` image. A manifest
  inside the image being measured cannot approve that image.

Produce the manifest with the actual hashes of your build. The placeholders below
are intentionally invalid:

```json
{
  "version": 1,
  "source": "sonic-net/sonic-buildimage@4784cca11:src/iccpd",
  "sha256": {
    "/usr/bin/iccpd": "REPLACE_WITH_REVIEWED_SHA256",
    "/usr/bin/mclagdctl": "REPLACE_WITH_REVIEWED_SHA256",
    "/usr/bin/mclagsyncd": "REPLACE_WITH_REVIEWED_SHA256",
    "/usr/local/yang-models/sonic-mclag.yang": "REPLACE_WITH_REVIEWED_SHA256"
  }
}
```

- All four paths are required, each with a lowercase 64-digit SHA-256 value.
- Source/version, the path set, duplicate/null/unknown fields and file size are
  validated.
- The agent passes only validated fingerprints to the fixed probe, which hashes the
  container files and checks running executables via `/proc`.
- `source` is a compatibility selector, not cryptographic provenance. Verify the
  build provenance and the hashes together.
- Without a manifest, the allowlist is empty and preflight is never eligible.
  Fingerprints are never inferred from process names or CLI output.

## Status

### STATE_DB fields

| Key | Fields read |
| --- | --- |
| `MCLAG_TABLE\|<domainID>` | `oper_status`, `role`, `system_mac`, `peer_mac` |
| `MCLAG_REMOTE_INTF_TABLE\|<domainID>\|<member>` | `oper_status` |
| `MCLAG_LOCAL_INTF_TABLE\|<member>` | `port_isolate_peer_link` |

These are reported under `observed.state`, together with `domainID`,
`consumerReady`, `preflightEligible` and a reason.

- `preflightEligible` is always a JSON boolean from the same preflight used before
  writes: audited running consumers, fresh CONFIG snapshot, local LAG and source
  dependencies, kernel address assignment and peer route. On failure it is `false`
  with a reason.
- `consumerReady` covers only the audited running consumers. It can be `true` while
  `preflightEligible` is `false`.

The controller requires `preflightEligible: true` on both switches before staging.
Peer-link and member LAGs and source/routing dependencies must pass on both peers,
but the native domain and session do not need to exist yet, which avoids a circular
dependency during initial staging.

### Native runtime evidence

After preflight passes, the agent collects `observed.native` with:

```text
docker exec iccpd timeout 4 /usr/bin/mclagdctl -i <domainID> dump state
docker exec iccpd timeout 4 /usr/bin/mclagdctl -i <domainID> dump portlist local
docker exec iccpd timeout 4 /usr/bin/mclagdctl -i <domainID> dump portlist peer
ip -j link show dev <peerlink-or-member>
docker exec iccpd timeout 4 /usr/bin/mclagdctl -i <domainID> dump state
```

Parsing details:

- `mclagdctl` has no JSON mode and no `dump mclag`. Text parsing uses the exact
  native labels (including the misspelled `sesssion Timeout `), the 60-dash port
  record boundaries and mandatory fields.
- Unknown labels, duplicate records or fields, truncation and malformed output fail
  closed.
- The two domain reads bracket the other probes. Any domain or session change
  between them invalidates the sample.
- Each native command has a 5-second host deadline; the whole runtime read has a
  12-second deadline. `timeout` also bounds the CLI inside the container. Large
  member sets may exceed the deadline and fail closed.
- Each required local LAG is queried individually, so unrelated interfaces such as
  `pimreg` (whose iproute2 output can contain `link: null`) are excluded. Each
  response must contain exactly the requested link.

### When `RuntimeVerified` is true

All of the following must hold:

- Domain ID, local and peer IPs, peer link, timers and the exact enabled member set
  match.
- `The MCLAG's keepalive is: OK` (ICCP operational) and `MCLAG info sync is:
  completed` (state exchange done).
- The CLI role is `Active` or `Standby` and matches the STATE_DB role, and STATE_DB
  domain status is `up`. The CLI role alone is not enough, because the CLI
  overwrites the received role using `inet_addr` ordering.
- Each local member and the peer link show `State: Up`, `PortchannelIsUp: 1`, have
  physical members and are not traffic-disabled. Kernel flags include `UP` and
  `LOWER_UP` with `operstate: UP`.
- Each requested peer member is a PortChannel with native `State: Up`, and its
  STATE_DB remote-interface status is `up`.

Notes:

- `IsIsolateWithPeerlink: Yes` is normal MLAG forwarding behavior and is not treated
  as a link fault.
- Missing or unknown evidence returns `false` with a reason. Redis transport/type
  errors and cancellation are returned as errors.
- STATE_DB `up` alone never establishes health. Non-native fields such as
  `info_sync_done` are ignored.
- Configuration and persistence verification are reported separately from runtime.
- This is local daemon, session and member convergence. It is not an atomic
  dual-switch snapshot, a VLAN/MTU consistency audit or proof of packet delivery.
  `mclagdctl` has no general consistency-check command.

## Tested hardware and known limitations

### Tested setup

| Item | Value |
| --- | --- |
| Platform | Dell Z9100 (Broadcom ASIC), two MLAG peers plus one dual-homed downstream switch |
| SONiC | `202511.1217682-4784cca11` |
| ICCPD | Built locally from `sonic-buildimage` `src/iccpd` matching the 202511 build; run manually, not installed as a persistent SONiC service |

The stock 202511 image ships no `iccpd` container, no `mclagdctl` and no
`FEATURE|iccpd` row. `swss` contains `/usr/bin/mclagsyncd` but does not run it. The
installed `sonic-mclag.yang` allows one domain and confirms `if_type=PortChannel`.
You need to build and supply `iccpd` yourself.

Topology used: peer link `PortChannel100`, a separate ICCP keepalive path on its own
/31, MLAG member `PortChannel10` on each peer, and a VLAN with an SVI on each peer
and on the downstream switch.

### Results

| Scenario | Result |
| --- | --- |
| Normal operation | Keepalive OK, sync completed, Active/Standby roles, both downstream members selected, pings passed. |
| One peer's downstream member disabled | Downstream LAG stayed up; both SVIs reachable with zero loss. |
| Peer link disabled | ICCP stayed synchronized and both members selected, but one peer SVI became unreachable from the downstream. Restoring the peer link restored it. |
| ICCP path down longer than session timeout | Keepalive error, sync incomplete, standby member deselected. Both SVIs stayed reachable via the active peer. Recovered after restoration. |
| Backend observation | `runtimeVerified: true` on both peers; `false` with a failed peer link; `preflightEligible: false` with a failed ICCP path. |

### Known limitations

- **Peer-link failure** does not keep all SVIs reachable. This needs further
  investigation before broader support.
- **Distinct peer SVI addresses** require `config mclag unique-ip add <Vlan>`
  **before** assigning the SVI addresses. Otherwise SVI pings fail.
- **ASIC cleanup order (Broadcom):** deleting the peer link LAG before removing
  isolation leaves an empty isolation group. A later SWSS deletion removes the APPL
  row, but the ASIC rejects the deletion (`has 1 bindings and 0 members`). A cold
  reboot clears the residual objects. Detach and verify isolation removal before
  deleting the peer link LAG. Matching CONFIG_DB and saved files do not prove the
  hardware is clean.
- The tests verified native backend observation only. They did not cover Kubernetes
  reconciliation, mTLS transport, uninterrupted failover, convergence timing,
  host-to-host transit, split-brain protection under simultaneous failures or
  production readiness.
- Configuration configured by hand with the native CLI is not adopted, so
  configuration and persistence verification stay `false` for it.

## Testing

```sh
go test ./internal/agent/sonic -run TestNetworkMLAG -count=1
go test -tags=integration ./internal/agent/sonic -run TestNetworkMLAG -count=1
go test ./internal/controller -run TestMLAG -count=1
```

- **Integration tests** run the real planner and engine with real Redis, durable
  journals, CAS and recovery; only native command transport and config save are
  faked. They cover domain/member stages, unsupported or absent consumers, missing
  dependencies, unreachable peer, malformed native evidence, no-op, ownership
  conflicts, additive restrictions, interrupted preparation and save, recovery
  revalidation, positive runtime, peer-member failure after convergence, and false
  runtime despite STATE_DB-only `up`.
- **Unit fixtures** reproduce the upstream text format, including trailing MAC
  whitespace, empty fields and native spelling. They are not captured hardware
  output.
- **Parser tests** cover identity, timer and member mismatches, missing, duplicate
  and unknown records, session transitions, admin-down/no-carrier and command
  failures.
