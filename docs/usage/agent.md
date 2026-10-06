# Switch agent

The switch agent runs on the switch and exposes device, interface and
configuration operations over gRPC. The controller manager connects to the
agent to observe device state and, when writes are enabled, to apply
configuration.

## Binaries

- `cmd/agent/main.go`: gRPC server deployed on the switch.
- `cmd/agent_cli/main.go`: CLI client for the agent API, useful for diagnostics.

## Capabilities

- Get device info (MAC address, HWSKU, SONiC OS version).
- List ports and interfaces.
- Get interface state and set interface admin state.
- Get neighbor info, when available.
- Observe and, when enabled, configure VLANs, port breakout, network resources,
  FRR mode migration, ACL/QoS and redundancy features. See the respective
  usage pages.

The agent uses SONiC Redis (CONFIG_DB, APPL_DB) as its data source for switch
state.

## Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--port` | `50051` | gRPC server port. |
| `--bind-address` | `127.0.0.1` | gRPC server bind address. |
| `--redis-addr` | `127.0.0.1:6379` | SONiC Redis address. |
| `--tls-cert-file` | | Required PEM server certificate file. |
| `--tls-key-file` | | Required PEM server private key file. |
| `--tls-client-ca-file` | | Required PEM CA bundle trusted to issue client certificates. |
| `--read-only` | `true` | Only allow read RPCs. All write features require `--read-only=false`. |
| `--allow-authoritative-vlans` | `false` | Allow authoritative VLAN reconciliation and ownership release. |
| `--vlan-authority-journal-dir` | | Persistent, root-only VLAN authority journal directory. Required for authoritative writes. |
| `--allow-breakout` | `false` | Allow port breakout reconciliation. |
| `--breakout-journal-dir` | | Private, persistent, absolute breakout journal directory. Required for breakout writes. |
| `--allow-network-config` | `false` | Allow network configuration. |
| `--allow-frr-migration` | `false` | Allow FRR migration. Requires network configuration. |
| `--allow-traffic-policy` | `false` | Allow ACL and QoS configuration. Requires network configuration. |
| `--allow-redundancy` | `false` | Allow MLAG and EVPN/VXLAN configuration. Requires network configuration. |
| `--network-journal-dir` | | Private, persistent, absolute network journal directory. Required for network writes and for all cooperating writers after first use. |

The agent requires mTLS. The controller connects using the
`SONIC_AGENT_TLS_CERT_FILE`, `SONIC_AGENT_TLS_KEY_FILE`,
`SONIC_AGENT_TLS_CA_FILE` and optional `SONIC_AGENT_TLS_SERVER_NAME` settings.

Keep journal directories across agent restarts. They are used to recover
interrupted operations and to track ownership; never delete them to force
recovery.
