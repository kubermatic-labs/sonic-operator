# Documentation

This directory contains the documentation for sonic-operator.

## Getting started
- `quickstart.md`: where to start.
- `installation/kustomize.md`, `installation/helm.md`: installation methods.
- `architecture.md`: components and high-level flow.

## Concepts
- `concepts/overview.md`: architecture, components, and reconciliation flow.
- `concepts/resources.md`: all custom resources at a glance.

## Usage
- `usage/getting-started.md`: build, deploy, and create first resources.
- `usage/provisioning.md`: ZTP scripts and ONIE installer delivery.
- `usage/agent.md`: the switch agent and its gRPC API.
- `usage/vlans.md`: Layer-2 VLANs (additive management).
- `usage/vlan-authoritative.md`: authoritative VLAN membership management.
- `usage/breakout.md`: port breakout.
- `usage/network-resources.md`: system, management, VRF, port channel, Layer-3 and static route resources.
- `usage/host-resources.md`: host-level switch resources.
- `usage/lag-l3-mappings.md`: LAG and Layer-3 mappings.
- `usage/bgp-relay.md`: BGP and DHCP relay.
- `usage/frr-migration.md`: FRR mode migration.
- `usage/traffic-policy.md`: ACL and QoS.
- `usage/redundancy.md`: redundancy.
- `usage/mlag.md`: MLAG.
- `usage/evpn-vxlan.md`: EVPN/VXLAN.
- `usage/evpn-hardware-qualification.md`: EVPN hardware qualification.

## Development
- `development/dev-workflow.md`: build, lint, test, and docs generation.
- `development/reuse.md`: REUSE compliance and license checks.
- `development/dev-docs.md`: documentation tooling and release pipeline.

## Local preview (VitePress)
```sh
make startdocs
```

Cleanup:
```sh
make cleandocs
```
