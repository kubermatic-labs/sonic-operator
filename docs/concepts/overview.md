# Overview

sonic-operator is a Kubernetes-native, declarative operator for onboarding and managing the lifecycle of bare-metal network switches running SONiC.

## Components
- **Controller manager** runs in the cluster, reconciles the custom resources and maintains their status.
- **Switch agent** runs on the switch and exposes device, port, interface and configuration operations over mTLS-secured gRPC.
- **Provisioning server** serves ZTP scripts and ONIE installer artifacts over HTTP.

## Reconciliation flow
1. You create a `Switch` resource that represents a physical switch and its management endpoint.
2. The controller connects to the switch agent and observes device state.
3. The controller creates or updates `SwitchInterface` resources for the discovered interfaces.
4. Status fields on `Switch` and `SwitchInterface` are updated from the observed state.
5. When writes are enabled, desired state is applied to the device. For example, interface admin state from `SwitchInterface.spec` is enforced for interfaces annotated with `sonic.networking.metal.ironcore.dev/manage-admin-state=true`.

## Safe defaults
The controller starts in observe-only mode (`--observe-only=true`) and the agent in read-only mode (`--read-only=true`). In this mode nothing is written to the device and no ZTP/ONIE provisioning is served. Writing configuration requires explicit opt-ins on the controller, the agent and, for most features, on each resource (`managementPolicy: Manage`). See the usage pages for the gates each feature needs.

## Provisioning flow
- ZTP scripts are rendered from templates, or taken from a ConfigMap, and served at `GET /ztp`.
- ONIE installers are served from a configured directory at the HTTP root (`/`).
- The provisioning server can run embedded in the manager or as a standalone binary.
