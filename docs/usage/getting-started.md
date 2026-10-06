# Getting started

This page shows how to build the operator from source, deploy it to a cluster and create your first resources. For packaged installation, see [Kustomize](/installation/kustomize) or [Helm](/installation/helm).

## Prerequisites
- go version v1.24.0+
- docker version 17.03+
- kubectl version v1.11.3+
- Access to a Kubernetes v1.11.3+ cluster

## Build and deploy
1. Build and push the image:

```sh
make docker-build docker-push IMG=<some-registry>/sonic-operator:tag
```

2. Install CRDs:

```sh
make install
```

3. Deploy the controller:

```sh
make deploy IMG=<some-registry>/sonic-operator:tag
```

## Create resources
Apply the sample manifests, then edit them for your environment:

```sh
kubectl apply -k config/samples/
```

The controller starts with `--observe-only=true` by default: it reads device state but makes no device writes and does not serve ZTP/ONIE provisioning. See the individual usage pages for the opt-ins required to write configuration.

## Uninstall
```sh
kubectl delete -k config/samples/
make uninstall
make undeploy
```
