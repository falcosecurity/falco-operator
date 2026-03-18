# Installation

## Prerequisites

- **Kubernetes 1.29+** — The Artifact Operator runs as a [native sidecar container](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/), which requires Kubernetes 1.29 or later.
- **kubectl** — Installed and configured to access your cluster.
- **Cluster admin privileges** — Required for installing CRDs and ClusterRoles.

## Install

Install the Falco Operator using the single-manifest installer from the latest release:

```bash
kubectl apply -f https://github.com/falcosecurity/falco-operator/releases/latest/download/install.yaml
```

To install a specific version:

```bash
export OPERATOR_VERSION=v0.2.0
kubectl apply -f "https://github.com/falcosecurity/falco-operator/releases/download/${OPERATOR_VERSION}/install.yaml"
```

### What gets created

The installer deploys the following resources:

| Resource | Name | Description |
|----------|------|-------------|
| Namespace | `falco-operator` | Dedicated namespace for the operator |
| CRD | `falcos.instance.falcosecurity.dev` | Falco instance management |
| CRD | `components.instance.falcosecurity.dev` | Companion component management |
| CRD | `configs.artifact.falcosecurity.dev` | Configuration management |
| CRD | `plugins.artifact.falcosecurity.dev` | Plugin management |
| CRD | `rulesfiles.artifact.falcosecurity.dev` | Rules management |
| ServiceAccount | `falco-operator` | Operator identity |
| ClusterRole | `falco-operator-role` | Required permissions |
| ClusterRoleBinding | `falco-operator-rolebinding` | Permission binding |
| Deployment | `falco-operator` | The operator itself |

### Verify installation

```bash
kubectl get pods -n falco-operator
kubectl wait pods --for=condition=Ready --all -n falco-operator
```

## Upgrade

To upgrade to a new version, re-apply the installer manifest:

```bash
export OPERATOR_VERSION=v0.2.0
kubectl apply -f "https://github.com/falcosecurity/falco-operator/releases/download/${OPERATOR_VERSION}/install.yaml"
```

> **Important**: Before upgrading, always check the [CHANGELOG](../CHANGELOG.md) and the [migration guide](migration-guide.md) for your target version. Major releases may include breaking API changes that require updating your custom resources before or after the upgrade.

## Uninstall

Remove resources in the correct order — artifact CRs first (so the Artifact Operator sidecar can process finalizer cleanup), then instance CRs, then the operator:

```bash
# 1. Remove artifact resources first
kubectl delete rulesfiles --all --all-namespaces
kubectl delete plugins --all --all-namespaces
kubectl delete configs --all --all-namespaces

# 2. Remove instance resources
kubectl delete components --all --all-namespaces
kubectl delete falco --all --all-namespaces

# 3. Remove the operator and CRDs
kubectl delete -f https://github.com/falcosecurity/falco-operator/releases/latest/download/install.yaml
```

> **Important**: Deleting Falco instances before artifacts will terminate the Artifact Operator sidecar, leaving artifact finalizers unresolved. Always delete artifact resources first.

## Required Permissions

The operator requires the following RBAC permissions:

| API Group | Resources | Verbs |
|-----------|-----------|-------|
| `""` (core) | pods, nodes, configmaps, secrets, serviceaccounts, services, endpoints, namespaces, replicationcontrollers | get, list, watch, create, update, patch, delete |
| `""` (core), `events.k8s.io` | events | create, patch, update |
| `apps` | daemonsets, deployments, replicasets | get, list, watch, create, update, patch, delete |
| `rbac.authorization.k8s.io` | roles, rolebindings, clusterroles, clusterrolebindings | get, list, watch, create, update, patch, delete |
| `discovery.k8s.io` | endpointslices | get, list, watch |
| `instance.falcosecurity.dev` | falcos, falcos/status, falcos/finalizers, components, components/status, components/finalizers | get, list, watch, create, update, patch, delete |
| `artifact.falcosecurity.dev` | configs, configs/status, configs/finalizers, plugins, plugins/status, plugins/finalizers, rulesfiles, rulesfiles/status, rulesfiles/finalizers | get, list, watch, create, update, patch, delete |

## Next Steps

- [Getting Started](getting-started.md) — Deploy Falco and add detection rules
- [Architecture](architecture.md) — Understand how the operator works
