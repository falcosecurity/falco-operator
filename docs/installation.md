# Installation

The Falco Operator can be installed in two ways: via the official Helm chart (recommended) or by applying the bundled YAML manifest.

## Contents

- [Prerequisites](#prerequisites)
- [Install with Helm](#install-with-helm) (recommended)
- [Install with YAML manifest](#install-with-yaml-manifest)
- [Required Permissions](#required-permissions)
- [Next Steps](#next-steps)

## Prerequisites

- **Kubernetes 1.29+**.
- **kubectl** — Installed and configured to access your cluster.
- **Cluster admin privileges** — Required for installing CRDs and ClusterRoles.
- **Helm 3.x** — Only required for the Helm installation method.

## Install with Helm

The Helm chart is the recommended way to install the Falco Operator. It packages CRDs, RBAC, and the operator Deployment, and exposes configuration through `values.yaml`.

### Adding the `falcosecurity` repository

Add the `falcosecurity` charts repository:

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
```

### Install

Install the chart with default values and release name `falco-operator`:

```bash
helm install falco-operator falcosecurity/falco-operator \
  --namespace falco-operator \
  --create-namespace
```

After a few seconds, verify the operator is running:

```bash
kubectl get pods -n falco-operator
kubectl wait pods --for=condition=Ready --all -n falco-operator
```

### Configuration

The chart exposes all common knobs (image, replicas, RBAC, probes, resources, tolerations, affinity, extra args, extra env, etc.) through `values.yaml`. See the full list in the [chart README](../chart/falco-operator/README.md#values) or the [`values.yaml`](../chart/falco-operator/values.yaml) file.

Override values with `--set` or a values file:

```bash
helm install falco-operator falcosecurity/falco-operator \
  --namespace falco-operator \
  --create-namespace \
  --set image.tag=0.2.1
```

```bash
helm install falco-operator falcosecurity/falco-operator \
  --namespace falco-operator \
  --create-namespace \
  -f my-values.yaml
```

### Upgrade

Review the [migration guide](migration-guide.md) for your target release before upgrading. Helm does not upgrade CRDs from a chart's `crds/` directory, so apply the target chart's CRDs before updating the release.

Choose a **chart version**, which is separate from the operator version in `appVersion`, and review your existing values file against that chart's defaults. Adjust the release name and namespace below if needed.

```bash
CHART_VERSION="<target-chart-version>"
CRD_FILE="$(mktemp)"
helm repo update
helm show chart falcosecurity/falco-operator --version "$CHART_VERSION"
helm show crds falcosecurity/falco-operator --version "$CHART_VERSION" > "$CRD_FILE"
```

After checking that the chart targets the desired operator version, apply the CRDs and wait for every CRD in that file to be established:

```bash
kubectl apply --server-side -f "$CRD_FILE" &&
kubectl wait --for=condition=Established --timeout=120s -f "$CRD_FILE"
```

If either command fails, stop before upgrading. For ownership conflicts, inspect the existing CRD and its field managers; do not add `--force-conflicts` blindly. Do not delete CRDs to resolve an upgrade conflict, because that also deletes their custom resources.

Once the CRD update succeeds, upgrade using your reviewed values file:

```bash
helm upgrade falco-operator falcosecurity/falco-operator \
  --namespace falco-operator \
  --version "$CHART_VERSION" \
  --values my-values.yaml \
  --wait --timeout 5m
```

> **Important**: Also check the [CHANGELOG](../CHANGELOG.md) and [chart CHANGELOG](../chart/falco-operator/CHANGELOG.md). Minor releases may include changes that require updating custom resources. For v0.4.x → v0.5.0, follow the [dedicated migration steps](migrations/v0.4.x-to-v0.5.0.md), including verification of the managed Falco workloads after Helm finishes.

### Uninstall

Remove resources in the correct order — artifact CRs first (so the Artifact Operator sidecar can process finalizer cleanup), then instance CRs, then the operator release:

```bash
# 1. Remove artifact resources first
kubectl delete rulesfiles --all --all-namespaces
kubectl delete plugins --all --all-namespaces
kubectl delete configs --all --all-namespaces

# 2. Remove instance resources
kubectl delete components --all --all-namespaces
kubectl delete falco --all --all-namespaces

# 3. Uninstall the Helm release
helm uninstall falco-operator --namespace falco-operator

# 4. Remove the operator namespace
kubectl delete namespace falco-operator
```

> **Important**: Deleting Falco instances before artifacts will terminate the Artifact Operator sidecar, leaving artifact finalizers unresolved. Always delete artifact resources first.

> **Note on CRDs**: Helm does not delete CRDs that are installed from a chart's `crds/` directory. If you want to fully remove the operator's API surface from the cluster, delete the CRDs manually after `helm uninstall`:
>
> ```bash
> kubectl delete crd \
>   falcos.instance.falcosecurity.dev \
>   components.instance.falcosecurity.dev \
>   configs.artifact.falcosecurity.dev \
>   plugins.artifact.falcosecurity.dev \
>   rulesfiles.artifact.falcosecurity.dev
> ```

## Install with YAML manifest

The YAML manifest is a single-file installer generated from the same Helm chart. Use it when Helm is not available or when you want to manage the operator with plain `kubectl apply`.

### Install

Create the operator namespace, then apply the single-manifest installer:

```bash
kubectl create namespace falco-operator

VERSION=latest
if [ "$VERSION" = "latest" ]; then
  kubectl apply --server-side -f https://github.com/falcosecurity/falco-operator/releases/latest/download/install.yaml
else
  kubectl apply --server-side -f https://github.com/falcosecurity/falco-operator/releases/download/${VERSION}/install.yaml
fi
```

### What gets created

The installer deploys the following resources into the `falco-operator` namespace:

| Resource           | Name                                    | Description                          |
| ------------------ | --------------------------------------- | ------------------------------------ |
| CRD                | `falcos.instance.falcosecurity.dev`     | Falco instance management            |
| CRD                | `components.instance.falcosecurity.dev` | Companion component management       |
| CRD                | `configs.artifact.falcosecurity.dev`    | Configuration management             |
| CRD                | `plugins.artifact.falcosecurity.dev`    | Plugin management                    |
| CRD                | `rulesfiles.artifact.falcosecurity.dev` | Rules management                     |
| ServiceAccount     | `falco-operator`                        | Operator identity                    |
| ClusterRole        | `falco-operator-role`                   | Required permissions                 |
| ClusterRoleBinding | `falco-operator-rolebinding`            | Permission binding                   |
| Deployment         | `falco-operator`                        | The operator itself                  |

### Verify installation

```bash
kubectl get pods -n falco-operator
kubectl wait pods --for=condition=Ready --all -n falco-operator
```

### Upgrade

To upgrade to a new version, re-apply the installer manifest:

```bash
VERSION=latest
if [ "$VERSION" = "latest" ]; then
  kubectl apply --server-side -f https://github.com/falcosecurity/falco-operator/releases/latest/download/install.yaml
else
  kubectl apply --server-side -f https://github.com/falcosecurity/falco-operator/releases/download/${VERSION}/install.yaml
fi
```

> **Important**: Before upgrading, always check the [CHANGELOG](../CHANGELOG.md) and the [migration guide](migration-guide.md) for your target version. Minor releases may still include breaking API changes that require updating your custom resources before or after the upgrade.

### Uninstall

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

# 4. Remove the operator namespace
kubectl delete namespace falco-operator
```

> **Important**: Deleting Falco instances before artifacts will terminate the Artifact Operator sidecar, leaving artifact finalizers unresolved. Always delete artifact resources first.

## Required Permissions

The operator requires the following RBAC permissions:

| API Group                    | Resources                                                                                                                                      | Verbs                                           |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| `""` (core)                  | pods, nodes, configmaps, secrets, serviceaccounts, services, endpoints, namespaces, replicationcontrollers                                     | get, list, watch, create, update, patch, delete |
| `""` (core), `events.k8s.io` | events                                                                                                                                         | create, patch, update                           |
| `apps`                       | daemonsets, deployments, replicasets                                                                                                           | get, list, watch, create, update, patch, delete |
| `rbac.authorization.k8s.io`  | roles, rolebindings, clusterroles, clusterrolebindings                                                                                         | get, list, watch, create, update, patch, delete |
| `discovery.k8s.io`           | endpointslices                                                                                                                                 | get, list, watch                                |
| `instance.falcosecurity.dev` | falcos, falcos/status, falcos/finalizers, components, components/status, components/finalizers                                                 | get, list, watch, create, update, patch, delete |
| `artifact.falcosecurity.dev` | configs, configs/status, configs/finalizers, plugins, plugins/status, plugins/finalizers, rulesfiles, rulesfiles/status, rulesfiles/finalizers | get, list, watch, create, update, patch, delete |

## Next Steps

- [Getting Started](getting-started.md) — Deploy Falco and add detection rules
- [Architecture](architecture.md) — Understand how the operator works
- [Migration Guide](migration-guide.md) — Switch between installation methods or upgrade across breaking releases
