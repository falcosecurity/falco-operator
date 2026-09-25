# Installation

The Falco Operator can be installed in two ways: via the official Helm chart (recommended) or by applying the bundled YAML manifest.

## Contents

- [Prerequisites](#prerequisites)
- [Install with Helm](#install-with-helm) (recommended)
- [Install with YAML manifest](#install-with-yaml-manifest)
- [Artifact transport and mTLS](#artifact-transport-and-mtls)
- [Required Permissions](#required-permissions)
- [Next Steps](#next-steps)

## Prerequisites

- **Kubernetes 1.29+**.
- **kubectl** — Installed and configured to access your cluster.
- **Cluster admin privileges** — Required for installing CRDs and ClusterRoles.
- **Helm 3.x** — Only required for the Helm installation method.

## Install with Helm

The Helm chart is the recommended way to install the Falco Operator. It packages CRDs, RBAC, the operator Deployment and artifact Service, and exposes configuration through `values.yaml`.

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
  --set resources.requests.cpu=100m
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

> **Important**: Also check the [operator release notes](https://github.com/falcosecurity/falco-operator/releases) and [chart CHANGELOG](../chart/falco-operator/CHANGELOG.md). Minor releases may include changes that require updating custom resources. For v0.4.x to v0.5.0, follow the [dedicated migration steps](migrations/v0.4.x-to-v0.5.0.md), including verification of the managed Falco workloads after Helm finishes.

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
>   rulesfiles.artifact.falcosecurity.dev \
>   artifactnodes.artifact.falcosecurity.dev
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

The installer creates these resources. Namespaced resources use `falco-operator`;
CRDs, ClusterRoles and ClusterRoleBindings are cluster-scoped.

| Resource           | Name                                    | Description                          |
| ------------------ | --------------------------------------- | ------------------------------------ |
| CRD                | `falcos.instance.falcosecurity.dev`     | Falco instance management            |
| CRD                | `components.instance.falcosecurity.dev` | Companion component management       |
| CRD                | `configs.artifact.falcosecurity.dev`    | Configuration management             |
| CRD                | `plugins.artifact.falcosecurity.dev`    | Plugin management                    |
| CRD                | `rulesfiles.artifact.falcosecurity.dev` | Rules management                     |
| CRD                | `artifactnodes.artifact.falcosecurity.dev` | Per-node installation status       |
| ServiceAccount     | `falco-operator`                        | Operator identity                    |
| ClusterRole        | `falco-operator-role`                   | Required permissions                 |
| ClusterRoleBinding | `falco-operator-rolebinding`            | Permission binding                   |
| Deployment         | `falco-operator`                        | The operator itself                  |
| Service            | `falco-operator`                        | Central artifact downloads on port 8082 |

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

> **Important**: Before upgrading, check the [operator release notes](https://github.com/falcosecurity/falco-operator/releases) and the [migration guide](migration-guide.md) for your target version. Minor releases may still include breaking API changes that require updating your custom resources before or after the upgrade.

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

## Artifact transport and mTLS

Falco pods must reach the operator's artifact Service on TCP 8082. The instance
operator needs registry access for OCI pulls and both operators need Kubernetes
API access. Account for DNS and these connections in NetworkPolicies or mesh
policies. The Falco API connection inside each pod is a separate
[startup prerequisite](configuration.md#falco-api-prerequisite).

By default the artifact server uses HTTP without application authentication or
namespace authorization. A mesh can encrypt that traffic, but does not enable the
operator's certificate-based authorization. Restrict access with network/mesh
policies if you use HTTP, especially for private artifacts: downloads use the
operator's cache and do not recheck the caller's permission to read registry
Secrets.

With `mtls.enabled: true`, cert-manager issues server and per-Falco client
certificates. The server checks the client identity against an existing Falco
resource and limits downloads to that resource's namespace. Administrators must
control who can request identities from the trusted issuer and protect its CA
key; trusting a CA alone does not enforce certificate issuance policy.

### Chart-managed CA

`mtls.createIssuer: true` requires cert-manager and trust-manager. The chart stores
its bootstrap CA Secret in the operator release namespace. Before enabling it,
check these controller-wide settings:

- cert-manager's `--cluster-resource-namespace` must point to the release namespace,
  so its ClusterIssuer can read that Secret. See the
  [cert-manager CA issuer contract](https://cert-manager.io/v1.16-docs/configuration/ca/).
- trust-manager's `app.trust.namespace` must point to the same namespace, so the
  Bundle can read its source. See the
  [trust-manager chart setting](https://github.com/cert-manager/trust-manager/blob/v0.13.0/deploy/charts/trust-manager/values.yaml#L182-L185).

Do not change these settings blindly on shared PKI installations: they affect
other issuers and Bundles. Use the externally managed issuer option below when
the existing configuration cannot host this bootstrap CA.

Create and label **both** the operator namespace and every Falco namespace before
installation. For the default release name, namespace and trust label:

```bash
kubectl create namespace falco-operator
kubectl create namespace falco
kubectl label namespace falco-operator falco artifact.falcosecurity.dev/trust=true
helm install falco-operator falcosecurity/falco-operator \
  --namespace falco-operator --set mtls.enabled=true
```

Skip namespace creation for namespaces that already exist. The chart does not
label them itself. Without the label, trust-manager does not create the
`falco-operator-artifact-ca-bundle` ConfigMap there, and pods remain in
`ContainerCreating` waiting for the mount.

Verify issuance and distribution before deploying Falco:

```bash
kubectl wait -n falco-operator issuer/falco-operator-selfsigned-issuer --for=condition=Ready --timeout=120s
kubectl wait -n falco-operator certificate/falco-operator-artifact-ca --for=condition=Ready --timeout=120s
kubectl wait clusterissuer/falco-operator-artifact-ca-issuer --for=condition=Ready --timeout=120s
kubectl wait bundle/falco-operator-artifact-ca-bundle --for=condition=Synced --timeout=120s
kubectl wait -n falco-operator certificate/falco-operator-artifact-server-tls --for=condition=Ready --timeout=120s
kubectl get configmap falco-operator-artifact-ca-bundle -n falco-operator
kubectl get configmap falco-operator-artifact-ca-bundle -n falco
```

After creating each Falco resource, check its client Certificate and pod readiness
in that namespace. Resource names change with chart name overrides. Review
[CA renewal and key rotation](configuration.md#artifact-server-ca-renewal) before
operating this CA.

### Externally managed issuer

Set `mtls.enabled: true`, `mtls.createIssuer: false`, `mtls.issuerName` to your
ClusterIssuer, and `mtls.caBundleConfigMapName` to your trust ConfigMap name.
The issuer must support server and client certificates, including the client's
SPIFFE URI SAN. Provision that ConfigMap, with a `ca-bundle.crt` key, in the
operator namespace and every Falco namespace. It must contain the trust roots
for both peers. The chart creates no CA or Bundle in this mode; trust distribution
and issuance policy remain your responsibility. cert-manager is still required.

## Required Permissions

The [generated ClusterRole](../chart/falco-operator/files/ClusterRole.yaml) is the
authoritative base permission list. The chart adds optional certificate
permissions in its [RBAC template](../chart/falco-operator/templates/rbac.yaml).

| API group | Resources | Verbs |
|-----------|-----------|-------|
| core | configmaps, pods, serviceaccounts, services | get, list, watch, create, update, patch, delete |
| core | endpoints, namespaces, nodes, replicationcontrollers | get, list, watch |
| core | secrets | get, list, watch, patch |
| core | events | create, patch |
| `events.k8s.io` | events | create, patch, update |
| `apps` | daemonsets, deployments | get, list, watch, create, update, patch, delete |
| `apps` | replicasets | get, list, watch |
| `rbac.authorization.k8s.io` | roles, rolebindings, clusterroles, clusterrolebindings | get, list, watch, create, update, patch, delete |
| `discovery.k8s.io` | endpointslices | get, list, watch |
| `instance.falcosecurity.dev` | falcos, components, and their status | get, list, watch, create, update, patch, delete |
| `artifact.falcosecurity.dev` | artifactnodes | get, list, watch, create, update, patch, delete |
| `artifact.falcosecurity.dev` | configs, plugins, rulesfiles, their status, artifactnodes/status | get, list, watch, update, patch |
| `artifact.falcosecurity.dev` | configs/finalizers, plugins/finalizers, rulesfiles/finalizers, artifactnodes/finalizers | update, patch |
| `coordination.k8s.io` | leases (leader election) | get, create, update |
| `cert-manager.io` | certificates (mTLS only) | get, list, watch, create, patch |
| Non-resource URL | `/metrics` | get |

When `rbac.create: false`, provide equivalent permissions for the enabled features
and review them on upgrades. In particular, an older role without ArtifactNode
permissions cannot support current artifact delivery; leader election needs
Leases, and mTLS needs Certificate access.

## Next Steps

- [Getting Started](getting-started.md) — Deploy Falco and add detection rules
- [Architecture](architecture.md) — Understand how the operator works
- [Migration Guide](migration-guide.md) — Switch between installation methods or upgrade across breaking releases
