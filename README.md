# Falco Operator

[![Falco Ecosystem Repository](https://raw.githubusercontent.com/falcosecurity/evolution/refs/heads/main/repos/badges/falco-ecosystem-blue.svg)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#ecosystem-scope) [![Incubating](https://img.shields.io/badge/status-incubating-orange?style=for-the-badge)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#incubating)
[![Last Release](https://img.shields.io/github/v/release/falcosecurity/falco-operator?style=for-the-badge)](https://github.com/falcosecurity/falco-operator/releases/latest)

![licence](https://img.shields.io/github/license/falcosecurity/falco-operator?style=for-the-badge)

The Kubernetes-native way to deploy and manage [Falco](https://falco.org). The Falco Operator transforms Falco from a powerful security tool into a fully integrated Kubernetes security solution, making it more accessible and manageable for teams of all sizes.

## Overview

The Falco Operator brings two components that work together:

- **Falco Operator** — Manages the lifecycle of Falco instances (DaemonSet or Deployment mode) and companion components (e.g., k8s-metacollector, falcosidekick, falcosidekick-ui)
- **Artifact Operator** — Manages rules, plugins, and configuration fragments (runs as a native sidecar in each Falco pod)

Five Custom Resource Definitions provide a declarative API:

| CRD | API Group | Purpose |
|-----|-----------|---------|
| [`Falco`](docs/crds/falco.md) | `instance.falcosecurity.dev/v1alpha1` | Falco instance lifecycle |
| [`Component`](docs/crds/component.md) | `instance.falcosecurity.dev/v1alpha1` | Companion components (e.g., k8s-metacollector) |
| [`Rulesfile`](docs/crds/rulesfile.md) | `artifact.falcosecurity.dev/v1alpha1` | Detection rules (OCI, inline, ConfigMap) |
| [`Plugin`](docs/crds/plugin.md) | `artifact.falcosecurity.dev/v1alpha1` | Falco plugins from OCI registries |
| [`Config`](docs/crds/config.md) | `artifact.falcosecurity.dev/v1alpha1` | Configuration fragments (inline, ConfigMap) |

## Architecture

![Falco Operator Architecture](docs/images/falco-operator-architecture.svg)

Users only need to install the Falco Operator Deployment. The Artifact Operator is automatically deployed as a native sidecar (Kubernetes 1.29+) alongside each Falco instance. Artifacts are delivered to Falco through shared `emptyDir` volumes.

For details, see the [Architecture documentation](docs/architecture.md).

## Quick Start

### Install the operator

```bash
kubectl create namespace falco-operator

VERSION=latest
if [ "$VERSION" = "latest" ]; then
  kubectl apply --server-side -f https://github.com/falcosecurity/falco-operator/releases/latest/download/install.yaml
else
  kubectl apply --server-side -f https://github.com/falcosecurity/falco-operator/releases/download/${VERSION}/install.yaml
fi
```

### Deploy Falco

```bash
cat <<EOF | kubectl apply -f -
apiVersion: instance.falcosecurity.dev/v1alpha1
kind: Falco
metadata:
  name: falco
spec: {}
EOF
```

### Add detection rules

```bash
cat <<EOF | kubectl apply -f -
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: Plugin
metadata:
  name: container
  labels:
    app.kubernetes.io/managed-by: falco-operator
spec:
  ociArtifact:
    image:
      repository: falcosecurity/plugins/plugin/container
      tag: latest
    registry:
      name: ghcr.io
---
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: Rulesfile
metadata:
  name: falco-rules
spec:
  ociArtifact:
    image:
      repository: falcosecurity/rules/falco-rules
      tag: latest
    registry:
      name: ghcr.io
  priority: 50
EOF
```

### Verify

```bash
kubectl get falco
kubectl get rulesfiles,plugins
kubectl logs -l app.kubernetes.io/name=falco -c falco --tail=10
```

For the complete walkthrough, see the [Getting Started guide](docs/getting-started.md).

## Documentation

| Document | Description |
|----------|-------------|
| [Installation](docs/installation.md) | Prerequisites, install, upgrade, uninstall |
| [Getting Started](docs/getting-started.md) | Step-by-step deployment guide |
| [Architecture](docs/architecture.md) | Components, interactions, design |
| [CRD Reference](docs/crds/) | Full reference for all Custom Resources |
| [Configuration](docs/configuration.md) | Defaults and customization |
| [Migration Guide](docs/migration-guide.md) | Upgrade from v0.1.x to v0.2.0 |
| [Contributing](docs/contributing.md) | Development, testing, PR guidelines |

## Key Features

- **Declarative management** — Define Falco deployments, rules, plugins, and configuration as Kubernetes Custom Resources
- **Multiple deployment modes** — DaemonSet for cluster-wide monitoring, Deployment for plugin-only workloads
- **Flexible artifact sources** — OCI registries, inline YAML, and Kubernetes ConfigMaps
- **Priority-based ordering** — Deterministic application of rules and configuration
- **Node targeting** — Apply different artifacts to different nodes via label selectors
- **Reference protection** — Finalizers prevent accidental deletion of referenced Secrets and ConfigMaps
- **Enhanced observability** — Kubernetes events and status conditions across all controllers
- **Server-Side Apply** — Conflict-free reconciliation with ownership tracking
- **Multi-instance support** — Run multiple Falco instances in the same cluster
- **Full pod customization** — Override any aspect of the Falco pod via `podTemplateSpec`

## License

This project is licensed to you under the [Apache 2.0](https://github.com/falcosecurity/falco-operator/blob/main/LICENSE) license.
