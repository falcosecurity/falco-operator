# Architecture

The Falco Operator manages Falco workloads, companion components and runtime artifacts through two cooperating binaries.

## Components

### Falco Operator (Instance Controller)

The instance operator runs as a Deployment, in `falco-operator` by default.
It registers seven controllers:

| Controllers | Responsibility |
|-------------|----------------|
| Falco and Component | Manage workloads, base configuration, Services and RBAC |
| ConfigMap and Secret references | Protect referenced resources with finalizers |
| Rulesfile, Plugin and Config aggregators | Process metadata, assign ArtifactNodes and aggregate per-node status |

For OCI sources, the instance operator resolves metadata and a digest, pulls the
required files into its local cache, and serves them over the artifact Service
(port 8082). Registry credentials are read from the artifact's namespace. Plugin
files are cached for the operating systems and architectures of target nodes.
Inline and ConfigMap rules also contribute compatibility metadata.

The Falco controller creates the Artifact Operator container and shared volumes
in each Falco pod. With application mTLS enabled, it also manages a per-instance
client Certificate. The chart supplies the server Certificate and trust settings.

### Artifact Operator (Sidecar Controller)

The Artifact Operator is a regular container in `spec.containers`, not a
restartable init container. Falco starts alongside it with the base configuration.
The sidecar waits for Falco's `/versions` API before starting its three artifact
controllers.

The sidecar reconciles ArtifactNodes assigned to its node and watches their parent
artifacts in its namespace. It checks compatibility, downloads OCI files from the central server, reads
inline and ConfigMap sources, and writes files to shared `emptyDir` volumes.
It manages generated plugin configuration and reports per-node installation
state in operator-owned [ArtifactNode](crds/artifactnode.md) resources.

| Controller | Sources | Falco path |
|------------|---------|------------|
| Rulesfile | OCI, inline YAML, ConfigMap | `/etc/falco/rules.d` |
| Plugin | OCI binary, plugin configuration | `/usr/share/falco/plugins` and `/etc/falco/config.d` |
| Config | Inline YAML, ConfigMap | `/etc/falco/config.d` |

### Interaction Between Components

```text
User CRs: Falco / Component / Rulesfile / Plugin / Config
                         |
                         v
             Instance operator Deployment
             | workloads, metadata, aggregate status
OCI registry --> local cache --> artifact HTTP(S) Service
                                      |
                                      v
             Falco pod: Artifact Operator sidecar
             | inline/ConfigMap sources from Kubernetes
             | compatibility checks and file installation
             +--> ArtifactNode status --> parent aggregation
             |
             v
             shared emptyDir files --> Falco reads/reloads
```

The cache and installed volumes have different owners and lifetimes. A sidecar
restart preserves the pod's volumes; pod recreation does not. A missing server
cache entry can be rebuilt from the resolved digest while sidecars retry.
Already-installed files remain available during download failures. See
[operator replicas and artifact downloads](configuration.md#operator-replicas-and-artifact-downloads)
for leader routing and cache recovery.

## Custom Resource Design

### API Groups

All custom resources are namespaced.

| API Group | CRDs |
|-----------|------|
| `instance.falcosecurity.dev/v1alpha1` | User-managed `Falco`, `Component` |
| `artifact.falcosecurity.dev/v1alpha1` | User-managed `Rulesfile`, `Plugin`, `Config`; operator-managed `ArtifactNode` |

### Status and Conditions

Instance resources report `Reconciled` and `Available`. Artifact parents report
aggregated node conditions and `status.observedGeneration`; Rulesfile and Plugin
also hold resolved metadata. Per-node conditions distinguish reference resolution,
compatibility, source installation, generated plugin configuration and blocked
deletion. See the [ArtifactNode reference](crds/artifactnode.md).

Desired configuration, installed files and Falco's loaded runtime state are
distinct. `Programmed=True` is not a reload acknowledgement. Check current
generations, installed files and Falco behavior when verifying an update.
[Reloads are best effort](configuration.md#artifact-reloads).

### Reference Protection

The operator protects referenced resources with these finalizers:

- `artifact.falcosecurity.dev/secret-in-use`: Secrets holding registry credentials.
- `artifact.falcosecurity.dev/configmap-in-use`: ConfigMaps referenced by rules or configuration.

Artifact finalizers also track cleanup. Plugin removal can wait for installed rules that still
depend on it. Remove artifacts before the Falco workloads that run their cleanup
controllers; see [uninstall](installation.md#uninstall).

## Reconciliation Strategy

Controllers use Server-Side Apply for managed resources and status, and patches
for finalizers. Field ownership limits unrelated changes; ownership conflicts
still require investigation. Reconciliation retries incomplete work rather than
treating a successful API write as proof of installed files or loaded Falco state.

## Default Configuration

### DaemonSet Mode (default)

| Setting | Value |
|---------|-------|
| Engine | `modern_ebpf` |
| Outputs | stdout + syslog |
| Webserver | Enabled (port 8765, Prometheus metrics) |
| Security context | Privileged |
| Host mounts | `/proc`, `/sys`, `/dev`, `/etc`, container runtimes |
| Resource requests | 100m CPU, 512Mi memory |
| Resource limits | 1000m CPU, 1024Mi memory |
| Probes | Startup (HTTP `/healthz`, 3s delay, 5s period, 20 failures), Liveness & Readiness (0s delay — the startup probe handles the wait) |

### Deployment Mode

| Setting | Value |
|---------|-------|
| Engine | `nodriver` (plugin-only) |
| Designed for | Plugin-based event sources |

### Artifact Operator Sidecar

| Setting | Value |
|---------|-------|
| Image | Configurable via `ARTIFACT_OPERATOR_IMAGE` env var |
| Default image | Matching release image embedded at build time; local fallback is `latest` |
| Probes | Startup (`/readyz`, 3s delay), Readiness (`/readyz`, 5s delay), Liveness (`/healthz`, 15s delay) — all on port 8081 |
| Volumes | 3 shared `emptyDir` volumes (config, rulesfiles, plugins) |
