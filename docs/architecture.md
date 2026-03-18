# Architecture

The Falco Operator manages Falco deployments, companion components, and runtime artifacts in Kubernetes through a set of cooperating controllers.

![Falco Operator Architecture](./images/falco-operator-architecture.svg)

## Components

### Falco Operator (Instance Controller)

The Falco Operator is the primary component that users install and interact with. It runs as a Deployment in the `falco-operator` namespace and watches for Custom Resources in the `instance.falcosecurity.dev` and `artifact.falcosecurity.dev` API groups.

The instance operator binary registers four controllers:
1. **Falco controller** — Reconciles `Falco` CRs
2. **Component controller** — Reconciles `Component` CRs
3. **ConfigMap reference controller** — Manages ConfigMap finalizers
4. **Secret reference controller** — Manages Secret finalizers

**Responsibilities:**
- Reconcile `Falco` CRs into DaemonSets or Deployments
- Reconcile `Component` CRs into Deployments for companion services
- Manage RBAC resources (ServiceAccount, Role, RoleBinding, ClusterRole, ClusterRoleBinding)
- Create Services for pod discovery
- Create ConfigMaps with base Falco configuration
- Deploy the Artifact Operator as a native sidecar in each Falco pod
- Track Secret and ConfigMap references with finalizers

**Reconciliation flow for Falco CRs:**
1. Fetch the Falco CR
2. Handle deletion (cleanup via finalizers)
3. Create RBAC resources
4. Create a Service
5. Create a ConfigMap with base configuration
6. Apply defaults (engine mode, resource limits, probes)
7. Set finalizer for graceful deletion
8. Create the DaemonSet or Deployment with the Artifact Operator as a native sidecar

### Artifact Operator (Sidecar Controller)

The Artifact Operator runs as a **native sidecar container** (Kubernetes 1.29+) in each Falco pod. It watches for Custom Resources in the `artifact.falcosecurity.dev` API group and delivers artifacts to the Falco container via shared `emptyDir` volumes.

**Responsibilities:**
- Watch for `Rulesfile`, `Plugin`, and `Config` CRs
- Download OCI artifacts (rules and plugin binaries)
- Resolve inline definitions and ConfigMap references
- Write artifacts to the shared filesystem with priority ordering
- Manage plugin configuration entries
- Record Kubernetes events for all operations

**Three controllers handle different artifact types:**

| Controller | Artifact Type | Sources | Output Path |
|------------|--------------|---------|-------------|
| Rulesfile | Detection rules (`.yaml`) | OCI artifact, inline YAML, ConfigMap | Shared rulesfiles volume |
| Plugin | Plugin binaries (`.so`) | OCI artifact | Shared plugins volume |
| Config | Configuration fragments (`.yaml`) | Inline YAML, ConfigMap | Shared config volume |

### Interaction Between Components

```
┌─────────────────────────────────────────────────────────────────┐
│                     Kubernetes API Server                        │
│                                                                  │
│  Falco CR   Component CR   Rulesfile CR   Plugin CR   Config CR  │
└─────┬───────────┬──────────────┬────────────┬──────────┬────────┘
      │           │              │            │          │
      ▼           ▼              ▼            ▼          ▼
┌──────────────────────┐
│   Falco Operator     │   Watches all CRDs, reconciles
│   (Deployment)       │   Falco instances, Components,
│                      │   and reference finalizers
└───┬──────────┬───────┘
    │          │ creates
    │          ▼
    │  ┌─────────────────────────────────────────────────┐
    │  │  Falco Pod (per node or replica)                 │
    │  │                                                  │
    │  │  ┌──────────────────┐  ┌──────────────────────┐  │
    │  │  │ Artifact Operator│  │   Falco Container    │  │
    │  │  │ (native sidecar) │  │                      │  │
    │  │  │                  │  │   modern_ebpf /      │  │
    │  │  │ Watches artifact │  │   nodriver           │  │
    │  │  │ CRs, downloads   │  │                      │  │
    │  │  │ OCI artifacts,   │  │  Reads:              │  │
    │  │  │ writes to shared │  │   /etc/falco/rules.d │  │
    │  │  │ volumes ─────────┼──┼─► /etc/falco/config.d│  │
    │  │  │                  │  │   /usr/share/falco/   │  │
    │  │  │                  │  │     plugins/          │  │
    │  │  └──────────────────┘  └──────────────────────┘  │
    │  └──────────────────────────────────────────────────┘
    │ creates
    ▼
┌──────────────────────────────┐
│  Component Deployment        │  e.g., k8s-metacollector
│  (per Component CR)          │
└──────────────────────────────┘
```

Users only need to install the Falco Operator Deployment. The Artifact Operator is automatically deployed as a sidecar alongside each Falco instance — users never interact with it directly.

## Custom Resource Design

### API Groups

| API Group | Scope | CRDs |
|-----------|-------|------|
| `instance.falcosecurity.dev/v1alpha1` | Cluster-level instance management | `Falco`, `Component` |
| `artifact.falcosecurity.dev/v1alpha1` | Per-node artifact delivery | `Rulesfile`, `Plugin`, `Config` |

### Status and Conditions

All CRDs report status through Kubernetes conditions:

**Instance CRDs (`Falco`, `Component`):**
- `Reconciled` — Whether the last reconciliation succeeded
- `Available` — Whether the service is ready

**Artifact CRDs (`Rulesfile`, `Plugin`, `Config`):**
- `Programmed` — Whether the artifact is successfully applied
- `ResolvedRefs` — Whether all referenced resources (ConfigMaps, Secrets) exist

### Reference Protection

The operator uses Kubernetes finalizers to protect referenced resources:

- `artifact.falcosecurity.dev/secret-in-use` — Prevents deletion of Secrets referenced by OCI artifact credentials
- `artifact.falcosecurity.dev/configmap-in-use` — Prevents deletion of ConfigMaps referenced by Rulesfile or Config resources

## Reconciliation Strategy

All controllers use **Server-Side Apply (SSA)** for resource management:

- The operator only manages fields it owns, leaving user-applied changes intact
- Concurrent modifications to managed fields are detected and reported
- Managed fields comparison prevents unnecessary API calls (spurious updates)
- Finalizer operations use Patch instead of Update for safety

## Default Configuration

### DaemonSet Mode (default)

| Setting | Value |
|---------|-------|
| Engine | `modern_ebpf` |
| Container engines | CRI + Docker enabled |
| Outputs | stdout + syslog |
| Webserver | Enabled (port 8765, Prometheus metrics) |
| Security context | Privileged |
| Host mounts | `/proc`, `/sys`, `/dev`, `/etc`, container runtimes |
| Resource requests | 100m CPU, 512Mi memory |
| Resource limits | 1000m CPU, 1024Mi memory |
| Probes | Liveness (60s delay), Readiness (30s delay) |

### Deployment Mode

| Setting | Value |
|---------|-------|
| Engine | `nodriver` (plugin-only) |
| Container engines | All disabled |
| Designed for | Plugin-based event sources |

### Artifact Operator Sidecar

| Setting | Value |
|---------|-------|
| Image | Configurable via `ARTIFACT_OPERATOR_IMAGE` env var |
| Default image | `docker.io/falcosecurity/artifact-operator:latest` |
| Probes | Readiness (5s delay), Liveness (15s delay) on port 8081 |
| Volumes | 3 shared `emptyDir` volumes (config, rulesfiles, plugins) |
