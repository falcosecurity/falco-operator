# Configuration

## How Configuration Works

The Falco Operator applies configuration at two levels:

1. **Base configuration** — The operator generates a default `falco.yaml` ConfigMap based on the deployment mode (DaemonSet or Deployment). This provides sensible defaults for each mode.

2. **Configuration fragments** — `Config` Custom Resources add or override specific settings on top of the base configuration. Fragments are applied in priority order (0–99) via the Artifact Operator sidecar.

This means you do not need to provide a complete Falco configuration. Only specify the settings you want to change.

## Default Settings

> These are the defaults of the operator-generated base `falco.yaml`. Optional functionality such as container metadata enrichment (`container.*`, `k8s.*` fields) is **not** part of the base config — load the [container plugin](getting-started.md) via a `Plugin` CR to enable it.

### DaemonSet Mode

When a Falco CR uses `type: DaemonSet` (or omits `type`), the operator applies these defaults:

| Category | Setting | Default Value |
|----------|---------|---------------|
| **Engine** | `engine.kind` | `modern_ebpf` |
| **Outputs** | `stdout_output.enabled` | `true` |
| | `syslog_output.enabled` | `true` |
| **Webserver** | `webserver.enabled` | `true` |
| | `webserver.listen_port` | `8765` |
| | `webserver.prometheus_metrics_enabled` | `true` |
| **Security** | Security context | Privileged |
| **Host mounts** | Paths | `/proc`, `/sys`, `/dev`, `/etc`, container runtime sockets |
| **Resources** | CPU request | `100m` |
| | Memory request | `512Mi` |
| | CPU limit | `1000m` |
| | Memory limit | `1024Mi` |
| **Probes** | Startup | HTTP `/healthz`, delay 3s, period 5s, 20 failures (~103s max) |
| | Liveness | HTTP `/healthz`, delay 0s (startup probe handles the wait) |
| | Readiness | HTTP `/healthz`, delay 0s (startup probe handles the wait) |

The full default `falco.yaml` configuration (engine, outputs, metrics, etc.) is defined in [`internal/pkg/resources/falco.go`](../internal/pkg/resources/falco.go).

### Deployment Mode

When a Falco CR uses `type: Deployment`, the operator applies these defaults:

| Category | Setting | Default Value |
|----------|---------|---------------|
| **Engine** | `engine.kind` | `nodriver` |
| **Designed for** | | Plugin-only workloads |

All other settings (outputs, webserver, resources) follow the same defaults as DaemonSet mode.

## Overriding Configuration

### Using Config CRs

Create a `Config` resource to override specific settings:

```yaml
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: Config
metadata:
  name: http-output
spec:
  config:
    http_output:
      enabled: true
      url: "http://falcosidekick.falco.svc:2801"
  priority: 50
```

### Using ConfigMap references

Store configuration in a ConfigMap and reference it:

```yaml
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: Config
metadata:
  name: base-config
spec:
  configMapRef:
    name: falco-base-config
  priority: 30
```

The ConfigMap must contain a key named `config.yaml`.

### Priority ordering

Configuration fragments are applied in ascending priority order:
- **Priority 0–29**: Base overrides (applied first)
- **Priority 30–69**: Standard configuration
- **Priority 70–99**: High-priority overrides (applied last, wins on conflicts)

Example: A Config with priority 30 sets `output_timeout: 1000`, and another with priority 70 sets `output_timeout: 5000`. The effective value is `5000`.

### Node-specific configuration

Use label selectors to apply configuration to specific nodes:

```yaml
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: Config
metadata:
  name: debug-node1
spec:
  config:
    libs_logger:
      enabled: true
      severity: debug
  priority: 90
  selector:
    matchLabels:
      kubernetes.io/hostname: "node1"
```

## Customizing the Falco Pod

The `podTemplateSpec` field in the Falco CR allows full control over the pod specification:

```yaml
apiVersion: instance.falcosecurity.dev/v1alpha1
kind: Falco
metadata:
  name: falco
spec:
  podTemplateSpec:
    spec:
      containers:
        - name: falco
          resources:
            requests:
              cpu: 500m
              memory: 1Gi
            limits:
              cpu: 2000m
              memory: 2Gi
      tolerations:
        - key: "node-role.kubernetes.io/control-plane"
          effect: "NoSchedule"
      nodeSelector:
        kubernetes.io/os: linux
```

Environment entries in `containers` and `initContainers` override defaults by name.
An explicit entry replaces the whole variable, including its `valueFrom` source;
`value: ""` (or just `name`) sets an empty value. Variables omitted from the
override retain their defaults. The same behavior applies to Component Pod templates.

For an environment variable with the same `name`:

| Operator default | Pod template override | Result |
|------------------|-----------------------|--------|
| `value: "30s"` | `valueFrom.secretKeyRef` | Only the Secret reference remains; the literal value is removed |
| `valueFrom.fieldRef` | `value: "manual"` | Only the literal value remains; the field reference is removed |
| Any value or source | `value: ""` | Explicitly empty value, with no `valueFrom` |
| Any value or source | Variable omitted | Operator default retained |

This replacement applies to each explicitly overridden environment variable,
not to the whole `env` list or every field of the Pod template.

### Reserved names

The following container names are reserved by the operator:
- `falco` — The main Falco container
- `artifact-operator` — The Artifact Operator native sidecar

You can customize these containers in `podTemplateSpec` by matching their names.

## Artifact Server DNS

The artifact server URL uses the cluster DNS domain, which defaults to
`cluster.local`. For a different domain, set the Helm value `clusterDomain` to the
domain configured in your cluster. This updates both the advertised URL and the
server certificate when mTLS is enabled.

For installations without Helm, configure the instance operator with
`--cluster-domain` or `CLUSTER_DOMAIN`, and ensure any server certificate covers
the resulting Service hostname. An explicit `ARTIFACT_SERVER_URL` still overrides
the generated URL and requires a certificate matching that URL when using TLS.

## Artifact Reloads

With Falco versions before 0.45, artifact reloads are **best effort**. By default,
the Artifact Operator sends SIGHUP and waits at least **5 seconds** before checking Falco's HTTP
endpoint or sending another signal. This cooldown reduces repeated signals; it
does not confirm that a reload completed or prevent every conflict with Falco's
own file watcher. Support for the reload changes planned for Falco 0.45 will be
validated separately; this setting does not enable a different reload mechanism.

Configure the cooldown per instance on the `artifact-operator` container:

```yaml
apiVersion: instance.falcosecurity.dev/v1alpha1
kind: Falco
metadata:
  name: falco
spec:
  podTemplateSpec:
    spec:
      containers:
        - name: artifact-operator
          env:
            - name: FALCO_RELOAD_COOLDOWN
              value: "5s"
```

The value must be a positive duration, such as `4s` or `10s`. The equivalent flag
is `--falco-reload-cooldown`; an explicit flag takes precedence over the environment
variable. Changing the Pod template follows the workload's update strategy; this
is not a live adjustment to an already-running sidecar. Falco metrics are not
required for the cooldown or the HTTP availability check.

## Artifact Downloads

The Artifact Operator limits each download from the central artifact server to
**5 minutes** by default. This is the total time for one attempt, including
connection setup and reading the response, not an inactivity timeout. A failed
download does not replace the installed OCI file; the controller retries it.
This setting does not affect registry pulls performed by the instance operator.

Set a global default using the Helm chart's existing `extraEnv`:

```yaml
extraEnv:
  - name: ARTIFACT_DOWNLOAD_TIMEOUT
    value: "2m"
```

The instance operator injects this value into its Artifact Operator sidecars.
Override it for one Falco instance through its Pod template:

```yaml
spec:
  podTemplateSpec:
    spec:
      containers:
        - name: artifact-operator
          env:
            - name: ARTIFACT_DOWNLOAD_TIMEOUT
              value: "1m"
```

Both binaries also accept `--artifact-download-timeout`; an explicit flag takes
precedence over the environment variable. Values must be positive Go durations,
such as `30s` or `2m`; zero does not disable the timeout. Updating an injected
value changes the Pod template and follows the workload's update strategy, not
a live reload. TCP connection setup and TLS handshakes retain their respective
30-second and 10-second limits. The central server's existing 5-minute write
timeout is independent: increasing the client timeout does not extend it.

## Artifact Operator Image

The Artifact Operator sidecar image is configurable via the `ARTIFACT_OPERATOR_IMAGE` environment variable on the Falco Operator Deployment:

```yaml
env:
  - name: ARTIFACT_OPERATOR_IMAGE
    value: "docker.io/falcosecurity/artifact-operator:v0.2.0"
```

Default: `docker.io/falcosecurity/artifact-operator:latest`

## Operator replicas and artifact downloads

When running more than one operator replica, enable leader election in the Helm values:

```yaml
replicaCount: 2
extraArgs:
  - --leader-elect=true
```

Only the leader runs the artifact server. Standby replicas remain Ready so that
Deployment rollouts can complete. The artifact Service selects the runtime label
`artifact.falcosecurity.dev/serving=true`, which the operator publishes after opening
its listener. Do not set this label in `podLabels`: it is managed by the running server.
Without leader election, each running server publishes its own label.

The operator clears its retained label on startup, before starting its default health
endpoint, and reconciles routing every five seconds. In steady state this makes two
API reads per server, plus one filtered Pod list when leader election is enabled;
unchanged labels are not patched. Keep the default readiness probe to preserve the
startup ordering. Election and Service endpoint updates are asynchronous, so failover
can temporarily interrupt downloads.

Artifact caches are local to each replica. A newly elected leader rebuilds missing
cache entries from the already-resolved digests, without following floating tags to
a different revision. It needs access to the registry and the configured credentials;
sidecars retry while the cache is being populated. Already-installed artifacts are
not removed because the server is temporarily unavailable.

## Artifact server CA renewal

With `mtls.createIssuer: true`, cert-manager automatically renews the bootstrap CA
certificate. The chart sets `privateKey.rotationPolicy: Never` on this CA so renewal
reuses its private key and existing, valid server and client certificates remain
trusted. This does not change the renewal or key rotation policy of those server
and client certificates, or of externally managed CAs.

The chart does not automate CA key rotation. Its trust-manager Bundle normally
contains one CA; replacing that CA does not retain trust in the old one, and a
CA Secret update does not automatically reissue existing leaf certificates.
Plan a dual-trust interval, renew the server and all client certificates against
the new CA, and verify their use before withdrawing the old CA. Review the
[CA issuer requirements](https://cert-manager.io/v1.16-docs/configuration/ca/)
before changing the issuer. Key reuse cannot recover a lost CA key or undo a
rotation already underway.

## Excluding labels from propagation

The operator copies the labels of a `Falco` (or `Component`) resource onto the resources it generates.
Some external tools add their own labels to the resources they manage and rely on them to decide which objects they own.
When such a label is copied onto a generated resource, the tool may treat that resource as one of its own and remove it when it is not part of its desired state.
Namespaced resources are protected by their `OwnerReference`, but cluster-scoped resources (`ClusterRole`, `ClusterRoleBinding`) cannot carry one, so they may be removed and recreated repeatedly.

The `--excluded-labels` flag lists label keys the operator must not copy from the resource's `metadata.labels` onto the resources it generates.
Matching keys are dropped wherever the operator would propagate them — including the workload metadata and its pod template — while pod selector labels are always preserved.
Labels you set explicitly (for example in `spec.podTemplateSpec.metadata.labels`) are left untouched.
The `*` wildcard is supported and the flag may be repeated.

The Helm chart exposes this as the `excludedLabels` array. It is empty by default — add the label keys your environment requires:

```yaml
excludedLabels:
  - argocd.argoproj.io/instance
  - kustomize.toolkit.fluxcd.io/name
  - kustomize.toolkit.fluxcd.io/namespace
```
