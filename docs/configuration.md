# Configuration

## How Configuration Works

The Falco Operator applies configuration at two levels:

1. **Base configuration** — The operator generates a default `falco.yaml` ConfigMap based on the deployment mode (DaemonSet or Deployment). This provides sensible defaults for each mode.

2. **Configuration fragments** — `Config` Custom Resources add or override specific settings on top of the base configuration. Fragments are applied in priority order (0–99) via the Artifact Operator sidecar.

This means you do not need to provide a complete Falco configuration. Only specify the settings you want to change.

## Default Settings

### DaemonSet Mode

When a Falco CR uses `type: DaemonSet` (or omits `type`), the operator applies these defaults:

| Category | Setting | Default Value |
|----------|---------|---------------|
| **Engine** | `engine.kind` | `modern_ebpf` |
| **Container engines** | CRI, Docker | Both enabled |
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

The full default `falco.yaml` configuration (engine, CRI sockets, outputs, metrics, etc.) is defined in [`internal/pkg/resources/falco.go`](../internal/pkg/resources/falco.go).

### Deployment Mode

When a Falco CR uses `type: Deployment`, the operator applies these defaults:

| Category | Setting | Default Value |
|----------|---------|---------------|
| **Engine** | `engine.kind` | `nodriver` |
| **Container engines** | All | Disabled |
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

### Reserved names

The following container names are reserved by the operator:
- `falco` — The main Falco container
- `artifact-operator` — The Artifact Operator native sidecar

You can customize these containers in `podTemplateSpec` by matching their names.

## Artifact Operator Image

The Artifact Operator sidecar image is configurable via the `ARTIFACT_OPERATOR_IMAGE` environment variable on the Falco Operator Deployment:

```yaml
env:
  - name: ARTIFACT_OPERATOR_IMAGE
    value: "docker.io/falcosecurity/artifact-operator:v0.2.0"
```

Default: `docker.io/falcosecurity/artifact-operator:latest`
