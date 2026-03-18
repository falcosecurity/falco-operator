# Config CRD Reference

**API Version**: `artifact.falcosecurity.dev/v1alpha1`
**Kind**: `Config`

## Description

The `Config` Custom Resource manages Falco configuration fragments. Fragments are written to the shared configuration directory and merged with the base Falco configuration in priority order. Configuration can be defined inline as structured YAML or loaded from a Kubernetes ConfigMap.

## Spec

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `config` | `*apiextensionsv1.JSON` | — | Structured YAML configuration fragment |
| `configMapRef` | `*ConfigMapRef` | — | Reference to a ConfigMap containing configuration (key: `config.yaml`) |
| `priority` | `int32` | `50` | Application order (0–99, lower = applied first) |
| `selector` | `*metav1.LabelSelector` | — | Node label selector for targeting specific nodes |

### ConfigMapRef

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | **Required.** Name of the ConfigMap (must contain key `config.yaml`) |

## Status

| Field | Type | Description |
|-------|------|-------------|
| `conditions` | `[]metav1.Condition` | `Programmed` and `ResolvedRefs` conditions |

## PrintColumns

`kubectl get configs` displays:

| Column | Source |
|--------|--------|
| Priority | `.spec.priority` |
| Programmed | `.status.conditions[?(@.type=="Programmed")].status` |
| Age | `.metadata.creationTimestamp` |

## Examples

### Inline configuration

```yaml
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: Config
metadata:
  name: engine-config
spec:
  config:
    engine:
      kind: modern_ebpf
      modern_ebpf:
        buf_size_preset: 4
        cpus_for_each_buffer: 2
        drop_failed_exit: false
    output_timeout: 2000
    buffered_outputs: false
    outputs_queue:
      capacity: 0
  priority: 50
```

### From ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: falco-config
data:
  config.yaml: |
    engine:
      kind: modern_ebpf
    output_timeout: 2000
---
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: Config
metadata:
  name: config-from-configmap
spec:
  configMapRef:
    name: falco-config
  priority: 50
```

### Node-specific debug config

```yaml
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: Config
metadata:
  name: debug-config
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

### Combined inline + ConfigMap

```yaml
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: Config
metadata:
  name: combined-config
spec:
  config:
    buffered_outputs: false
  configMapRef:
    name: base-config
  priority: 50
```

## Notes

- The `config` field is a structured YAML object (since v0.2.0). In v0.1.x, it was a plain string with pipe-literal (`|-`) syntax.
- The `priority` field determines the order in which configuration fragments are applied. Lower values are applied first.
- Both `config` (inline) and `configMapRef` can be used together in a single Config resource.
- The ConfigMap must contain a key named `config.yaml` with the configuration content.
- The operator adds a finalizer to referenced ConfigMaps to prevent accidental deletion.
- Node targeting via `selector` allows applying different configuration to different nodes (e.g., debug logging on specific nodes).
