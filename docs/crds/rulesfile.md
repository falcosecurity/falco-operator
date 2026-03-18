# Rulesfile CRD Reference

**API Version**: `artifact.falcosecurity.dev/v1alpha1`
**Kind**: `Rulesfile`

## Description

The `Rulesfile` Custom Resource manages Falco detection rules. Rules can be sourced from OCI registries, defined inline as YAML, or loaded from Kubernetes ConfigMaps. All three sources can be combined in a single resource.

## Spec

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ociArtifact` | `*OCIArtifact` | — | OCI artifact containing rules |
| `inlineRules` | `*apiextensionsv1.JSON` | — | Structured YAML rules defined inline |
| `configMapRef` | `*ConfigMapRef` | — | Reference to a ConfigMap containing rules (key: `rules.yaml`) |
| `priority` | `int32` | `50` | Application order (0–99, lower = applied first) |
| `selector` | `*metav1.LabelSelector` | — | Node label selector for targeting specific nodes |

### OCIArtifact

| Field | Type | Description |
|-------|------|-------------|
| `image.repository` | `string` | **Required.** OCI repository path (e.g., `falcosecurity/rules/falco-rules`) |
| `image.tag` | `string` | Image tag or digest (default: `latest`) |
| `registry.name` | `string` | Registry hostname (default: `ghcr.io`) |
| `registry.auth.secretRef.name` | `string` | Secret with registry credentials (keys: `username`, `password`) |
| `registry.plainHTTP` | `bool` | Use plain HTTP (mutually exclusive with `tls`) |
| `registry.tls.insecureSkipVerify` | `bool` | Skip TLS verification |

### ConfigMapRef

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | **Required.** Name of the ConfigMap (must contain key `rules.yaml`) |

## Status

| Field | Type | Description |
|-------|------|-------------|
| `conditions` | `[]metav1.Condition` | `Programmed` and `ResolvedRefs` conditions |

## Examples

### From OCI registry

```yaml
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
```

### From OCI with private registry

```yaml
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: Rulesfile
metadata:
  name: private-rules
spec:
  ociArtifact:
    image:
      repository: my-org/falco-rules
      tag: v1.0.0
    registry:
      name: registry.example.com
      auth:
        secretRef:
          name: registry-credentials
  priority: 40
```

### Inline rules

```yaml
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: Rulesfile
metadata:
  name: custom-rules
spec:
  inlineRules:
    - rule: Terminal shell in container
      desc: A shell was used as the entrypoint into a container with an attached terminal.
      condition: >
        spawned_process and container
        and shell_procs and proc.tty != 0
        and container_entrypoint
      output: >
        A shell was spawned in a container (user=%user.name container_id=%container.id
        image=%container.image.repository)
      priority: NOTICE
      tags: [container, shell, mitre_execution]
  priority: 60
```

### From ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: my-rules
data:
  rules.yaml: |
    - rule: Write below binary dir
      desc: An attempt to write below a binary directory.
      condition: bin_dir and evt.dir = < and open_write
      output: File below binary dir opened for writing (file=%fd.name)
      priority: ERROR
      tags: [filesystem, mitre_persistence]
---
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: Rulesfile
metadata:
  name: configmap-rules
spec:
  configMapRef:
    name: my-rules
  priority: 55
```

### Node-targeted rules

```yaml
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: Rulesfile
metadata:
  name: production-rules
spec:
  ociArtifact:
    image:
      repository: falcosecurity/rules/falco-rules
      tag: latest
    registry:
      name: ghcr.io
  priority: 50
  selector:
    matchLabels:
      environment: production
```

## Notes

- The `priority` field determines the order in which rules files are loaded by Falco. Lower values are loaded first.
- When combining multiple sources (OCI + inline + ConfigMap), each source gets a sub-priority within the main priority.
- The ConfigMap must contain a key named `rules.yaml` with the rules content.
- The operator adds a finalizer to referenced ConfigMaps to prevent accidental deletion.
