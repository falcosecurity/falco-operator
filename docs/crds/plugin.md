# Plugin CRD Reference

**API Version**: `artifact.falcosecurity.dev/v1alpha1`
**Kind**: `Plugin`

## Description

The `Plugin` Custom Resource manages Falco plugins. Plugin binaries are downloaded from OCI registries and made available to Falco containers. The operator also manages plugin configuration entries in the Falco configuration.

## Spec

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ociArtifact` | `*OCIArtifact` | — | OCI artifact containing the plugin binary |
| `config.name` | `string` | — | Plugin name (used in Falco configuration) |
| `config.libraryPath` | `string` | — | Path to the `.so` file |
| `config.initConfig` | `*apiextensionsv1.JSON` | — | Plugin initialization parameters (supports nested objects) |
| `config.openParams` | `string` | — | Plugin open parameters |
| `selector` | `*metav1.LabelSelector` | — | Node label selector for targeting specific nodes |

### OCIArtifact

| Field | Type | Description |
|-------|------|-------------|
| `image.repository` | `string` | **Required.** OCI repository path (e.g., `falcosecurity/plugins/plugin/container`) |
| `image.tag` | `string` | Image tag or digest (default: `latest`) |
| `registry.name` | `string` | Registry hostname (default: `ghcr.io`) |
| `registry.auth.secretRef.name` | `string` | Secret with registry credentials (keys: `username`, `password`) |
| `registry.plainHTTP` | `bool` | Use plain HTTP (mutually exclusive with `tls`) |
| `registry.tls.insecureSkipVerify` | `bool` | Skip TLS verification |

## Status

| Field | Type | Description |
|-------|------|-------------|
| `conditions` | `[]metav1.Condition` | `Programmed` and `ResolvedRefs` conditions |

## Examples

### Container plugin

```yaml
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: Plugin
metadata:
  name: container
spec:
  ociArtifact:
    image:
      repository: falcosecurity/plugins/plugin/container
      tag: latest
    registry:
      name: ghcr.io
```

### Plugin with initialization config

```yaml
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: Plugin
metadata:
  name: container
spec:
  ociArtifact:
    image:
      repository: falcosecurity/plugins/plugin/container
      tag: latest
    registry:
      name: ghcr.io
  config:
    initConfig:
      label_max_len: 100
      with_size: false
```

### K8s audit plugin

```yaml
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: Plugin
metadata:
  name: k8saudit
spec:
  ociArtifact:
    image:
      repository: falcosecurity/plugins/plugin/k8saudit
      tag: latest
    registry:
      name: ghcr.io
  config:
    openParams: "http://:9765/k8s-audit"
```

## Notes

- The `initConfig` field accepts arbitrary nested JSON/YAML objects (since v0.2.0). In v0.1.x, it was limited to flat `map[string]string`.
- When `config.name` is not specified, the operator derives it from the OCI artifact metadata.
- The operator manages plugin configuration entries in the shared Falco config automatically.
- The operator adds a finalizer to referenced Secrets to prevent accidental deletion.
