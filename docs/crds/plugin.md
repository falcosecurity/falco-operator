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
| `config.initConfig` | `*apiextensionsv1.JSON` | — | Plugin initialization parameters (supports nested objects). Mutually exclusive with `config.configMapRef` |
| `config.configMapRef` | `*ConfigMapRef` | — | Reference to a ConfigMap holding the plugin initialization parameters (key: `initConfig.yaml`). Mutually exclusive with `config.initConfig` |
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

### ConfigMapRef

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | **Required.** Name of the ConfigMap in the Plugin's namespace (must contain key `initConfig.yaml`) |

## Status

| Field | Type | Description |
|-------|------|-------------|
| `conditions` | `[]metav1.Condition` | Aggregated programming, reference, compatibility and deletion-blocked conditions from [ArtifactNode](artifactnode.md) resources. See [artifact status](../configuration.md#artifact-status) for the types and reasons |
| `artifactMeta` | `ArtifactMeta` | Resolved OCI digest, requirements and plugin metadata |
| `observedGeneration` | `int64` | Latest resource generation fully processed by the instance operator |

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

### Plugin with initialization config from a ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: container-init-config
data:
  initConfig.yaml: |
    label_max_len: 100
    with_size: false
---
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
    configMapRef:
      name: container-init-config
```

> Socket paths under `initConfig.engines.<engine>.sockets` are node paths (e.g. `/run/containerd/containerd.sock`) — do not prepend `/host`; the container plugin adds `HOST_ROOT` automatically.

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
- The initialization config can instead be read from a ConfigMap with `config.configMapRef`. The ConfigMap must contain a key named `initConfig.yaml` holding the config as YAML; an empty value sets no initialization config. A change of the ConfigMap rewrites the plugin configuration on the nodes the Plugin is assigned to; see [artifact reloads](../configuration.md#artifact-reloads).
- `config.initConfig` and `config.configMapRef` are mutually exclusive. A Plugin that sets both is not programmed: `ConfigProgrammed` is `False` and says why. The same happens when the ConfigMap lacks the `initConfig.yaml` key or holds invalid YAML; a missing ConfigMap sets `ResolvedRefs` to `False`.
- When `config.name` is not specified, the operator derives it from the OCI artifact metadata.
- The operator manages plugin configuration entries in the shared Falco config automatically.
- The operator adds a finalizer to referenced Secrets and ConfigMaps to prevent accidental deletion.
- OCI plugins without compatibility requirements in their metadata are blocked by default; see [artifact compatibility](../configuration.md#artifact-compatibility).
- Restarts and auth Secret rotation do not refresh an unchanged OCI tag. See [OCI revisions](../configuration.md#oci-revisions) for explicit updates and digest pinning.
- Removal can be blocked while installed rules still depend on this plugin. Inspect `DeletionBlocked` and remove or update the dependent rules before deleting it; do not strip finalizers to bypass cleanup.
