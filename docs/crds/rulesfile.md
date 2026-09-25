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
| `registry.auth.secretRef.name` | `string` | Secret with registry credentials (keys: `username`, `password`). Ignored if `registry.auth.azure` is also set |
| `registry.auth.azure` | `*AzureAuth` | Azure identity authentication for Azure Container Registry (see below). Takes precedence over `secretRef` when both are set — not merged, `secretRef` is ignored entirely |
| `registry.plainHTTP` | `bool` | Use plain HTTP (mutually exclusive with `tls`) |
| `registry.tls.insecureSkipVerify` | `bool` | Skip TLS verification |

### AzureAuth

Authenticates to Azure Container Registry (ACR) via an Azure identity instead of a static Secret. Exactly one of four methods, selected by `method`. Every field except `method` and `serviceAccountRef` falls back to the matching `AZURE_*` environment variable on the falco-operator Deployment when left unset — see the field godoc on `AzureAuth` for the full list.

| Field | Type | Description |
|-------|------|-------------|
| `method` | `string` | **Required.** `clientSecret`, `clientCertificate`, `managedIdentity`, or `workloadIdentity` |
| `tenantId` | `string` | Microsoft Entra tenant ID. Required for `clientSecret`, `clientCertificate`, `workloadIdentity` (falls back to `AZURE_TENANT_ID`) |
| `clientId` | `string` | Application (client) ID. Required for `clientSecret`, `clientCertificate`, `workloadIdentity` (falls back to `AZURE_CLIENT_ID`); optional for `managedIdentity` (selects user-assigned when set). **Warning:** the `AZURE_CLIENT_ID` fallback applies to `managedIdentity` too — if it's set cluster-wide for the other methods' convenience, every `managedIdentity` resource that leaves this field empty silently stops being system-assigned and attempts (and fails) a user-assigned lookup with that value instead. There's no way to force system-assigned back once the environment provides a value; an empty field can't override a non-empty environment variable |
| `clientSecretRef.name` | `string` | Secret with the app registration's client secret (key: `clientSecret`). Used for `clientSecret` (falls back to `AZURE_CLIENT_SECRET`) |
| `clientCertificateRef.name` | `string` | Secret with the client certificate (key: `certificate`, PEM or PKCS#12) and optional password (key: `password`). Used for `clientCertificate` (falls back to `AZURE_CLIENT_CERTIFICATE_PATH`/`AZURE_CLIENT_CERTIFICATE_PASSWORD`) |
| `sendCertificateChain` | `bool` | Send the certificate's public chain (x5c header) for Subject Name/Issuer trust. Only used for `clientCertificate` (falls back to `AZURE_CLIENT_SEND_CERTIFICATE_CHAIN`) |
| `serviceAccountRef.name` | `string` | ServiceAccount (same namespace) to federate a token for. Required for `workloadIdentity`, no environment fallback. The named ServiceAccount must carry the annotation `azure.falcosecurity.dev/client-id`, set to exactly this `clientId`, before the operator will mint a token for it |

### ConfigMapRef

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | **Required.** Name of the ConfigMap (must contain key `rules.yaml`) |

## Status

| Field | Type | Description |
|-------|------|-------------|
| `conditions` | `[]metav1.Condition` | `Programmed` and `ResolvedRefs` conditions |
| `artifactMeta` | `ArtifactMeta` | Requirements and dependencies aggregated from every configured source |
| `artifactMetaSourcesHash` | `string` | Hash of the source snapshot represented by `artifactMeta` |
| `observedGeneration` | `int64` | Latest resource generation fully processed by the instance operator |

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

### From Azure Container Registry with workload identity

```yaml
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: Rulesfile
metadata:
  name: azure-rules
spec:
  ociArtifact:
    image:
      repository: my-org/falco-rules
      tag: v1.0.0
    registry:
      name: myregistry.azurecr.io
      auth:
        azure:
          method: workloadIdentity
          tenantId: 00000000-0000-0000-0000-000000000000
          clientId: 11111111-1111-1111-1111-111111111111
          serviceAccountRef:
            name: acr-reader
  priority: 40
```

See `examples/artifact_v1alpha1_rulesfile_oci_azure.yaml` for all four methods (three commented out), including the required ServiceAccount annotation.

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
- OCI artifacts are re-pulled when any of `image.repository`, `image.tag`, `registry.name`, `registry.plainHTTP`, `registry.tls.insecureSkipVerify`, `registry.auth.secretRef.name`, or the referenced auth Secret data changes. Pin `image.tag` to a digest (`sha256:...`) for strict GitOps: a mutable tag whose content moves on the registry is not detected until the spec changes or the pod restarts.
