# Migration Guide: v0.1.x to v0.2.0

This guide covers all breaking changes in Falco Operator v0.2.0 and the steps required to migrate from v0.1.x.

> **Warning**: This migration involves breaking API changes. Existing custom resources with the old schema will not validate against the new CRDs. **Test the migration in a staging environment first.** The recommended approach is to delete existing artifact and instance CRs, apply the new CRDs and operator, and recreate the CRs with the updated format.

## Migration Steps Overview

1. [Back up existing resources](#step-1-back-up-existing-resources)
2. [Delete existing resources](#step-2-delete-existing-resources)
3. [Update CRDs and operator](#step-3-update-crds-and-operator)
4. [Recreate resources with new format](#step-4-recreate-resources-with-new-format)
5. [Update monitoring and scripts](#step-5-update-monitoring-and-scripts)

## Step 1: Back up existing resources

Export your current custom resources before making changes:

```bash
kubectl get rulesfiles -o yaml --all-namespaces > rulesfiles-backup.yaml
kubectl get plugins -o yaml --all-namespaces > plugins-backup.yaml
kubectl get configs -o yaml --all-namespaces > configs-backup.yaml
kubectl get falcos -o yaml --all-namespaces > falcos-backup.yaml
```

## Step 2: Delete existing resources

Delete resources in the correct order (artifacts first, then instances):

```bash
kubectl delete rulesfiles --all --all-namespaces
kubectl delete plugins --all --all-namespaces
kubectl delete configs --all --all-namespaces
kubectl delete falco --all --all-namespaces
```

## Step 3: Update CRDs and operator

Apply the new install manifest, which includes updated CRDs and the new operator version:

```bash
export OPERATOR_VERSION=v0.2.0
kubectl apply -f "https://github.com/falcosecurity/falco-operator/releases/download/${OPERATOR_VERSION}/install.yaml"
```

This adds the new `Component` CRD and updates all existing CRDs with new fields, conditions, and print columns.

## Step 4: Recreate resources with new format

Use the following sections to convert your backed-up resources to the new API format.

### OCI artifact references

**Affected resources**: `Rulesfile` and `Plugin` CRs that use `ociArtifact`

The `ociArtifact` structure has been completely redesigned. The flat `reference` and `pullSecret` fields are replaced with structured `image` and `registry` objects.

### Rulesfile

**Before (v0.1.x):**
```yaml
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: Rulesfile
metadata:
  name: falco-rules
spec:
  ociArtifact:
    reference: ghcr.io/falcosecurity/rules/falco-rules:latest
```

**After (v0.2.0):**
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
```

### Plugin

**Before (v0.1.x):**
```yaml
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: Plugin
metadata:
  name: container
spec:
  ociArtifact:
    reference: ghcr.io/falcosecurity/plugins/plugin/container:0.2.4
  config:
    initConfig:
      label_max_len: "100"
```

**After (v0.2.0):**
```yaml
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: Plugin
metadata:
  name: container
spec:
  ociArtifact:
    image:
      repository: falcosecurity/plugins/plugin/container
      tag: "0.2.4"
    registry:
      name: ghcr.io
  config:
    initConfig:
      label_max_len: 100
```

### With private registry credentials

**Before (v0.1.x):**
```yaml
spec:
  ociArtifact:
    reference: registry.example.com/my-org/rules:v1.0
    pullSecret:
      secretName: my-secret
      usernameKey: username
      passwordKey: password
```

**After (v0.2.0):**
```yaml
spec:
  ociArtifact:
    image:
      repository: my-org/rules
      tag: v1.0
    registry:
      name: registry.example.com
      auth:
        secretRef:
          name: my-secret
```

> **Note**: The Secret must use keys `username` and `password`. The `usernameKey` and `passwordKey` options have been removed — the key names are now fixed.

### How to split a reference string

Given a reference like `ghcr.io/falcosecurity/rules/falco-rules:latest`:

| v0.1.x field | v0.2.0 field | Value |
|-------------|-------------|-------|
| `reference` (full string) | — | *(removed)* |
| — | `registry.name` | `ghcr.io` |
| — | `image.repository` | `falcosecurity/rules/falco-rules` |
| — | `image.tag` | `latest` |

### Config resources

**Affected resources**: All `Config` CRs

The `spec.config` field changed from a YAML string to a structured YAML object.

**Before (v0.1.x):**
```yaml
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: Config
metadata:
  name: my-config
spec:
  config: |-
    engine:
      kind: modern_ebpf
    output_timeout: 2000
```

**After (v0.2.0):**
```yaml
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: Config
metadata:
  name: my-config
spec:
  config:
    engine:
      kind: modern_ebpf
    output_timeout: 2000
```

**Migration**: Remove the `|-` (pipe-literal) indicator and de-indent the YAML content so it becomes a direct YAML object under `config:`.

### Rulesfile inline rules

**Affected resources**: `Rulesfile` CRs that use `inlineRules`

The `spec.inlineRules` field changed from a YAML string to a structured YAML list.

**Before (v0.1.x):**
```yaml
spec:
  inlineRules: |-
    - rule: Terminal shell in container
      desc: A shell was used as the entrypoint into a container.
      condition: spawned_process and container and shell_procs
      output: Shell spawned (user=%user.name container=%container.id)
      priority: NOTICE
      tags: [container, shell]
```

**After (v0.2.0):**
```yaml
spec:
  inlineRules:
    - rule: Terminal shell in container
      desc: A shell was used as the entrypoint into a container.
      condition: spawned_process and container and shell_procs
      output: Shell spawned (user=%user.name container=%container.id)
      priority: NOTICE
      tags: [container, shell]
```

**Migration**: Remove the `|-` (pipe-literal) indicator so that `inlineRules` becomes a direct YAML list.

## Step 5: Update monitoring and scripts

### Condition type names changed

| v0.1.x | v0.2.0 |
|--------|--------|
| `ConditionReconciled` | `Reconciled` |
| `ConditionAvailable` | `Available` |

Update any monitoring queries, alerts, or scripts that filter on `.status.conditions[].type`.

### kubectl get output columns changed

The output of `kubectl get falco`, `kubectl get rulesfiles`, `kubectl get plugins`, and `kubectl get configs` has changed. All CRDs now display status conditions and additional metadata. Update any scripts that parse `kubectl get` output.

### Plugin initConfig type change

The `spec.config.initConfig` field changed from `map[string]string` to arbitrary JSON. Existing flat key-value maps still validate, but values are no longer required to be strings. If your tooling generates Plugin CRs, ensure it handles the new type.

### Falco CRD printcolumns source changed

The `Type` and `Version` columns in `kubectl get falco` now read from `.status.resourceType` and `.status.version` instead of `.spec.type` and `.spec.version`. These are populated by the controller after reconciliation.

After recreating all resources and updating your tooling, verify everything is reconciled:

```bash
kubectl get falco
kubectl get rulesfiles
kubectl get plugins
kubectl get configs
```

## Summary of All Breaking Changes

| # | Change | Severity | CRD Re-apply | CR Update |
|---|--------|----------|:---:|:---:|
| 1 | `ociArtifact.reference` → `ociArtifact.image` + `ociArtifact.registry` | **Critical** | Yes | Yes |
| 2 | `ociArtifact.pullSecret` → `ociArtifact.registry.auth.secretRef` | **Critical** | Yes | Yes |
| 3 | Config `spec.config`: string → structured YAML | **Critical** | Yes | Yes |
| 4 | Rulesfile `spec.inlineRules`: string → structured YAML | **High** | Yes | Yes |
| 5 | Plugin `spec.config.initConfig`: `map[string]string` → JSON | **Medium** | Yes | Maybe |
| 6 | Condition types: `ConditionX` → `X` | **Medium** | Yes | No |
| 7 | Falco shortName: `prom` → `falco` | **Medium** | Yes | No |
| 8 | Falco printcolumns: `spec` → `status` source | **Low** | Yes | No |
| 9 | Artifact CRD printcolumns overhaul | **Low** | Yes | No |
| 10 | RBAC permissions expanded | **Low** | Yes | No |
| 11 | `FalcoSpec.Type`/`Version`: value → pointer, schema defaults removed | **Low** | Yes | No |
