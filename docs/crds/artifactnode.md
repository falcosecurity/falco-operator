# ArtifactNode CRD Reference

**API Version**: `artifact.falcosecurity.dev/v1alpha1`
**Kind**: `ArtifactNode`

The instance operator creates these namespaced resources for nodes matching a
Config, Rulesfile or Plugin selector where Falco pods are running. The Artifact
Operator on each assigned node writes the installation status. Users manage the
parent artifact, not ArtifactNode manifests. The owner reference identifies the
parent, including its UID; `spec.nodeName` is immutable. Labels identify the kind,
parent and node, but long names are hashed; use the owner reference and
`spec.nodeName` for full identities.

## Status

| Field | Meaning |
|-------|---------|
| `conditions` | Per-node reference resolution, compatibility, programming and cleanup observations |
| `installedArtifacts` | Installed files, keyed by source medium (`oci`, `inline`, `configmap`), with path, priority and content hash |
| `installedArtifacts[].specHash` | OCI spec identity used for the installed file |
| `installedArtifacts[].config.path` | Generated plugin configuration path, when applicable |

`Programmed` summarizes installation. Source-specific conditions are
`OCIArtifactProgrammed`, `InlineArtifactProgrammed` and
`ConfigMapArtifactProgrammed`; plugins also report `ConfigProgrammed`.
`ResolvedRefs` and `DependenciesSatisfied` explain reference or compatibility
blocks. `DeletionBlocked=True` records that installed dependents blocked removal.
It can remain present if a later cleanup step fails after those dependents are removed.

The instance operator aggregates these conditions onto the parent artifact.
Check condition `observedGeneration` against the parent's current generation,
and the parent's `status.observedGeneration` for instance-operator processing.
After a rejected update, an older source condition and installed file can remain
while the current generation reports a failure or pending state.

```bash
kubectl get artifactnodes -n falco
kubectl describe artifactnode <name> -n falco
```

Status describes installation, not proof that Falco accepted a reload. Verify the
files in the Falco container and its loaded rules/plugins when diagnosing a
runtime issue. See [artifact reloads](../configuration.md#artifact-reloads).
