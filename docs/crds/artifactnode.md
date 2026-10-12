# ArtifactNode CRD Reference

**API Version**: `artifact.falcosecurity.dev/v1alpha1`
**Kind**: `ArtifactNode`

## Description

An `ArtifactNode` records which artifacts (`Rulesfile`, `Plugin`, `Config`) are assigned to one node of a
namespace, and their state on that node. There is one per namespace and node that runs a Falco pod, named after
the node. Users manage the artifacts, not ArtifactNode manifests.

Two writers share the object, each owning one half:

- The instance operator owns the object and its `spec`. It creates the ArtifactNode when a Falco pod runs on the
  node, lists in `spec.artifacts` every artifact of the namespace whose `selector` selects the node, and deletes
  the ArtifactNode once nothing is assigned or reported, or once the node has run no Falco pod for two minutes.
- The Artifact Operator sidecar on that node owns `status`. It installs what the spec lists, removes what the
  spec no longer lists, and reports each artifact's state in `status.artifacts`.

The instance operator aggregates the per-node conditions onto each artifact's own status. Look at the parent
artifact first; the ArtifactNode tells which node reports what.

## Spec

| Field | Type | Description |
|-------|------|-------------|
| `nodeName` | `string` | **Required.** The node the artifacts are assigned to. Immutable. |
| `artifacts` | `[]NodeArtifactRef` | The artifacts assigned to the node, unique by `kind` and `name`. At most 100. |

### NodeArtifactRef

| Field | Type | Description |
|-------|------|-------------|
| `kind` | `string` | `Rulesfile`, `Plugin` or `Config` |
| `name` | `string` | Name of the artifact, in the ArtifactNode's namespace |
| `uid` | `string` | UID of the artifact the assignment was made for; tells a recreated artifact from its predecessor |

When more than 100 artifacts select a node, the ones already assigned keep their place, newcomers fill the
remaining room oldest first, and the rest stay unassigned until there is room. An artifact left out reports
`Programmed=False` with reason `NodeCapacityExceeded`, and the instance operator logs it.

## Status

| Field | Type | Description |
|-------|------|-------------|
| `artifacts` | `[]NodeArtifactStatus` | Per-artifact state on the node, written only by the node's sidecar. At most 100. |

The 100 entries go first to the artifacts the spec no longer lists and the node has yet to remove: their entry
is what keeps the deleted artifact from going while its files are still there. A newly assigned artifact whose
entry does not fit is installed once a removal has made room.

### NodeArtifactStatus

| Field | Type | Description |
|-------|------|-------------|
| `kind`, `name` | `string` | The artifact the entry reports on |
| `uid` | `string` | UID of the artifact the entry reports on; an entry for a previous incarnation is ignored |
| `conditions` | `[]metav1.Condition` | Reference resolution, compatibility, programming and cleanup observations on this node |
| `installedArtifacts` | `[]InstalledArtifact` | Installed files, keyed by source medium (`oci`, `inline`, `configmap`), with path, priority and content hash |
| `installedArtifacts[].specHash` | `string` | OCI spec identity used for the installed file |

`Programmed` summarizes installation. Source-specific conditions are
`OCIArtifactProgrammed`, `InlineArtifactProgrammed` and
`ConfigMapArtifactProgrammed`; plugins also report `ConfigProgrammed`.
`ResolvedRefs` and `DependenciesSatisfied` explain reference or compatibility
blocks. `DeletionBlocked=True` records that installed dependents blocked removal.
A source removed from an artifact's spec whose file could not be deleted reports
`ArtifactRemoveFailed` until the removal succeeds.

Check condition `observedGeneration` against the artifact's current generation,
and the artifact's `status.observedGeneration` for instance-operator processing.
After a rejected update, an older source condition and installed file can remain
while the current generation reports a failure or pending state. The artifact
then shows that source condition as `Unknown` with reason `Pending`, "Waiting for
nodes to report ... for generation N", for as long as the update stays rejected:
its `Programmed=False` condition, not the pending one, says why.

An entry carries no heartbeat. It says what the sidecar last wrote, so a sidecar
that hangs or crash-loops while its pod stays `Running` leaves its last report,
`Programmed=True` included, in place until the artifact's spec changes; the
conditions then become `Pending`, since nothing reports on the new generation.
Check the `artifact-operator` container of the node's Falco pod when a node's
entry stops following its artifacts.

An artifact the spec no longer lists keeps its status entry until the sidecar has
removed its files; the artifact's deletion waits for that.

## Lifecycle and events

- The sidecar holds the `artifactnode.artifact.falcosecurity.dev/sidecar` finalizer, so a deleted ArtifactNode
  still gets its files removed. The instance operator releases it when the node's Falco pod is gone, since the
  pod's `emptyDir` volumes went with it.
- A `BulkRemoval` Warning event on the ArtifactNode means one change dropped 10 or more artifacts from the node,
  more often a selector or label mistake than an intended change. The removal still happens.
- A `MultipleSidecarsOnNode` Warning event means several Falco pods in the namespace run on the node. Their
  sidecars share the one ArtifactNode and overwrite each other's status; run one Falco pod per node and
  namespace.

## Examples

```bash
# One row per node running Falco in the namespace.
kubectl get artifactnodes -n falco

# What is assigned to a node, and what its sidecar reports.
kubectl get artifactnode <node-name> -n falco -o yaml

# Every node's state for one Rulesfile.
kubectl get artifactnodes -n falco -o json | jq '.items[] |
  {node: .spec.nodeName, status: (.status.artifacts[]? | select(.kind == "Rulesfile" and .name == "my-rules"))}'
```

Status describes installation, not proof that Falco accepted a reload. Verify the
files in the Falco container and its loaded rules/plugins when diagnosing a
runtime issue. See [artifact reloads](../configuration.md#artifact-reloads).
