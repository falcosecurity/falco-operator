# Version Matrix

This page tracks the **default Falco version** the operator installs for each Falco Operator release.

When a `Falco` resource does not pin a version (via `spec.version` or an explicit image in `spec.podTemplateSpec`), the operator deploys the default Falco version listed below. The default is defined by `FalcoTag` in [`internal/pkg/image/const.go`](../internal/pkg/image/const.go).

Each row marks the operator version that introduced a given default; `+` means that default applies from that version onward, until the next row.

| Falco Operator | Default Falco |
|----------------|---------------|
| v0.0.1+        | 0.41.0        |
| v0.2.0+        | 0.43.0        |
| v0.3.0+        | 0.44.0        |
| v0.3.1+        | 0.44.1        |

> The operator version is the released operator image tag (which matches the Helm chart `appVersion`). You can always override the Falco version per instance — see [Configuration](configuration.md) and the [Falco CRD reference](crds/falco.md).

## For maintainers

When changing the default Falco version, update `FalcoTag` in `internal/pkg/image/const.go` and add a row to the table above using the operator version that will ship the change. The table must be updated in the same PR, before the release tag is pushed.
