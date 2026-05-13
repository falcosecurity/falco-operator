# Migration Guide

This page is the index of migration chapters for the Falco Operator. Each chapter documents a specific, self-contained migration path. New chapters are added over time as new migrations become relevant — older chapters are kept for historical reference.

## Chapters

| Chapter | Description |
|---------|-------------|
| [v0.1.x → v0.2.0](migrations/v0.1.x-to-v0.2.0.md) | Upgrade from Falco Operator v0.1.x to v0.2.0 — breaking API changes to `Rulesfile`, `Plugin`, `Config`, and `Falco` CRs, plus new conditions and print columns. |
| [YAML manifest → Helm](migrations/manifest-to-helm.md) | Move an existing installation from the bundled YAML manifest (`install.yaml`) to the official Helm chart, keeping CRDs and custom resources intact. |

## How to pick the right chapter

- **Upgrading across a breaking Falco Operator release?** Read the version-pair chapter for your source/target versions (e.g. `v0.1.x → v0.2.0`).
- **Changing how the operator itself is installed** (e.g. switching from the YAML manifest to the Helm chart)? Read the installation-method chapter.

The two are independent — you can do them at different times. If you need to do both at once, follow the version-pair chapter first (which keeps your existing install method), then the installation-method chapter.

## Related documentation

- [Installation](installation.md) — Install with Helm or YAML manifest, including upgrade and uninstall instructions.
- [CHANGELOG](../CHANGELOG.md) — Per-release notes for the operator.
- [Chart CHANGELOG](../chart/falco-operator/CHANGELOG.md) — Per-release notes for the Helm chart.
