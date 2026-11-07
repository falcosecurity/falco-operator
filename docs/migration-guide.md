# Migration Guide

This page is the index of migration chapters for the Falco Operator. Each chapter documents a specific, self-contained migration path. New chapters are added over time as new migrations become relevant — older chapters are kept for historical reference.

## Chapters

| Chapter | Description |
|---------|-------------|
| [v0.1.x → v0.2.0](migrations/v0.1.x-to-v0.2.0.md) | Upgrade from Falco Operator v0.1.x to v0.2.0 — breaking API changes to `Rulesfile`, `Plugin`, `Config`, and `Falco` CRs, plus new conditions and print columns. |
| [v0.2.x–v0.4.x and release candidates → v0.5.0](migrations/v0.4.x-to-v0.5.0.md) | Upgrade to v0.5.0 from v0.2.x, v0.3.x, v0.4.x or a v0.5.0 release candidate — new artifact delivery through `ArtifactNode`s, compatibility enforcement, Falco pod template changes, and the CRD update. |
| [YAML manifest → Helm](migrations/manifest-to-helm.md) | Move an existing installation from the bundled YAML manifest (`install.yaml`) to the official Helm chart, keeping CRDs and custom resources intact. |

## Upgrade paths

Find the release you run today and follow the chapters in order. Releases not listed as a step have no breaking changes between them.

| From | To v0.5.0 |
|------|-----------|
| v0.1.x | [v0.1.x → v0.2.0](migrations/v0.1.x-to-v0.2.0.md), then [→ v0.5.0](migrations/v0.4.x-to-v0.5.0.md) |
| v0.2.x, v0.3.x, v0.4.x | [→ v0.5.0](migrations/v0.4.x-to-v0.5.0.md) |
| v0.5.0-rc1 to rc4 | [→ v0.5.0](migrations/v0.4.x-to-v0.5.0.md#upgrading-from-a-release-candidate) |

Upgrade directly to the target release: there is no need to install each intermediate release.

## How to pick the right chapter

- **Upgrading across a breaking Falco Operator release?** Read the version-pair chapter for your source/target versions (e.g. `v0.1.x → v0.2.0`).
- **Changing how the operator itself is installed** (e.g. switching from the YAML manifest to the Helm chart)? Read the installation-method chapter.

The two are independent — you can do them at different times. If you need to do both at once, follow the version-pair chapter first (which keeps your existing install method), then the installation-method chapter.

## Related documentation

- [Installation](installation.md) — Install with Helm or YAML manifest, including upgrade and uninstall instructions.
- [Operator releases](https://github.com/falcosecurity/falco-operator/releases): per-release notes for the operator.
- [Chart CHANGELOG](../chart/falco-operator/CHANGELOG.md) — Per-release notes for the Helm chart.
