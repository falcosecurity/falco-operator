# Contributing

Thank you for your interest in contributing to the Falco Operator! This guide covers the development workflow, testing, and PR guidelines.

## Prerequisites

- **Go 1.26+**
- **Docker** (for building container images)
- **kubectl** (for interacting with test clusters)
- **Kind** (for local e2e testing)
- **Make** (build automation)

## Development Setup

Clone the repository:

```bash
git clone https://github.com/falcosecurity/falco-operator.git
cd falco-operator
```

Install development tools:

```bash
make controller-gen envtest golangci-lint
```

## Project Structure

```
falco-operator/
├── api/                          # CRD type definitions
│   ├── artifact/v1alpha1/        # Rulesfile, Plugin, Config types
│   ├── common/v1alpha1/          # Shared types (OCIArtifact, conditions)
│   └── instance/v1alpha1/        # Falco, Component types
├── cmd/
│   ├── instance/                 # Instance Operator entrypoint (Falco + Component controllers)
│   └── artifact/                 # Artifact Operator entrypoint (Rulesfile + Plugin + Config controllers)
├── controllers/
│   ├── instance/                 # Instance controllers
│   │   ├── falco/                # Falco reconciler
│   │   ├── component/            # Component reconciler
│   │   └── reference/            # Secret/ConfigMap finalizer controllers
│   └── artifact/                 # Artifact controllers
│       ├── rulesfile/            # Rulesfile reconciler
│       ├── plugin/               # Plugin reconciler
│       └── config/               # Config reconciler
├── internal/pkg/                 # Shared internal packages
│   ├── artifact/                 # OCI registry defaults, artifact utilities
│   ├── builders/                 # Fluent builders for K8s resources
│   ├── common/                   # Archive, conditions, finalizer, JSON, sidecar helpers
│   ├── controllerhelper/         # Shared controller helpers (diff, deletion, finalizer, status)
│   ├── credentials/              # Credential resolution
│   ├── filesystem/               # Filesystem abstraction (interfaces, mock, OS)
│   ├── image/                    # Container image constants and helpers
│   ├── index/                    # Declarative index registry (config, plugin, rulesfile)
│   ├── instance/                 # Shared instance reconciliation logic
│   ├── managedfields/            # Managed fields comparison for SSA
│   ├── mounts/                   # Volume mount helpers
│   ├── oci/                      # OCI client and puller
│   ├── priority/                 # Priority ordering
│   ├── resources/                # Pod/container generation, defaults, overlays
│   ├── scheme/                   # Kubernetes scheme setup
│   └── version/                  # Version info (injected via ldflags)
├── chart/
│   └── falco-operator/           # Helm chart (CRDs, templates, values)
├── examples/                     # Example CRs and quickstart manifest
├── dist/                         # Generated install.yaml (build output)
├── build/
│   └── Dockerfile                # Shared Dockerfile for both operator binaries
├── .goreleaser.yml               # Release configuration
├── docs/                         # Documentation
├── test/
│   └── e2e/                      # End-to-end tests
├── hack/                         # Helper scripts
├── CHANGELOG.md
├── Makefile
└── go.mod / go.sum
```

## Build

Build both binaries:

```bash
make build
```

This produces:
- `bin/instance-operator` — The Instance Operator (manages Falco and Component CRs)
- `bin/artifact-operator` — The Artifact Operator (manages Rulesfile, Plugin, Config CRs)

Build container images:

```bash
# Build the instance operator image
make docker-build IMG=falcosecurity/falco-operator:dev

# Build the artifact operator image
OPERATOR=artifact make docker-build IMG=falcosecurity/artifact-operator:dev
```

> **Note on build dependency**: The instance operator embeds the artifact operator image reference at compile time via ldflags (`version.ArtifactOperatorImage`). In CI, the artifact operator image is built and pushed first, and its tag is injected into the instance operator build. For local development, the default `docker.io/falcosecurity/artifact-operator:latest` is used.

### Generating the install manifest

```bash
make build-installer IMG=falcosecurity/falco-operator:dev
```

This generates `dist/install.yaml` via `helm template`, aggregating CRDs, RBAC, and the operator Deployment.

### Helm chart publishing and versioning

The Helm chart source lives in [`../chart/falco-operator/`](../chart/falco-operator/). This repository is the source of truth for the chart content and release metadata, including [`../chart/falco-operator/Chart.yaml`](../chart/falco-operator/Chart.yaml), [`../chart/falco-operator/CHANGELOG.md`](../chart/falco-operator/CHANGELOG.md), [`../chart/falco-operator/README.gotmpl`](../chart/falco-operator/README.gotmpl), and the generated [`../chart/falco-operator/README.md`](../chart/falco-operator/README.md).

Published Falco Helm charts live in the [`falcosecurity/charts`](https://github.com/falcosecurity/charts) repository, so the Falco Operator chart is published by syncing this source chart into `falcosecurity/charts/charts/falco-operator` and merging a chart-release PR there.

PRs that change chart templates, values, CRDs, RBAC, or the operator application version rendered by the chart must update the chart release metadata in this repository before they are synced to `falcosecurity/charts`.

Use SemVer for `Chart.yaml` `version`: major for breaking changes to chart values, rendered resources, or upgrade behavior; minor for backward-compatible chart features; patch for backward-compatible fixes or metadata changes. Set `Chart.yaml` `appVersion` to the Falco Operator application version rendered by the chart.

Run `make chart-docs` after changing chart values or chart documentation, and update [`../chart/falco-operator/CHANGELOG.md`](../chart/falco-operator/CHANGELOG.md) when preparing a chart release.

Chart releases are authored as **release PRs in this source repository**: a release PR bumps [`../chart/falco-operator/Chart.yaml`](../chart/falco-operator/Chart.yaml), updates [`../chart/falco-operator/CHANGELOG.md`](../chart/falco-operator/CHANGELOG.md), and carries the `/kind chart-release` label. Normal chart changes and version bumps must not be authored directly in `falcosecurity/charts`.

The cross-repository sync to `falcosecurity/charts` belongs to Falco infrastructure, not to this repository. A Prow job in [`falcosecurity/test-infra`](https://github.com/falcosecurity/test-infra), running as the Falco project automation bot, opens or updates the corresponding sync PR (titled `sync(charts/falco-operator): v<version>`) in `falcosecurity/charts` when [`../chart/falco-operator/`](../chart/falco-operator/) changes. That sync PR is the publication gate: merging it on `falcosecurity/charts` publishes the chart.

## Code Generation

After modifying API types (`api/` directory), regenerate manifests:

```bash
make manifests generate
```

This updates:
- CRD YAMLs in `chart/falco-operator/crds/`
- `zz_generated.deepcopy.go` files
- RBAC rules in `chart/falco-operator/files/ClusterRole.yaml`

## Testing

### Unit tests

```bash
make test
```

Uses kubebuilder's `envtest` for integration testing against an in-memory API server.

### E2E tests

> **Note**: E2e tests are currently being migrated to [Chainsaw](https://kyverno.github.io/chainsaw/). The new test suite is under active development and not yet available on `main`. The existing Ginkgo-based e2e tests provide basic operator startup verification.

E2E tests require a running Kubernetes cluster (Kind recommended):

```bash
# Create a Kind cluster
kind create cluster

# Run e2e tests
make test-e2e
```

### Linting

```bash
make lint
```

Fix lint issues automatically:

```bash
make lint-fix
```

## Pull Request Guidelines

### Branch naming

- `feat/<description>` — New features
- `fix/<description>` — Bug fixes
- `docs/<description>` — Documentation changes
- `refactor/<description>` — Code refactoring
- `test/<description>` — Test changes

### Commit messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(api): add new field to Config CRD
fix(plugin): handle nil initConfig gracefully
docs: update migration guide
refactor(controller): extract shared helper
test(e2e): add Config lifecycle test
```

Use `!` after the type for breaking changes:

```
feat(api)!: rename field in Rulesfile spec
```

### PR template

When opening a PR, fill in the template:

1. **Kind label** (required): `/kind feature`, `/kind bug`, `/kind cleanup`, `/kind documentation`, `/kind failing-test`, `/kind design`, `/kind chart-release`
2. **Area label** (required): `/area instance-operator`, `/area artifact-operator`, `/area chart`, `/area pkg`, `/area api`, `/area docs`
3. **Description**: What the PR does and why
4. **Linked issues**: `Fixes #<number>` or `Relates to #<number>`


### Review process

PRs require approval from at least one [OWNERS](../OWNERS) approver

## Deploying for Development

Deploy the operator to a local cluster for testing:

```bash
# Install CRDs
make install

# Run the operator locally (outside the cluster)
make run

# Or deploy to the cluster
make deploy IMG=falcosecurity/falco-operator:dev
```

> `make deploy` and `make undeploy` use the local Helm chart in [`chart/falco-operator/`](../chart/falco-operator/) under the hood (via `helm upgrade --install` and `helm uninstall`). This is the same chart that gets published to `falcosecurity/charts` — see [Helm chart publishing and versioning](#helm-chart-publishing-and-versioning).

Clean up:

```bash
make undeploy
make uninstall
```
