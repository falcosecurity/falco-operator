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

Download the repository-local CLI tools:

```bash
make tools
```

Go tools such as controller-gen, setup-envtest and golangci-lint are pinned in
`go.mod`; Make invokes them through `go tool` without separate install targets.

## Project Structure

```
falco-operator/
├── api/                          # CRD type definitions
│   ├── artifact/v1alpha1/        # Rulesfile, Plugin, Config, ArtifactNode types
│   ├── common/v1alpha1/          # Shared types (OCIArtifact, conditions)
│   └── instance/v1alpha1/        # Falco, Component types
├── cmd/
│   ├── instance/                 # Instance Operator entrypoint (Falco + Component controllers)
│   └── artifact/                 # Artifact Operator entrypoint (Rulesfile + Plugin + Config controllers)
├── controllers/
│   ├── instance/                 # Instance controllers
│   │   ├── falco/                # Falco reconciler
│   │   ├── component/            # Component reconciler
│   │   ├── artifact/             # Parent metadata, cache and status aggregators
│   │   └── reference/            # Secret/ConfigMap finalizer controllers
│   └── artifact/                 # Artifact controllers
│       ├── rulesfile/            # Rulesfile reconciler
│       ├── plugin/               # Plugin reconciler
│       └── config/               # Config reconciler
├── internal/pkg/                 # Shared internal packages
│   ├── artifact/                 # OCI registry defaults, artifact utilities
│   ├── artifactcache/            # Central OCI blob cache and ownership index
│   ├── artifactserver/           # HTTP(S) delivery and mTLS authorization
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
│   ├── nodeartifacts/            # Installed files, dependencies and Falco reloads
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
├── Makefile
└── go.mod / go.sum
```

## Build

Build both binaries:

```bash
make build
```

This produces:

- `bin/instance-operator` — The Instance Operator (workloads, parent artifacts and central server)
- `bin/artifact-operator` — The Artifact Operator (manages Rulesfile, Plugin, Config CRs)

Build container images:

```bash
export IMG_INSTANCE=falco-operator:dev
export IMG_ARTIFACT=artifact-operator:dev
make docker.build.instance docker.build.artifact
```

The instance build embeds `IMG_ARTIFACT` through `version.ArtifactOperatorImage`.
Keep this reference aligned with the artifact image you build and load. The
lower-level `docker.build` target uses `OPERATOR` and `IMG`; the paired targets
above set these for you.

### Generating the install manifest

```bash
make installer.build IMG="$IMG_INSTANCE"
```

This generates `dist/install.yaml` via `helm template`, aggregating CRDs, RBAC,
the operator Deployment and artifact Service.

### Helm chart publishing and versioning

The Helm chart source lives in [`../chart/falco-operator/`](../chart/falco-operator/). Published Falco Helm charts live in [`falcosecurity/charts`](https://github.com/falcosecurity/charts), and Falco infrastructure syncs this chart there only when the chart version is bumped.

Open Falco Operator chart issues and PRs in this repository; `falcosecurity/charts` receives the generated sync PR.

- Regular chart PRs: do not bump [`../chart/falco-operator/Chart.yaml`](../chart/falco-operator/Chart.yaml); add the change under `## Unreleased` in [`../chart/falco-operator/CHANGELOG.md`](../chart/falco-operator/CHANGELOG.md).
- Chart release PRs: use `/kind chart-release`, bump [`../chart/falco-operator/Chart.yaml`](../chart/falco-operator/Chart.yaml), and move the selected `## Unreleased` entries into the new version section. Entries not included in that release can stay under `## Unreleased`.

Use SemVer for `Chart.yaml` `version`: major for breaking changes, minor for backward-compatible chart features, patch for fixes or metadata changes. Set `appVersion` to the Falco Operator version rendered by the chart when preparing a chart release.

Run `make chart.docs` after changing chart values or chart documentation. Normal chart changes and version bumps must not be authored directly in `falcosecurity/charts`.

Before publishing a chart, verify its `appVersion` and rendered image against the
release's matching operator pair, CRDs, RBAC and artifact Service. A chart install
using an older default image does not validate current-source artifact delivery.

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

Uses kubebuilder's `envtest` to run a local API server and etcd for integration tests.

### E2E tests

Chainsaw tests require a test cluster with the operator, KWOK and OCI fixtures
installed. Use an absolute `KUBECONFIG` path so standalone scripts can find it
when Chainsaw runs them from each test directory.

On a dedicated local Kind cluster, build and load both images, deploy the operator,
and populate the registry fixtures:

```bash
export CLUSTER_PROVIDER=kind
make cluster.up WITH_TELEPRESENCE=false
make cluster.load
make deploy.http
make registry.setup
```

`cluster.up` also installs KWOK and the configured PKI test dependencies. For mTLS
coverage, use `make deploy.mtls` instead. These targets configure shared PKI
controllers for the test namespace; do not run them against a production cluster.

```bash
make test.chainsaw
```

The HA test temporarily changes the installed operator Deployment and restarts its
manager container. It is excluded by default. Run it only on a dedicated,
single-replica test installation, with no concurrent changes to that Deployment:

```bash
CHAINSAW_ENABLE_HA_TEST=true make test.chainsaw \
  CHAINSAW_ARGS='--selector test.falcosecurity.dev/disruptive=true'
```

It restores the original Deployment spec on cleanup, refusing to overwrite
concurrent changes. CI enables this test for the instance-operator category in
both HTTP and mTLS modes.

### Linting

```bash
make lint
```

Fix lint issues automatically:

```bash
make lint.fix
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

# Run locally with an artifact server URL reachable from Falco pods
ARTIFACT_SERVER_URL="http://<operator-host>:8082" make run

# Or build/load both images and deploy to the local cluster
make cluster.load IMG_INSTANCE=falco-operator:dev IMG_ARTIFACT=artifact-operator:dev
make deploy.http IMG_INSTANCE=falco-operator:dev IMG_ARTIFACT=artifact-operator:dev
```

The central artifact server is required. Helm configures its in-cluster URL
automatically; local runs must advertise a host and port reachable from the pods.

`make deploy.http`, `make deploy.mtls` and `make undeploy` use the local Helm chart
in [`chart/falco-operator/`](../chart/falco-operator/), via `helm upgrade --install`
and `helm uninstall`. See [Helm chart publishing and versioning](#helm-chart-publishing-and-versioning).

Clean up:

```bash
make undeploy
make uninstall
```
