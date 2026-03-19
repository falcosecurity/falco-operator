# Change Log

## v0.2.0

Released on YYYY-MM-DD

### Major Changes

* **Component controller**: New `Component` CRD (`instance.falcosecurity.dev/v1alpha1`) for deploying companion components such as [k8s-metacollector](https://github.com/falcosecurity/k8s-metacollector). The instance operator was reorganized around shared reconciliation logic and fluent builders. [[`8f94eb8`](https://github.com/falcosecurity/falco-operator/commit/8f94eb8)]
* **Ecosystem component types**: Added `falcosidekick` and `falcosidekick-ui` component types to the `Component` CRD with production-ready defaults. The UI includes a `wait-redis` init container that blocks until Redis is reachable. [[`6d9ee6a`](https://github.com/falcosecurity/falco-operator/commit/6d9ee6a)]
* **Falco defaults alignment with Helm chart**: Added startup probe, complete CRI socket paths (including GKE `host-containerd`), `suggested_output`, `plugins_hostinfo`, `json_include_output_fields_property`, and `falco_libs` auto-purging settings. [[`6d9ee6a`](https://github.com/falcosecurity/falco-operator/commit/6d9ee6a)]
* **Redesigned OCI artifact API** (**BREAKING**): The `ociArtifact` structure now uses `image` (with `repository` and `tag`) and `registry` (with `name`, `auth`, `tls`, `plainHTTP`) instead of the flat `reference` and `pullSecret` model. See the [migration guide](docs/migration-guide.md). [[`4ce7025`](https://github.com/falcosecurity/falco-operator/commit/4ce7025)]
* **ConfigMap support for rules and configuration**: `Rulesfile` and `Config` CRs can now reference Kubernetes ConfigMaps as data sources, alongside OCI artifacts and inline definitions. [[`70e804e`](https://github.com/falcosecurity/falco-operator/commit/70e804e), [`c12f37f`](https://github.com/falcosecurity/falco-operator/commit/c12f37f)]
* **Structured API types** (**BREAKING**): `Rulesfile.spec.inlineRules` and `Config.spec.config` are now structured YAML objects instead of plain strings. [[`1d48604`](https://github.com/falcosecurity/falco-operator/commit/1d48604), [`c12f37f`](https://github.com/falcosecurity/falco-operator/commit/c12f37f)]
* **Reference tracking with finalizers**: Secrets and ConfigMaps referenced by artifact CRs are protected from accidental deletion via finalizers (`artifact.falcosecurity.dev/secret-in-use`, `artifact.falcosecurity.dev/configmap-in-use`). [[`1263a5d`](https://github.com/falcosecurity/falco-operator/commit/1263a5d), [`04614c5`](https://github.com/falcosecurity/falco-operator/commit/04614c5)]
* **Enhanced observability**: All controllers now emit Kubernetes events for artifact operations. Status conditions follow Kubernetes conventions (`Programmed`, `ResolvedRefs`, `Reconciled`, `Available`). All artifact CRDs include `printcolumns` for readable `kubectl get` output. [[`e381f3c`](https://github.com/falcosecurity/falco-operator/commit/e381f3c), [`8676f84`](https://github.com/falcosecurity/falco-operator/commit/8676f84), [`6b47ecc`](https://github.com/falcosecurity/falco-operator/commit/6b47ecc), [`b5729b1`](https://github.com/falcosecurity/falco-operator/commit/b5729b1)]
* **Update strategy support**: The `Falco` CRD now accepts `updateStrategy` (DaemonSet) and `strategy` (Deployment) fields for rolling update configuration. [[`2875112`](https://github.com/falcosecurity/falco-operator/commit/2875112)]


### Minor Changes

* **Server-Side Apply migration**: Reconciliation logic moved from dry-run/update to SSA, with managed fields comparison to prevent spurious updates. [[`98f279f`](https://github.com/falcosecurity/falco-operator/commit/98f279f), [`6f99d67`](https://github.com/falcosecurity/falco-operator/commit/6f99d67), [`630641e`](https://github.com/falcosecurity/falco-operator/commit/630641e)]
* **Conditions consolidation**: Artifact conditions consolidated into `Programmed` and `ResolvedRefs`; condition type values simplified (e.g., `ConditionReconciled` → `Reconciled`). [[`3741cf8`](https://github.com/falcosecurity/falco-operator/commit/3741cf8), [`6758acb`](https://github.com/falcosecurity/falco-operator/commit/6758acb)]
* Go version bumped to 1.26; linters updated. [[`f0a5e8d`](https://github.com/falcosecurity/falco-operator/commit/f0a5e8d)]
* Alessandro Cannarella (c2ndev) added to OWNERS as approver. [[`1a6e628`](https://github.com/falcosecurity/falco-operator/commit/1a6e628)]


### Bug Fixes

* Plugin `initConfig` changed to `apiextensionsv1.JSON` to support nested configuration objects. [[`9d37b3d`](https://github.com/falcosecurity/falco-operator/commit/9d37b3d)]
* Fixed consistent name handling in Plugin controller `addConfig`/`removeConfig`. [[`2a2a4bd`](https://github.com/falcosecurity/falco-operator/commit/2a2a4bd)]
* Added RBAC `patch` verb for artifacts; fixed Kubernetes 1.32+ schema compatibility. [[`7c7962e`](https://github.com/falcosecurity/falco-operator/commit/7c7962e)]
* Fixed ConfigMap indexer and restored artifact constants. [[`6936c53`](https://github.com/falcosecurity/falco-operator/commit/6936c53)]
* Added ConfigMap watch permission to artifact operator. [[`ff5217c`](https://github.com/falcosecurity/falco-operator/commit/ff5217c)]
* Fixed SSA strategy switch to `Recreate`/`OnDelete` failing due to K8s-defaulted `rollingUpdate` not being owned by the field manager.
* Fixed invalid user input on SSA apply causing `ERROR` stack traces and infinite requeue instead of setting condition and stopping.
* Fixed diff error handling in controllers. [[`5fce1c9`](https://github.com/falcosecurity/falco-operator/commit/5fce1c9)]
* Prevented spurious updates via managed fields comparison. [[`49921ce`](https://github.com/falcosecurity/falco-operator/commit/49921ce)]
* Fixed RBAC permissions for event recording. [[`a31f127`](https://github.com/falcosecurity/falco-operator/commit/a31f127)]
* Added node name to recorders for artifact controllers. [[`8326402`](https://github.com/falcosecurity/falco-operator/commit/8326402)]
* Updated CI workflows for renamed `cmd/instance` entrypoint. [[`8f0e33c`](https://github.com/falcosecurity/falco-operator/commit/8f0e33c)]


### Non user-facing changes

* Test improvements: SSA diff checks, integration tests, Secret/ConfigMap reference edge cases, artifact controller rewrites. [[`d7070bd`](https://github.com/falcosecurity/falco-operator/commit/d7070bd), [`09f8900`](https://github.com/falcosecurity/falco-operator/commit/09f8900), [`242d62b`](https://github.com/falcosecurity/falco-operator/commit/242d62b), [`1f84076`](https://github.com/falcosecurity/falco-operator/commit/1f84076)]
* Added Rulesfile and Config sample manifests. [[`f7c44f7`](https://github.com/falcosecurity/falco-operator/commit/f7c44f7), [`ef3a767`](https://github.com/falcosecurity/falco-operator/commit/ef3a767)]
* Renamed ConfigMapRef condition to `ResolvedRef`. [[`9251e77`](https://github.com/falcosecurity/falco-operator/commit/9251e77)]
* 18 dependency bumps (GitHub Actions, controller-runtime, OpenTelemetry, GoReleaser, Ginkgo/Gomega, and others).


### Statistics

|   MERGED PRS    | NUMBER |
|-----------------|--------|
| Not user-facing |     25 |
| Release note    |     33 |
| Total           |     58 |

## v0.1.1

Released on 2026-01-30


### Bug Fixes

* build(deps): bump `sigs.k8s.io/controller-runtime` from 0.22.4 to 0.23.0 - [@dependabot[bot]](https://github.com/apps/dependabot)


## v0.1.0

Released on 2025-05-30


### Major Changes

* Initial release of the Falco Operator
* Falco Operator controller for managing Falco instances (DaemonSet and Deployment modes)
* Artifact Operator sidecar for managing rules, plugins, and configurations
* Custom Resource Definitions: `Falco`, `Rulesfile`, `Plugin`, `Config`
* OCI artifact support for rules and plugins
* Label-based node selection for artifacts
* Priority system for deterministic artifact ordering
* Default configuration with `modern_ebpf` engine for DaemonSet mode and `nodriver` for Deployment mode
* Single-manifest installation via `install.yaml`
