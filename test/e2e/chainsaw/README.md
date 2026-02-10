# Chainsaw E2E Tests

This directory contains end-to-end tests for the Falco Operator using [Chainsaw](https://kyverno.github.io/chainsaw/) (Kyverno's declarative Kubernetes testing framework).

## Running Tests

### Prerequisites

- A running Kubernetes cluster (Kind recommended)
- The operator deployed to the cluster
- [Chainsaw](https://kyverno.github.io/chainsaw/) installed

### Quick Start (Full Lifecycle)

```bash
# Setup + test + teardown in one command
make test-e2e-all
```

### Step-by-Step

```bash
# 1. Setup: build images, deploy operator to Kind cluster
make test-e2e-setup

# 2. Run all e2e tests
make test-e2e

# 3. Run a specific test suite
make test-e2e CHAINSAW_TEST_DIR=./test/e2e/chainsaw/falco/lifecycle

# 4. Teardown: undeploy operator
make test-e2e-teardown
```

### Makefile Targets

| Target | Description |
|--------|-------------|
| `test-e2e-setup` | Build images, load into Kind, install CRDs, deploy operator |
| `test-e2e` | Run chainsaw e2e tests (requires running cluster with operator) |
| `test-e2e-teardown` | Undeploy operator |
| `test-e2e-all` | Full lifecycle: setup, test, teardown |

## Global Configuration

The [.chainsaw.yaml](.chainsaw.yaml) file centralizes default timeouts and settings for all tests. Individual tests inherit these defaults unless they override them.

```yaml
spec:
  timeouts:
    apply: 30s      # Time to apply resources
    assert: 5m      # Time for assertions to succeed (retries until timeout)
    cleanup: 2m     # Time for cleanup operations
    delete: 30s     # Time for deletion operations
    error: 30s      # Time before error timeout
    exec: 3m        # Time for script execution
  parallel: 10      # Run 10 tests in parallel
  failFast: false   # Continue running tests even if one fails
  fullName: true    # Use full test names in output
```

When adjusting timeouts, prefer updating the global configuration over setting per-test or per-step overrides. This keeps behavior consistent and easy to reason about.

## Directory Structure

```
test/e2e/chainsaw/
├── .chainsaw.yaml                          # Global config
├── README.md                               # This file
├── TEST_MATRIX.md                          # Full test matrix and coverage tracking
├── common/
│   ├── _step_templates/                    # Reusable step templates (12)
│   │   ├── apply-assert-falco-daemonset.yaml
│   │   ├── apply-assert-falco-deployment.yaml
│   │   ├── assert-falco-status.yaml
│   │   ├── verify-content-update.yaml
│   │   ├── verify-dir-listing.yaml
│   │   ├── verify-file-contains.yaml
│   │   ├── verify-file-deleted.yaml
│   │   ├── verify-file-rename.yaml
│   │   ├── verify-file-size.yaml
│   │   ├── verify-plugin-config.yaml
│   │   ├── verify-plugin.yaml
│   │   └── wait-falco-pod-ready.yaml
│   └── scripts/                            # Standalone verification scripts (10)
│       ├── common.sh                       # Shared utility functions (pod lookup, exec, retry)
│       ├── debug_artifact.sh               # Diagnostic dump on test failure
│       ├── verify_content_update.sh
│       ├── verify_dir_listing.sh
│       ├── verify_file_contains.sh
│       ├── verify_file_deleted.sh
│       ├── verify_file_rename.sh
│       ├── verify_file_size.sh
│       ├── verify_plugin_config.sh
│       └── wait_for_plugin.sh
├── falco/                                  # Falco CRD tests
│   ├── lifecycle/                          # DaemonSet CRUD, idempotent, type-switch, delete
│   ├── deployment/                         # Deployment CRUD, status, scale
│   ├── podtemplate/                        # Custom PodTemplateSpec
│   └── version/                            # Version upgrade, image override
├── config/
│   └── lifecycle/                          # Inline CRUD, priority, selector, boundary tests
├── rulesfile/
│   ├── lifecycle/                          # All sources, priority, selector, multi-source, delete
│   └── edge-cases/                         # Missing ConfigMap handling
├── plugin/
│   └── lifecycle/                          # OCI create, multiple, update, selector, delete
├── integration/
│   └── full-stack/                         # Falco + Config + Rulesfile + Plugin + type switch
└── validation/                             # CRD validation (invalid type, priority bounds)
```

**10 test suites** running in parallel via `make test-e2e`.

## Best Practices

### 1. Use Step Templates for Reusable Operations

Step templates in `common/_step_templates/` encapsulate common operations shared across tests. Always prefer using an existing template over duplicating YAML.

**Using a template:**
```yaml
- name: Create Falco instance
  use:
    template: ../../common/_step_templates/apply-assert-falco-daemonset.yaml
```

**Overriding bindings when needed:**
```yaml
- name: Verify config file
  use:
    template: ../../common/_step_templates/verify-file-contains.yaml
  bindings:
    - name: file_path
      value: "/etc/falco/config.d/50-config-test.yaml"
    - name: expected_content
      value: "json_output"
```

### 2. Define Test-Wide Bindings

Define shared values at the top of the test spec to avoid repetition:

```yaml
spec:
  bindings:
    - name: falco_name
      value: falco-test
    - name: falco_version
      value: "0.43.0"
```

Step-level bindings override test-level bindings when templates need different values.

### 3. Script Conventions

Scripts in `common/scripts/` follow these conventions:

**Standalone**: Every script is self-contained and runnable from the command line. All inputs come from environment variables:

```bash
NAMESPACE=default \
FILE_PATH=/etc/falco/config.d/50-config-test.yaml \
EXPECTED_CONTENT=json_output \
bash common/scripts/verify_file_contains.sh
```

All environment variables are documented in a header comment at the top of each script.

**Safety flags**: Every script starts with `set -o errexit`, `set -o nounset`, `set -o pipefail`.

**Structured output**: Scripts output JSON on failure for debugging:
```json
{
  "error": "Pattern not found in file",
  "file_path": "/etc/falco/config.d/50-config-test.yaml",
  "pattern": "json_output"
}
```

**Modular**: Scripts source `common.sh` for shared utility functions. Each script does one thing:
- `verify_file_contains.sh` — Verify file exists and contains a pattern
- `verify_content_update.sh` — Verify file content was updated (new present, old absent)
- `verify_file_size.sh` — Verify file has minimum size (OCI artifacts)
- `verify_file_rename.sh` — Verify file was renamed (priority changes)
- `verify_file_deleted.sh` — Verify file was removed
- `verify_dir_listing.sh` — Verify directory contains expected files
- `verify_plugin_config.sh` — Verify plugin entry in config
- `wait_for_plugin.sh` — Wait for plugin .so download
- `debug_artifact.sh` — Diagnostic dump on failure (pod status, logs, events)

### 4. Adding New Tests

1. Create a new directory under the appropriate CRD category
2. Create a `chainsaw-test.yaml` with test-level bindings
3. Reuse existing step templates where possible
4. For test-specific resources, create separate YAML files in the test directory
5. If a new common pattern emerges, extract it into a step template

## Test Coverage


| Suite | CRD | Scenarios |
|-------|-----|-----------|
| `falco/lifecycle` | Falco | DaemonSet create, status, idempotent, type-switch, delete |
| `falco/deployment` | Falco | Deployment create, status, scale |
| `falco/version` | Falco | Version upgrade, image override |
| `falco/podtemplate` | Falco | Custom labels, tolerations, resources |
| `config/lifecycle` | Config | Inline CRUD, priority rename, selector, boundary, delete |
| `rulesfile/lifecycle` | Rulesfile | Inline, OCI, ConfigMap, multi-source, selector, delete |
| `rulesfile/edge-cases` | Rulesfile | Missing ConfigMap handling |
| `plugin/lifecycle` | Plugin | OCI create, multiple, update, selector, delete |
| `integration/full-stack` | All | Full stack + DaemonSet to Deployment type switch |
| `validation` | All | CRD validation rejection |

## Chainsaw Gotchas

### Unbound Variables

Chainsaw expressions like `($myvar)` fail if `myvar` is not bound. Always explicitly bind every variable used in expressions at either the test or step level.

### Script Runs Once, Assert Retries

In a step with a `script:` followed by an `assert:`, the script executes once and its output is captured. The `assert:` block retries independently. Structure scripts to handle retries internally when needed.

### Relative Paths in Templates

Script paths in templates use paths relative to the **test directory**, not the template directory. Templates in `common/_step_templates/` reference scripts as `../../common/scripts/foo.sh`, which resolves correctly when used from a test two levels deep (e.g., `falco/lifecycle/`).
