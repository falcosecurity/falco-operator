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
make test-e2e CHAINSAW_TEST_DIR=./test/e2e/chainsaw/falco-daemonset

# 4. Teardown: undeploy operator
make test-e2e-teardown
```

### Makefile Targets

| Target | Description |
|--------|-------------|
| `test-e2e-setup` | Build images, load into Kind, install CRDs, deploy operator |
| `test-e2e` | Run chainsaw e2e tests (requires running cluster with operator) |
| `test-e2e-teardown` | Undeploy operator |
| `test-e2e-all` | Full lifecycle: setup → test → teardown |

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
  parallel: 6       # Run 6 tests in parallel
  failFast: false   # Continue running tests even if one fails
  fullName: true    # Use full test names in output
```

When adjusting timeouts, prefer updating the global configuration over setting per-test or per-step overrides. This keeps behavior consistent and easy to reason about.

## Directory Structure

```
test/e2e/chainsaw/
├── .chainsaw.yaml                          # Global config
├── README.md                               # This file
├── common/
│   ├── _step_templates/                    # Reusable step templates
│   │   ├── apply-assert-falco-daemonset.yaml
│   │   ├── apply-assert-falco-deployment.yaml
│   │   ├── wait-falco-pod-ready.yaml
│   │   ├── verify-file-contains.yaml
│   │   ├── verify-content-update.yaml
│   │   ├── verify-file-size.yaml
│   │   ├── verify-file-rename.yaml
│   │   └── verify-plugin.yaml
│   └── scripts/                            # Standalone verification scripts
│       ├── common.sh
│       ├── debug_artifact.sh
│       ├── verify_file_contains.sh
│       ├── verify_content_update.sh
│       ├── verify_file_size.sh
│       ├── verify_file_rename.sh
│       └── wait_for_plugin.sh
├── falco-daemonset/                        # Falco DaemonSet deployment test
├── falco-deployment/                       # Falco Deployment test
├── config-inline/                          # Config with inline content
├── rulesfile-inline/                       # Rulesfile with inline rules
├── rulesfile-oci/                          # Rulesfile from OCI registry
└── plugin-oci/                             # Plugin from OCI registry
```

## Best Practices

### 1. Use Step Templates for Reusable Operations

Step templates in `common/_step_templates/` encapsulate common operations shared across tests. Always prefer using an existing template over duplicating YAML.

**Using a template:**
```yaml
- name: Create Falco instance
  use:
    template: ../common/_step_templates/apply-assert-falco-daemonset.yaml
```

**Overriding bindings when needed:**
```yaml
- name: Verify config file
  use:
    template: ../common/_step_templates/verify-file-contains.yaml
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
    - name: config_file_path
      value: "/etc/falco/config.d/50-config-test.yaml"
```

Step-level bindings override test-level bindings when templates need different values.

### 3. Script Best Practices

Scripts in `common/scripts/` follow these conventions:

#### Standalone

Every script is self-contained and runnable directly from the command line. All inputs come from environment variables:

```bash
# Run a script standalone for debugging:
NAMESPACE=default \
FILE_PATH=/etc/falco/config.d/50-config-test.yaml \
EXPECTED_CONTENT=json_output \
bash common/scripts/verify_file_contains.sh
```

All environment variables are documented in a header comment at the top of each script.

#### Safety Flags

Every script starts with:
```bash
set -o errexit   # Abort on nonzero exit status
set -o nounset   # Abort on unbound variable
set -o pipefail  # Abort on pipe failure
```

#### Debuggable

Scripts output structured JSON on failure, including the exact commands executed:
```json
{
  "error": "Pattern not found in file",
  "file_path": "/etc/falco/config.d/50-config-test.yaml",
  "pattern": "json_output",
  "actual_content": "..."
}
```

#### Modular

Scripts source `common.sh` for shared utility functions. Each script does one thing well:
- `verify_file_contains.sh` - Verify file exists and contains a pattern
- `verify_content_update.sh` - Verify file content was updated
- `verify_file_size.sh` - Verify file has minimum size (OCI artifacts)
- `verify_file_rename.sh` - Verify file was renamed (priority changes)
- `wait_for_plugin.sh` - Wait for plugin .so download
- `debug_artifact.sh` - Diagnostic dump on failure

### 4. Adding New Tests

1. Create a new directory under `test/e2e/chainsaw/`
2. Create a `chainsaw-test.yaml` with test-level bindings
3. Reuse existing step templates where possible
4. For test-specific resources, use inline `apply: file:` blocks
5. If a new common pattern emerges, extract it into a step template

## Test Coverage

| Test Suite | Operator | Description |
|-----------|----------|-------------|
| `falco-daemonset` | falco-operator | Falco deployed as DaemonSet |
| `falco-deployment` | falco-operator | Falco deployed as Deployment |
| `config-inline` | artifact-operator | Config with inline YAML (create + update) |
| `rulesfile-inline` | artifact-operator | Rulesfile with inline rules (create + update) |
| `rulesfile-oci` | artifact-operator | Rulesfile from OCI registry (create + priority update) |
| `plugin-oci` | artifact-operator | Plugin from OCI registry |

## Chainsaw Gotchas

### Unbound Variables

Chainsaw expressions like `($myvar)` fail if `myvar` is not bound. Always explicitly bind every variable used in expressions at either the test or step level.

### Script Runs Once, Assert Retries

In a step with a `script:` followed by an `assert:`, the script executes **once** and its output is captured. The `assert:` block retries independently. Structure scripts to handle retries internally when needed.

### Relative Paths in Templates

Script paths in templates use paths relative to the **test directory**, not the template directory. Templates in `common/_step_templates/` reference scripts as `../../common/scripts/foo.sh`, which resolves correctly when used from a test in `<test-name>/`.
