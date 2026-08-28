#!/usr/bin/env bash
# Pushes purpose-built OCI test artifacts with controlled config layers to the local registry.
# Run by .github/workflows/test-e2e-chainsaw.yml before the chainsaw suite.
#
# This is a deliberate, CI-owned duplicate of hack/oci-test-artifacts/setup-oci-artifacts.sh (kept
# for local dev via `make registry.setup`) so CI has no dependency on anything under hack/ or the
# Makefile. Keep both copies in sync by hand when the test artifact set changes.
#
# Prerequisites: falcoctl, kubectl, tar in PATH.
# The registry must already be deployed: kubectl apply -f .github/e2e/oci-artifacts/registry.yaml
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
FIXTURES_DIR="${SCRIPT_DIR}/fixtures"

REGISTRY_NAMESPACE=oci-registry

command -v falcoctl >/dev/null 2>&1 || { echo "falcoctl not found. Install it first."; exit 1; }
command -v kubectl  >/dev/null 2>&1 || { echo "kubectl not found."; exit 1; }

echo "Waiting for registry deployment..."
kubectl rollout status deployment/registry -n "${REGISTRY_NAMESPACE}" --timeout=120s

echo "Starting port-forward to registry on localhost:5000..."
kubectl port-forward -n "${REGISTRY_NAMESPACE}" svc/registry 5000:5000 &
PF_PID=$!

TMPDIR=$(mktemp -d)
trap 'kill "${PF_PID}" 2>/dev/null; rm -rf "${TMPDIR}"' EXIT

# falcoctl defaults to writing its config at /etc/falcoctl/falcoctl.yaml and creates that
# directory if missing, which is fine for a root-owned local dev machine, but the unprivileged
# CI runner user can't write to /etc. Redirect every falcoctl call below into our own tempdir
# instead.
falcoctl() { command falcoctl --config "${TMPDIR}/falcoctl.yaml" "$@"; }

# Wait until the registry responds (up to 30s).
for i in $(seq 1 30); do
    if curl -sf http://localhost:5000/v2/ >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
curl -sf http://localhost:5000/v2/ >/dev/null 2>&1 || { echo "ERROR: registry not reachable at localhost:5000 after 30s"; exit 1; }

REGISTRY="localhost:5000"
echo "Registry push endpoint: ${REGISTRY}"

# make_rulesfile_tar <yaml_content> <output_tarball>
make_rulesfile_tar() {
    local content="$1"
    local tarfile="$2"
    local workdir
    workdir=$(mktemp -d "${TMPDIR}/rules-XXXXXX")
    printf '%s\n' "${content}" > "${workdir}/rules.yaml"
    tar -czf "${tarfile}" -C "${workdir}" rules.yaml
}

RULE_CONTENT=$(cat "${FIXTURES_DIR}/rule-basic.yaml")
RULE_WITH_ENGINE_REQ=$(cat "${FIXTURES_DIR}/rule-with-engine-req.yaml")
RULE_WITH_JSON_DEP_MET=$(cat "${FIXTURES_DIR}/rule-with-json-dep-met.yaml")
RULE_WITH_JSON_DEP_UNMET=$(cat "${FIXTURES_DIR}/rule-with-json-dep-unmet.yaml")
RULE_WITH_CONTAINER_DEP=$(cat "${FIXTURES_DIR}/rule-with-container-dep.yaml")

echo ""
echo "Pushing rulesfile-engine-req-met (requires engine_version_semver>=0.0.1, always met)..."
make_rulesfile_tar "${RULE_CONTENT}" "${TMPDIR}/rulesfile-engine-req-met.tar.gz"
falcoctl registry push \
    --type rulesfile \
    --version 0.1.0 \
    --plain-http \
    --requires engine_version_semver:0.0.1 \
    "${REGISTRY}/falco-test/rulesfile-engine-req-met:latest" \
    "${TMPDIR}/rulesfile-engine-req-met.tar.gz"

echo ""
echo "Pushing rulesfile-engine-req-unmet (requires engine_version_semver>=999.0.0, never met)..."
make_rulesfile_tar "${RULE_CONTENT}" "${TMPDIR}/rulesfile-engine-req-unmet.tar.gz"
falcoctl registry push \
    --type rulesfile \
    --version 0.1.0 \
    --plain-http \
    --requires engine_version_semver:999.0.0 \
    "${REGISTRY}/falco-test/rulesfile-engine-req-unmet:latest" \
    "${TMPDIR}/rulesfile-engine-req-unmet.tar.gz"

echo ""
echo "Pushing rulesfile-plugin-dep-met (depends on json>=0.7.0)..."
make_rulesfile_tar "${RULE_WITH_JSON_DEP_MET}" "${TMPDIR}/rulesfile-plugin-dep-met.tar.gz"
falcoctl registry push \
    --type rulesfile \
    --version 0.1.0 \
    --plain-http \
    --depends-on json:0.7.0 \
    "${REGISTRY}/falco-test/rulesfile-plugin-dep-met:latest" \
    "${TMPDIR}/rulesfile-plugin-dep-met.tar.gz"

echo ""
echo "Pushing rulesfile-plugin-dep-unmet (depends on json>=999.0.0, never met)..."
make_rulesfile_tar "${RULE_WITH_JSON_DEP_UNMET}" "${TMPDIR}/rulesfile-plugin-dep-unmet.tar.gz"
falcoctl registry push \
    --type rulesfile \
    --version 0.1.0 \
    --plain-http \
    --depends-on json:999.0.0 \
    "${REGISTRY}/falco-test/rulesfile-plugin-dep-unmet:latest" \
    "${TMPDIR}/rulesfile-plugin-dep-unmet.tar.gz"

echo ""
echo "Pushing rulesfile-config-content-reqs (config+YAML both declare engine_version_semver 0.0.1)..."
make_rulesfile_tar "${RULE_WITH_ENGINE_REQ}" "${TMPDIR}/rulesfile-config-content-reqs.tar.gz"
falcoctl registry push \
    --type rulesfile \
    --version 0.1.0 \
    --plain-http \
    --requires engine_version_semver:0.0.1 \
    "${REGISTRY}/falco-test/rulesfile-config-content-reqs:latest" \
    "${TMPDIR}/rulesfile-config-content-reqs.tar.gz"

echo ""
echo "Pushing rulesfile-all-sources (depends on container>=0.1.0, for all-sources removal-order test)..."
make_rulesfile_tar "${RULE_WITH_CONTAINER_DEP}" "${TMPDIR}/rulesfile-all-sources.tar.gz"
falcoctl registry push \
    --type rulesfile \
    --version 0.1.0 \
    --plain-http \
    --depends-on container:0.1.0 \
    "${REGISTRY}/falco-test/rulesfile-all-sources:latest" \
    "${TMPDIR}/rulesfile-all-sources.tar.gz"

echo ""
echo "Pushing rulesfile-plugin-dep-alternatives (primary json>=999.0.0 never met; alternative container>=0.1.0 met)..."
make_rulesfile_tar "${RULE_CONTENT}" "${TMPDIR}/rulesfile-plugin-dep-alternatives.tar.gz"
falcoctl registry push \
    --type rulesfile \
    --version 0.1.0 \
    --plain-http \
    --depends-on "json:999.0.0|container:0.1.0" \
    "${REGISTRY}/falco-test/rulesfile-plugin-dep-alternatives:latest" \
    "${TMPDIR}/rulesfile-plugin-dep-alternatives.tar.gz"

echo ""
echo "Downloading real plugin binaries and official rules from the Falco distribution (S3 bucket)..."
OFFICIAL_RULES_VERSION=5.1.0

for ARCH in x86_64 aarch64; do
    curl -fsSL -L \
        "https://download.falco.org/plugins/stable/json-0.7.4-linux-${ARCH}.tar.gz" \
        -o "${TMPDIR}/plugin-json-${ARCH}.tar.gz"
    curl -fsSL -L \
        "https://download.falco.org/plugins/stable/container-0.7.1-linux-${ARCH}.tar.gz" \
        -o "${TMPDIR}/plugin-container-${ARCH}.tar.gz"
    curl -fsSL -L \
        "https://download.falco.org/plugins/stable/k8smeta-0.4.0-linux-${ARCH}.tar.gz" \
        -o "${TMPDIR}/plugin-k8smeta-${ARCH}.tar.gz"
    curl -fsSL -L \
        "https://download.falco.org/plugins/stable/k8saudit-0.18.0-linux-${ARCH}.tar.gz" \
        -o "${TMPDIR}/plugin-k8saudit-${ARCH}.tar.gz"
done

# ponytail: official S3 release tarball already contains falco_rules.yaml at the root.
curl -fsSL -L \
    "https://download.falco.org/rules/falco-rules-${OFFICIAL_RULES_VERSION}.tar.gz" \
    -o "${TMPDIR}/rulesfile-official.tar.gz"

K8S_AUDIT_RULES_VERSION=0.18.0
curl -fsSL -L \
    "https://raw.githubusercontent.com/falcosecurity/plugins/plugins/k8saudit/v${K8S_AUDIT_RULES_VERSION}/plugins/k8saudit/rules/k8s_audit_rules.yaml" \
    -o "${TMPDIR}/k8s_audit_rules.yaml"
tar -czf "${TMPDIR}/rulesfile-k8s-audit-rules.tar.gz" -C "${TMPDIR}" k8s_audit_rules.yaml

# push_plugin <tag> <version> <tarball_base> [extra falcoctl flags...]
# Pushes linux/amd64 and linux/arm64 in a single call, producing a multi-arch manifest index.
push_plugin() {
    local tag="$1" version="$2" base="$3"
    shift 3
    falcoctl registry push \
        --type plugin --version "${version}" --plain-http \
        --platform linux/amd64 --platform linux/arm64 \
        "$@" \
        "${REGISTRY}/${tag}" \
        "${TMPDIR}/${base}-x86_64.tar.gz" \
        "${TMPDIR}/${base}-aarch64.tar.gz"
}

echo ""
echo "Pushing rulesfile-official (official falco_rules.yaml ${OFFICIAL_RULES_VERSION}: engine>=0.57.0 and container>=0.4.0 in config layer)..."
falcoctl registry push \
    --type rulesfile \
    --version "${OFFICIAL_RULES_VERSION}" \
    --plain-http \
    --requires engine_version_semver:0.57.0 \
    --depends-on container:0.4.0 \
    "${REGISTRY}/falco-test/rulesfile-official:latest" \
    "${TMPDIR}/rulesfile-official.tar.gz"

echo ""
echo "Pushing rulesfile-k8s-audit-rules (official k8s_audit_rules.yaml ${K8S_AUDIT_RULES_VERSION}: requires"
echo "engine_version 15 (legacy int scheme) and k8saudit>=0.18.0 / json>=0.7.0, all declared in the"
echo "file's own required_engine_version/required_plugin_versions content - no --requires/--depends-on"
echo "flags needed here, the instance operator parses those directives directly from the rules content)..."
falcoctl registry push \
    --type rulesfile \
    --version "${K8S_AUDIT_RULES_VERSION}" \
    --plain-http \
    "${REGISTRY}/falco-test/rulesfile-k8s-audit-rules:latest" \
    "${TMPDIR}/rulesfile-k8s-audit-rules.tar.gz"

echo ""
echo "Pushing plugin-api-unmet (real json 0.7.4 binary, requires plugin_api_version>=9.99.0, never met)..."
push_plugin "falco-test/plugin-api-unmet:latest" "0.7.4" "plugin-json" \
    --requires plugin_api_version:9.99.0

echo ""
echo "Pushing plugin-json (real json 0.7.4 binary, requires plugin_api_version 3.11.0)..."
push_plugin "falco-test/plugin-json:latest" "0.7.4" "plugin-json" \
    --requires plugin_api_version:3.11.0

echo ""
echo "Pushing plugin-container (real container 0.7.1 binary, requires plugin_api_version 3.10.0)..."
push_plugin "falco-test/plugin-container:latest" "0.7.1" "plugin-container" \
    --requires plugin_api_version:3.10.0

echo ""
echo "Pushing plugin-k8smeta (real k8smeta 0.4.0 binary, requires plugin_api_version 3.9.0)..."
push_plugin "falco-test/plugin-k8smeta:latest" "0.4.0" "plugin-k8smeta" \
    --requires plugin_api_version:3.9.0

echo ""
echo "Pushing plugin-k8saudit (real k8saudit 0.18.0 binary, requires plugin_api_version 3.11.0)..."
push_plugin "falco-test/plugin-k8saudit:latest" "0.18.0" "plugin-k8saudit" \
    --requires plugin_api_version:3.11.0

echo ""
echo "All OCI test artifacts pushed to ${REGISTRY}."
