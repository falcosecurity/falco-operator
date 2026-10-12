#!/usr/bin/env bash
# Run simulate_sidecar_report.sh for every ArtifactNode of a namespace. It is meant for a test's catch and
# cleanup, where the simulated entries must be withdrawn so that the namespace can be deleted: it never fails.
# Env vars:
#   NAMESPACE:         Namespace of the ArtifactNodes.
#   STRIP_FINALIZERS:  "true" also removes every finalizer of each ArtifactNode (default false), for nodes
#                      where no real artifact operator runs to release its own.
#   Every variable of simulate_sidecar_report.sh except NODE_NAME (KINDS, WITHDRAW, CONDITIONS, ...).
set -o nounset

script_dir="$(cd "$(dirname "$0")" && pwd)"

kubectl get artifactnodes.artifact.falcosecurity.dev -n "${NAMESPACE}" -o name 2>/dev/null | while read -r node; do
  NODE_NAME="${node#*/}" bash "${script_dir}/simulate_sidecar_report.sh" || true
  if [ "${STRIP_FINALIZERS:-false}" = "true" ]; then
    kubectl patch "${node}" -n "${NAMESPACE}" --type=merge -p '{"metadata":{"finalizers":[]}}' 2>/dev/null || true
  fi
done
exit 0
