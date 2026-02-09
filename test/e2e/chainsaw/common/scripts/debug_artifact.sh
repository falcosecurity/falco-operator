#!/bin/bash
# Debug helper for artifact operator e2e tests.
# Outputs diagnostic information when a test step fails.
#
# Variables (from environment):
#   NAMESPACE: (Required) The namespace to debug.

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

echo "=== Debug Information ==="
echo "Namespace: ${NAMESPACE}"

echo ""
echo "=== Pod Status ==="
kubectl get pods -n "${NAMESPACE}" -o wide 2>/dev/null || echo "No pods found"

echo ""
echo "=== Rules Directory ==="
exec_in_falco "ls -la /etc/falco/rules.d/ 2>/dev/null" || echo "Unable to list rules directory"

echo ""
echo "=== Config Directory ==="
exec_in_falco "ls -la /etc/falco/config.d/ 2>/dev/null" || echo "Unable to list config directory"

echo ""
echo "=== Plugin Directory ==="
exec_in_falco "ls -la /usr/share/falco/plugins/ 2>/dev/null" || echo "Unable to list plugin directory"

echo ""
echo "=== Artifact Operator Logs ==="
falco_pod=$(get_pod 2>/dev/null || echo "")
if [ -n "${falco_pod}" ]; then
  kubectl logs -n "${NAMESPACE}" "${falco_pod}" -c artifact-operator --tail=50 2>/dev/null || echo "Unable to get artifact operator logs"
else
  echo "No Falco pod found for artifact operator logs"
fi

echo ""
echo "=== Falco Logs ==="
falco_pod=$(get_pod 2>/dev/null || echo "")
if [ -n "${falco_pod}" ]; then
  kubectl logs -n "${NAMESPACE}" "${falco_pod}" -c falco --tail=50 2>/dev/null || echo "Unable to get Falco logs"
else
  echo "No Falco pod found"
fi

echo ""
echo "=== Events ==="
kubectl get events -n "${NAMESPACE}" --sort-by='.lastTimestamp' 2>/dev/null | tail -20 || echo "No events found"
