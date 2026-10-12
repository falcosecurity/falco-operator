#!/usr/bin/env bash
# Put a label on, or take one off, the nodes that run the Falco pods of a test. The label is an argument of
# `kubectl label`: "key=value" sets it, "key-" removes it. Nodes are cluster-scoped and outlive the test, so a
# test that labels real nodes must take the label off again, in a step and in its catch.
#
# Env vars:
#   NAMESPACE:     Namespace of the Falco pods.
#   FALCO_NAME:    Value of the app.kubernetes.io/name label on the Falco pods.
#   LABEL:         The label argument, e.g. "key=value" or "key-".
#   ALLOW_FAILURE: "true" makes the script succeed whatever happens (default false), for a best-effort removal in
#                  a test's catch or cleanup.
set -o errexit
set -o nounset
set -o pipefail

if [ "${ALLOW_FAILURE:-false}" = "true" ]; then
  trap 'exit 0' EXIT
fi

NAMESPACE="${NAMESPACE}"
FALCO_NAME="${FALCO_NAME}"
LABEL="${LABEL}"

nodes=$(kubectl get pods -n "${NAMESPACE}" -l "app.kubernetes.io/name=${FALCO_NAME}" -o jsonpath='{range .items[*]}{.spec.nodeName}{"\n"}{end}' | sort -u)
if [ -z "${nodes}" ]; then
  echo "no Falco pod of ${FALCO_NAME} runs in ${NAMESPACE}" >&2
  exit 1
fi

for node in ${nodes}; do
  kubectl label node "${node}" "${LABEL}" --overwrite
done
