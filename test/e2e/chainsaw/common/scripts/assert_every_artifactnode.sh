#!/usr/bin/env bash
# Wait until every ArtifactNode of a namespace satisfies a check, and there is at least one. A chainsaw assert
# without a name is satisfied by any one object, which on a cluster with several nodes says nothing about the
# others; this is for the assertions that are about each node.
#
# Env vars:
#   NAMESPACE:   Namespace of the ArtifactNodes.
#   CHECK:       jq filter applied to each ArtifactNode; it holds when it outputs true.
#   MAX_RETRIES: Default: 120.
#   RETRY_DELAY: Seconds between polls. Default: 1.
set -o errexit
set -o nounset
set -o pipefail

NAMESPACE="${NAMESPACE}"
CHECK="${CHECK}"
MAX_RETRIES="${MAX_RETRIES:-120}"
RETRY_DELAY="${RETRY_DELAY:-1}"
RESOURCE="artifactnodes.artifact.falcosecurity.dev"

failing=""
for _ in $(seq 1 "${MAX_RETRIES}"); do
  nodes=$(kubectl get "${RESOURCE}" -n "${NAMESPACE}" -o json)
  count=$(jq '.items | length' <<<"${nodes}")
  failing=$(jq -r ".items[] | select((${CHECK}) != true) | .metadata.name" <<<"${nodes}")
  if [ "${count}" -gt 0 ] && [ -z "${failing}" ]; then
    echo "all ${count} ArtifactNodes of ${NAMESPACE} satisfy the check"
    exit 0
  fi
  sleep "${RETRY_DELAY}"
done

echo "not every ArtifactNode of ${NAMESPACE} satisfies the check within ${MAX_RETRIES} attempts; failing: ${failing:-none exists}" >&2
exit 1
