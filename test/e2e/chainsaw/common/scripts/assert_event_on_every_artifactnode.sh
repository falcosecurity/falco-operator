#!/usr/bin/env bash
# Wait until every ArtifactNode of a namespace has an Event of a given reason regarding it, and there is at least
# one ArtifactNode. Each artifact operator records its Events on its own node's ArtifactNode, so one Event does
# not show that the others did.
# Env vars:
#   NAMESPACE:   Namespace of the ArtifactNodes and of their Events.
#   REASON:      Reason of the Event, e.g. "BulkRemoval".
#   MAX_RETRIES: Default: 60.
#   RETRY_DELAY: Seconds between polls. Default: 1.
set -o errexit
set -o nounset
set -o pipefail

warned=""
nodes=""
for _ in $(seq 1 "${MAX_RETRIES:-60}"); do
  warned=$(kubectl get events.events.k8s.io -n "${NAMESPACE}" -o json |
    jq -r --arg reason "${REASON}" '.items[] | select(.reason == $reason and .regarding.kind == "ArtifactNode") | .regarding.name' | sort -u)
  nodes=$(kubectl get artifactnodes.artifact.falcosecurity.dev -n "${NAMESPACE}" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | sort -u)
  if [ -n "${nodes}" ] && [ "${warned}" = "${nodes}" ]; then
    exit 0
  fi
  sleep "${RETRY_DELAY:-1}"
done

echo "not every ArtifactNode got a ${REASON} Event; with one: ${warned}; nodes: ${nodes}" >&2
exit 1
