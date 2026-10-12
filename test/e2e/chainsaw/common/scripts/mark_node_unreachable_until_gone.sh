#!/usr/bin/env bash
# Make a node look unreachable for a long time, the way the node lifecycle controller marks one whose kubelet stopped
# reporting, and wait for a resource to be gone.
#
# The node gets the node.kubernetes.io/unreachable NoExecute taint with a time in the past. On a node that reports
# Ready, such as a KWOK fake node, the node lifecycle controller takes the taint away again within seconds, so it is
# put back until the resource is gone.
#
# Env vars:
#   NODE_NAME:    Node to mark unreachable.
#   SINCE:        How long ago the node became unreachable, as a `date -d` offset (default "1 hour ago").
#   RESOURCE:     Resource type of the object to wait for, e.g. configs.artifact.falcosecurity.dev.
#   NAME:         Name of the object.
#   NAMESPACE:    Namespace of the object.
#   MAX_RETRIES:  Attempts, one second apart (default 90).
set -o errexit
set -o nounset
set -o pipefail

NODE_NAME="${NODE_NAME}"
SINCE="${SINCE:-1 hour ago}"
RESOURCE="${RESOURCE}"
NAME="${NAME}"
NAMESPACE="${NAMESPACE}"
MAX_RETRIES="${MAX_RETRIES:-90}"

since=$(date -u -d "${SINCE}" +%Y-%m-%dT%H:%M:%SZ)

for _ in $(seq 1 "${MAX_RETRIES}"); do
  # Only NotFound means gone: any other failure (a wrong resource name, an API hiccup) must not pass.
  if ! output=$(kubectl get "${RESOURCE}" "${NAME}" -n "${NAMESPACE}" 2>&1 >/dev/null); then
    if printf '%s' "${output}" | grep -q "NotFound"; then
      echo "${RESOURCE}/${NAME} is gone"
      exit 0
    fi
    echo "unable to get ${RESOURCE}/${NAME}: ${output}" >&2
    exit 1
  fi
  taints=$(kubectl get node "${NODE_NAME}" -o json | jq -c --arg since "${since}" '
    [(.spec.taints // [])[] | select((.key == "node.kubernetes.io/unreachable" and .effect == "NoExecute") | not)]
    + [{key: "node.kubernetes.io/unreachable", effect: "NoExecute", timeAdded: $since}]')
  kubectl patch node "${NODE_NAME}" --type=merge -p "{\"spec\":{\"taints\":${taints}}}" >/dev/null
  sleep 1
done

echo "${RESOURCE}/${NAME} in ${NAMESPACE} is still there after ${MAX_RETRIES} attempts" >&2
exit 1
