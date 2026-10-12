#!/usr/bin/env bash
# Delete a (KWOK) Falco pod, keep it away for a while and create it again, then fail if the node's ArtifactNode
# was replaced in the meantime: a pod that comes back within the absence grace must keep its ArtifactNode.
# Env vars:
#   NAMESPACE:        Namespace of the pod and of the ArtifactNode.
#   NODE_NAME:        Name of the node, which is also the name of its ArtifactNode.
#   POD_NAME:         Name of the pod.
#   ABSENCE_SECONDS:  How long the pod stays away.
#   SETTLE_SECONDS:   How long to wait after the pod is back before comparing uids. Default: 10.
#   RULESFILE_NAME:   Optional. A Rulesfile that must stay Programmed=True for the whole absence.
set -o errexit
set -o nounset
set -o pipefail

manifest="$(mktemp)"
trap 'rm -f "${manifest}"' EXIT

artifactnode_uid() {
  kubectl get artifactnodes.artifact.falcosecurity.dev "${NODE_NAME}" -n "${NAMESPACE}" -o jsonpath='{.metadata.uid}'
}

uid_before=$(artifactnode_uid)
kubectl get pod "${POD_NAME}" -n "${NAMESPACE}" -o json |
  jq 'del(.metadata.resourceVersion, .metadata.uid, .metadata.creationTimestamp, .status)' >"${manifest}"
kubectl delete pod "${POD_NAME}" -n "${NAMESPACE}" --wait=true

for _ in $(seq 1 "${ABSENCE_SECONDS}"); do
  if [ -n "${RULESFILE_NAME:-}" ]; then
    programmed=$(kubectl get rulesfile "${RULESFILE_NAME}" -n "${NAMESPACE}" \
      -o jsonpath='{.status.conditions[?(@.type=="Programmed")].status}')
    if [ "${programmed}" != "True" ]; then
      echo "the parent flapped to Programmed=${programmed} while the pod was away" >&2
      exit 1
    fi
    kubectl get artifactnodes.artifact.falcosecurity.dev "${NODE_NAME}" -n "${NAMESPACE}" >/dev/null
  fi
  sleep 1
done

kubectl apply -f "${manifest}"
kubectl wait --for=jsonpath='{.status.phase}'=Running pod/"${POD_NAME}" -n "${NAMESPACE}" --timeout=60s
sleep "${SETTLE_SECONDS:-10}"

uid_after=$(artifactnode_uid)
if [ "${uid_before}" != "${uid_after}" ]; then
  echo "the ArtifactNode was replaced (${uid_before} -> ${uid_after}) although the pod came back within the grace" >&2
  exit 1
fi
