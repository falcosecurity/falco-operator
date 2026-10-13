#!/usr/bin/env bash
# Delete every ArtifactNode of a namespace, as a person or a crash might, and wait until each of them is back as
# a new object (a new uid). A sidecar that is running holds its finalizer on its node's object until it has
# removed what it installed, so the objects are terminating for a while. The assignment controller creates them
# again once they are gone, from the artifacts themselves.
#
# Env vars:
#   NAMESPACE:        Namespace of the ArtifactNodes.
#   STRIP_FINALIZERS: "true" also removes the finalizers of the deleted objects (default false), for when the
#                     artifact operator that would release its own is down.
#   MAX_RETRIES: Default: 120.
#   RETRY_DELAY: Seconds between polls. Default: 1.
set -o errexit
set -o nounset
set -o pipefail

NAMESPACE="${NAMESPACE}"
MAX_RETRIES="${MAX_RETRIES:-120}"
RETRY_DELAY="${RETRY_DELAY:-1}"
RESOURCE="artifactnodes.artifact.falcosecurity.dev"

uids() {
  kubectl get "${RESOURCE}" -n "${NAMESPACE}" -o jsonpath='{range .items[*]}{.metadata.uid}{"\n"}{end}' | sort
}

old=$(uids)
count=$(printf '%s\n' "${old}" | grep -c . || true)
if [ "${count}" -eq 0 ]; then
  echo "no ArtifactNode in ${NAMESPACE} to delete" >&2
  exit 1
fi

kubectl delete "${RESOURCE}" --all -n "${NAMESPACE}" --wait=false
if [ "${STRIP_FINALIZERS:-false}" = "true" ]; then
  for node in $(kubectl get "${RESOURCE}" -n "${NAMESPACE}" -o name); do
    kubectl patch "${node}" -n "${NAMESPACE}" --type=merge -p '{"metadata":{"finalizers":null}}' || true
  done
fi

for _ in $(seq 1 "${MAX_RETRIES}"); do
  now=$(uids)
  if [ "$(printf '%s\n' "${now}" | grep -c . || true)" -eq "${count}" ] &&
    [ -z "$(comm -12 <(printf '%s\n' "${old}") <(printf '%s\n' "${now}"))" ]; then
    echo "all ${count} ArtifactNodes were recreated"
    exit 0
  fi
  sleep "${RETRY_DELAY}"
done

echo "the ${count} ArtifactNodes were not all recreated within ${MAX_RETRIES} attempts; now: ${now}" >&2
exit 1
