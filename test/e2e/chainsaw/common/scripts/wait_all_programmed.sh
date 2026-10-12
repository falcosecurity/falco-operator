#!/usr/bin/env bash
# Wait until every resource of one type in a namespace is Programmed, after checking how many there are. An
# ArtifactNode assert is satisfied by one node; a parent is Programmed only once every node it is assigned to
# reports it, so this covers the others.
# Env vars:
#   NAMESPACE:       Namespace of the resources.
#   RESOURCE:        Resource type, e.g. "configs.artifact.falcosecurity.dev".
#   EXPECTED_COUNT:  How many resources of that type the namespace must hold.
#   TIMEOUT:         Wait timeout. Default: 120s.
set -o errexit
set -o nounset
set -o pipefail

count=$(kubectl get "${RESOURCE}" -n "${NAMESPACE}" -o name | wc -l)
if [ "${count}" -ne "${EXPECTED_COUNT}" ]; then
  echo "expected ${EXPECTED_COUNT} ${RESOURCE}, found ${count}" >&2
  exit 1
fi
kubectl wait "${RESOURCE}" --all -n "${NAMESPACE}" --for=condition=Programmed=True --timeout="${TIMEOUT:-120s}"
