#!/usr/bin/env bash
# Assert that, in each of the given namespaces, the first artifact the node's ArtifactNode lists carries the uid
# of the Rulesfile of that same namespace: same-named artifacts of two namespaces must not be mixed up.
# Env vars:
#   NAMESPACES:      Space-separated namespaces to check.
#   NODE_NAME:       Name of the node, which is also the name of its ArtifactNode in each namespace.
#   RULESFILE_NAME:  Name of the Rulesfile, the same in each namespace.
set -o errexit
set -o nounset
set -o pipefail

for ns in ${NAMESPACES}; do
  want=$(kubectl get rulesfile "${RULESFILE_NAME}" -n "${ns}" -o jsonpath='{.metadata.uid}')
  got=$(kubectl get artifactnodes.artifact.falcosecurity.dev "${NODE_NAME}" -n "${ns}" -o jsonpath='{.spec.artifacts[0].uid}')
  if [ "${want}" != "${got}" ]; then
    echo "the ArtifactNode of ${ns} lists uid ${got}, but the Rulesfile of that namespace has ${want}" >&2
    exit 1
  fi
done
