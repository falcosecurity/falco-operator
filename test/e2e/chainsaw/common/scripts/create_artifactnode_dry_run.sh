#!/usr/bin/env bash
# Ask the API server, without persisting anything, to create an ArtifactNode listing a given number of
# artifacts. It fails when the server rejects the object, which is how the list's size cap is tested.
# Env vars:
#   NAMESPACE:       Namespace of the ArtifactNode.
#   ARTIFACT_COUNT:  Number of artifacts in spec.artifacts.
set -o errexit
set -o nounset
set -o pipefail

jq -n --arg ns "${NAMESPACE}" --argjson n "${ARTIFACT_COUNT}" '{
  apiVersion: "artifact.falcosecurity.dev/v1alpha1", kind: "ArtifactNode",
  metadata: {name: "too-many", namespace: $ns},
  spec: {nodeName: "some-node", artifacts: [range($n) | {kind: "Rulesfile", name: ("rules-" + tostring), uid: ("uid-" + tostring)}]}
}' | kubectl create --dry-run=server -f -
