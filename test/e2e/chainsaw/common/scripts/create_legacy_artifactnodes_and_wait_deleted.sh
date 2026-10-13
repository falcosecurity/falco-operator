#!/usr/bin/env bash
# Create the ArtifactNodes a v0.5.0 release candidate would have left behind for one node, one per artifact kind
# and each holding that kind's old finalizer, then wait until the operator has deleted every ArtifactNode of the
# namespace: it must release the old finalizers, which no artifact operator handles any more.
# Env vars:
#   NAMESPACE: Namespace of the ArtifactNodes.
#   NODE_NAME: Node the leftovers name.
#   TIMEOUT:   Wait timeout. Default: 120s.
set -o errexit
set -o nounset
set -o pipefail

for kind in rulesfile plugin config; do
  kubectl apply -f - <<YAML
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: ArtifactNode
metadata:
  name: ${kind}--leftover--${NODE_NAME}
  namespace: ${NAMESPACE}
  finalizers:
    - ${kind}node.artifact.falcosecurity.dev/finalizer
spec:
  nodeName: ${NODE_NAME}
YAML
done
kubectl wait --for=delete artifactnodes.artifact.falcosecurity.dev --all -n "${NAMESPACE}" --timeout="${TIMEOUT:-120s}"
