#!/usr/bin/env bash
# Delete a resource without waiting for it to be confirmed gone. Needed whenever the deletion is
# expected to trigger near-instant recreation under the same name (e.g. an owned object a
# controller recreates on its next reconcile): chainsaw's own `delete:` step always waits for the
# object to be absent by namespace+name (see kyverno/chainsaw's
# pkg/engine/operations/delete/operation.go waitForDeletion), which can never observe "gone" once
# a new object with a different UID has already taken the same name, and so always runs out its
# configured delete timeout. Pair this with get_resource_uid.sh (before) and
# wait_for_resource_uid_changed.sh (after) to confirm the delete-and-recreate cycle actually
# happened instead of just firing the delete blind.
# Env vars:
#   NAMESPACE: Namespace of the resource. Omit for cluster-scoped resources.
#   RESOURCE:  Resource type, e.g. "artifactnodes.artifact.falcosecurity.dev".
#   NAME:      Resource name.
set -o errexit
set -o nounset
set -o pipefail

RESOURCE="${RESOURCE}"
NAME="${NAME}"
NAMESPACE="${NAMESPACE:-}"

NAMESPACE_ARGS=()
if [ -n "$NAMESPACE" ]; then
  NAMESPACE_ARGS=(-n "$NAMESPACE")
fi

if ! OUTPUT=$(kubectl delete "$RESOURCE" "$NAME" "${NAMESPACE_ARGS[@]}" --wait=false 2>&1); then
  cat <<EOF
{
  "status": "failure",
  "message": "kubectl delete failed",
  "resource": "$RESOURCE",
  "name": "$NAME",
  "namespace": "$NAMESPACE",
  "error": $(printf '%s' "$OUTPUT" | jq -Rs .)
}
EOF
  exit 1
fi

cat <<EOF
{
  "status": "success",
  "resource": "$RESOURCE",
  "name": "$NAME",
  "namespace": "$NAMESPACE"
}
EOF
