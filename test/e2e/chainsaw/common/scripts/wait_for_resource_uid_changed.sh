#!/usr/bin/env bash
# Poll until a resource's UID differs from a previously-captured one (see get_resource_uid.sh),
# confirming an object was actually deleted and a new one recreated under the same name, rather
# than the same object having existed the whole time. A shape-only assert (spec/status) can't
# tell those apart when the recreated object's fields look identical to the original's.
# Env vars:
#   NAMESPACE: Namespace of the resource. Omit for cluster-scoped resources.
#   RESOURCE:  Resource type, e.g. "artifactnodes.artifact.falcosecurity.dev".
#   NAME:      Resource name.
#   OLD_UID:   The UID captured before deletion; success requires a different, non-empty UID.
#   MAX_RETRIES: Default: 200.
#   RETRY_DELAY: Seconds between polls. Default: 1.
set -o errexit
set -o nounset
set -o pipefail

RESOURCE="${RESOURCE}"
NAME="${NAME}"
NAMESPACE="${NAMESPACE:-}"
OLD_UID="${OLD_UID}"
MAX_RETRIES="${MAX_RETRIES:-200}"
RETRY_DELAY="${RETRY_DELAY:-1}"

NAMESPACE_ARGS=()
if [ -n "$NAMESPACE" ]; then
  NAMESPACE_ARGS=(-n "$NAMESPACE")
fi

LAST_ERROR="no attempts made"
CURRENT_UID=""

for ATTEMPT in $(seq 1 "$MAX_RETRIES"); do
  if CURRENT_UID=$(kubectl get "$RESOURCE" "$NAME" "${NAMESPACE_ARGS[@]}" -o jsonpath='{.metadata.uid}' 2>&1); then
    if [ -n "$CURRENT_UID" ] && [ "$CURRENT_UID" != "$OLD_UID" ]; then
      cat <<EOF
{
  "status": "success",
  "message": "resource recreated with a new UID",
  "resource": "$RESOURCE",
  "name": "$NAME",
  "namespace": "$NAMESPACE",
  "old_uid": "$OLD_UID",
  "new_uid": "$CURRENT_UID",
  "retry_attempt": $ATTEMPT,
  "max_retries": $MAX_RETRIES
}
EOF
      exit 0
    fi
    LAST_ERROR="UID still $CURRENT_UID (unchanged, or not yet recreated)"
  else
    LAST_ERROR="kubectl get failed: $CURRENT_UID"
  fi
  sleep "$RETRY_DELAY"
done

cat <<EOF
{
  "status": "failure",
  "message": "resource UID never changed after $MAX_RETRIES attempts",
  "resource": "$RESOURCE",
  "name": "$NAME",
  "namespace": "$NAMESPACE",
  "old_uid": "$OLD_UID",
  "last_error": $(printf '%s' "$LAST_ERROR" | jq -Rs .),
  "retry_attempt": $MAX_RETRIES,
  "max_retries": $MAX_RETRIES
}
EOF
exit 1
