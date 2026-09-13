#!/usr/bin/env bash
# Print a resource's current UID as JSON, for binding into a later step via chainsaw's
# `outputs:` (see rulesfile-inline-plugin-dep-alternatives for the $stdout/json_parse pattern).
# Used to capture a "before" UID so a later step can confirm an object was actually deleted and
# recreated (a new UID under the same name), not merely that an object with an acceptable shape
# exists at that name.
# Env vars:
#   NAMESPACE: Namespace of the resource. Omit for cluster-scoped resources.
#   RESOURCE:  Resource type, e.g. "artifactnodes.artifact.falcosecurity.dev".
#   NAME:      Resource name.
#   MAX_RETRIES: Default: 200.
#   RETRY_DELAY: Seconds between polls. Default: 1.
set -o errexit
set -o nounset
set -o pipefail

RESOURCE="${RESOURCE}"
NAME="${NAME}"
NAMESPACE="${NAMESPACE:-}"
MAX_RETRIES="${MAX_RETRIES:-200}"
RETRY_DELAY="${RETRY_DELAY:-1}"

NAMESPACE_ARGS=()
if [ -n "$NAMESPACE" ]; then
  NAMESPACE_ARGS=(-n "$NAMESPACE")
fi

LAST_ERROR="no attempts made"
UID_VALUE=""

for ATTEMPT in $(seq 1 "$MAX_RETRIES"); do
  if UID_VALUE=$(kubectl get "$RESOURCE" "$NAME" "${NAMESPACE_ARGS[@]}" -o jsonpath='{.metadata.uid}' 2>&1); then
    if [ -n "$UID_VALUE" ]; then
      cat <<EOF
{
  "status": "success",
  "resource": "$RESOURCE",
  "name": "$NAME",
  "namespace": "$NAMESPACE",
  "uid": "$UID_VALUE",
  "retry_attempt": $ATTEMPT,
  "max_retries": $MAX_RETRIES
}
EOF
      exit 0
    fi
    LAST_ERROR="empty UID returned"
  else
    LAST_ERROR="kubectl get failed: $UID_VALUE"
  fi
  sleep "$RETRY_DELAY"
done

cat <<EOF
{
  "status": "failure",
  "message": "unable to get resource UID after $MAX_RETRIES attempts",
  "resource": "$RESOURCE",
  "name": "$NAME",
  "namespace": "$NAMESPACE",
  "last_error": $(printf '%s' "$LAST_ERROR" | jq -Rs .),
  "retry_attempt": $MAX_RETRIES,
  "max_retries": $MAX_RETRIES
}
EOF
exit 1
