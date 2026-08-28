#!/usr/bin/env bash
# Verify an artifact file is present on the Falco node filesystem.
# Env vars:
#   NAMESPACE:     Namespace of the Falco pod.
#   FALCO_NAME:    Value of app.kubernetes.io/name label on the Falco pod.
#   DIR:           Directory to check (e.g. /etc/falco/rules.d).
#   FILE_PATTERN:  Substring to grep for in the directory listing.
set -o errexit
set -o nounset
set -o pipefail

NAMESPACE="${NAMESPACE}"
FALCO_NAME="${FALCO_NAME}"
DIR="${DIR}"
FILE_PATTERN="${FILE_PATTERN}"

MAX_RETRIES="${MAX_RETRIES:-200}"
RETRY_DELAY="${RETRY_DELAY:-1}"

LAST_ERROR="no attempts made"
POD=""

for ATTEMPT in $(seq 1 "$MAX_RETRIES"); do
  if ! POD=$(kubectl get pods -n "$NAMESPACE" -l "app.kubernetes.io/name=$FALCO_NAME" \
      -o jsonpath='{.items[0].metadata.name}' 2>&1); then
    LAST_ERROR="kubectl get pods failed: $POD"
    sleep "$RETRY_DELAY"
    continue
  fi
  if [ -z "$POD" ]; then
    LAST_ERROR="no pod found for app.kubernetes.io/name=$FALCO_NAME in $NAMESPACE"
    sleep "$RETRY_DELAY"
    continue
  fi

  if ! FILES=$(kubectl exec -n "$NAMESPACE" "$POD" -c falco -- \
      sh -c "ls \"$DIR\"/ 2>/dev/null | grep \"$FILE_PATTERN\" || true" 2>&1); then
    LAST_ERROR="kubectl exec failed: $FILES"
    sleep "$RETRY_DELAY"
    continue
  fi

  if [ -n "$FILES" ]; then
    cat <<EOF
{
  "status": "success",
  "message": "Found files matching pattern",
  "namespace": "$NAMESPACE",
  "falco_name": "$FALCO_NAME",
  "pod": "$POD",
  "dir": "$DIR",
  "file_pattern": "$FILE_PATTERN",
  "files_found": $(printf '%s' "$FILES" | jq -Rs .),
  "retry_attempt": $ATTEMPT,
  "max_retries": $MAX_RETRIES
}
EOF
    exit 0
  fi
  LAST_ERROR="no files matching '$FILE_PATTERN' found in $DIR"
  sleep "$RETRY_DELAY"
done

cat <<EOF
{
  "status": "failure",
  "message": "No files matching pattern found after $MAX_RETRIES attempts",
  "namespace": "$NAMESPACE",
  "falco_name": "$FALCO_NAME",
  "pod": "$POD",
  "dir": "$DIR",
  "file_pattern": "$FILE_PATTERN",
  "files_found": null,
  "last_error": $(printf '%s' "$LAST_ERROR" | jq -Rs .),
  "retry_attempt": $MAX_RETRIES,
  "max_retries": $MAX_RETRIES
}
EOF
exit 1
