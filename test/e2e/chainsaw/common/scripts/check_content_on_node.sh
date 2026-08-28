#!/usr/bin/env bash
# Verify specific content is present in a file under a directory on the Falco node filesystem.
# Env vars:
#   NAMESPACE:       Namespace of the Falco pod.
#   FALCO_NAME:      Value of app.kubernetes.io/name label on the Falco pod.
#   DIR:             Directory to search recursively (e.g. /etc/falco/rules.d).
#   CONTENT_PATTERN: Substring to grep for within file contents.
#   FILE_PATTERN:    Substring to further filter matches by filename. Optional.
set -o errexit
set -o nounset
set -o pipefail

NAMESPACE="${NAMESPACE}"
FALCO_NAME="${FALCO_NAME}"
DIR="${DIR}"
CONTENT_PATTERN="${CONTENT_PATTERN}"
FILE_PATTERN="${FILE_PATTERN:-}"

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

  if ! MATCHES=$(kubectl exec -n "$NAMESPACE" "$POD" -c falco -- \
      sh -c "grep -r \"$CONTENT_PATTERN\" \"$DIR\"/ 2>/dev/null || true" 2>&1); then
    LAST_ERROR="kubectl exec failed: $MATCHES"
    sleep "$RETRY_DELAY"
    continue
  fi

  if [ -n "$FILE_PATTERN" ]; then
    MATCHES=$(echo "$MATCHES" | grep "$FILE_PATTERN" || true)
  fi

  if [ -n "$MATCHES" ]; then
    cat <<EOF
{
  "status": "success",
  "message": "Found matching content",
  "namespace": "$NAMESPACE",
  "falco_name": "$FALCO_NAME",
  "pod": "$POD",
  "dir": "$DIR",
  "content_pattern": "$CONTENT_PATTERN",
  "file_pattern": "$FILE_PATTERN",
  "matches": $(printf '%s' "$MATCHES" | jq -Rs .),
  "retry_attempt": $ATTEMPT,
  "max_retries": $MAX_RETRIES
}
EOF
    exit 0
  fi
  LAST_ERROR="no content matching '$CONTENT_PATTERN' (file_pattern='$FILE_PATTERN') found in $DIR"
  sleep "$RETRY_DELAY"
done

cat <<EOF
{
  "status": "failure",
  "message": "No matching content found after $MAX_RETRIES attempts",
  "namespace": "$NAMESPACE",
  "falco_name": "$FALCO_NAME",
  "pod": "$POD",
  "dir": "$DIR",
  "content_pattern": "$CONTENT_PATTERN",
  "file_pattern": "$FILE_PATTERN",
  "matches": null,
  "last_error": $(printf '%s' "$LAST_ERROR" | jq -Rs .),
  "retry_attempt": $MAX_RETRIES,
  "max_retries": $MAX_RETRIES
}
EOF
exit 1
