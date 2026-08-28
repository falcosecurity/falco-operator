#!/usr/bin/env bash
# Assert that an exact file is present or absent on the Falco node filesystem.
# Env vars:
#   NAMESPACE:      Namespace of the Falco pod.
#   FALCO_NAME:     Value of app.kubernetes.io/name label on the Falco pod.
#   DIR:            Directory to check (e.g. /etc/falco/rules.d).
#   EXPECTED_FILE:  Exact filename to check (no directory prefix).
#   SHOULD_EXIST:   "true" to assert presence (default), "false" to assert absence.
set -o errexit
set -o nounset
set -o pipefail

SHOULD_EXIST="${SHOULD_EXIST:-true}"
MAX_RETRIES="${MAX_RETRIES:-180}"
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

  if kubectl exec -n "$NAMESPACE" "$POD" -c falco -- \
      sh -c "[ -e '$DIR/$EXPECTED_FILE' ]" >/dev/null 2>&1; then
    FILE_EXISTS="true"
  else
    FILE_EXISTS="false"
  fi

  if [ "$FILE_EXISTS" = "$SHOULD_EXIST" ]; then
    if [ "$SHOULD_EXIST" = "true" ]; then
      MSG="file present as expected"
    else
      MSG="file absent as expected"
    fi
    cat <<EOF
{
  "status": "success",
  "message": "$MSG",
  "file": "$DIR/$EXPECTED_FILE",
  "pod": "$POD",
  "attempt": $ATTEMPT
}
EOF
    exit 0
  fi

  if [ "$SHOULD_EXIST" = "true" ]; then
    LAST_ERROR="file $DIR/$EXPECTED_FILE not found"
  else
    LAST_ERROR="file $DIR/$EXPECTED_FILE still present"
  fi
  sleep "$RETRY_DELAY"
done

cat <<EOF
{
  "status": "failure",
  "message": "$LAST_ERROR after $MAX_RETRIES attempts",
  "file": "$DIR/$EXPECTED_FILE",
  "pod": "$POD"
}
EOF
exit 1
