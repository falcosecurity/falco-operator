#!/usr/bin/env bash
# Read the SHA-256 checksum of an installed file for byte-for-byte comparisons.
# Env vars:
#   NAMESPACE:  Namespace of the Falco pod.
#   FALCO_NAME: Value of app.kubernetes.io/name label on the Falco pod.
#   FILE_PATH:  Exact path to the file inside the falco container.
set -o errexit
set -o nounset
set -o pipefail

MAX_RETRIES="${MAX_RETRIES:-180}"
RETRY_DELAY="${RETRY_DELAY:-1}"
LAST_ERROR="no attempts made"
POD=""

for ATTEMPT in $(seq 1 "$MAX_RETRIES"); do
  if ! POD=$(kubectl get pods -n "$NAMESPACE" -l "app.kubernetes.io/name=$FALCO_NAME" \
      -o jsonpath='{.items[0].metadata.name}' 2>&1); then
    LAST_ERROR="kubectl get pods failed: $POD"
  elif [ -z "$POD" ]; then
    LAST_ERROR="no pod found for app.kubernetes.io/name=$FALCO_NAME in $NAMESPACE"
  elif CHECKSUM=$(kubectl exec -n "$NAMESPACE" "$POD" -c falco -- sha256sum "$FILE_PATH" 2>&1); then
    jq -n --arg checksum "${CHECKSUM%% *}" --arg file_path "$FILE_PATH" --arg pod "$POD" \
      '{status: "success", checksum: $checksum, file_path: $file_path, pod: $pod}'
    exit 0
  else
    LAST_ERROR="kubectl exec/sha256sum failed: $CHECKSUM"
  fi
  sleep "$RETRY_DELAY"
done

jq -n --arg message "$LAST_ERROR" --arg file_path "$FILE_PATH" --arg pod "$POD" \
  '{status: "failure", message: $message, file_path: $file_path, pod: $pod}'
exit 1
