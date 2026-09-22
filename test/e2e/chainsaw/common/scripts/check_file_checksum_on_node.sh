#!/usr/bin/env bash
# Read the SHA-256 checksum of an installed file on every matching Falco pod.
# Success requires identical bytes on all pods; the scalar checksum is safe to use
# for later comparisons. Do not use this for architecture-specific binaries on a
# mixed-architecture DaemonSet.
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
PODS=""

get_pods() {
  local response
  if ! response=$(kubectl get pods -n "$NAMESPACE" -l "app.kubernetes.io/name=$FALCO_NAME" -o json 2>&1); then
    LAST_ERROR="kubectl get pods failed: $response"
    return 1
  fi
  if ! PODS=$(printf '%s' "$response" | jq -ce '
    [.items[].metadata | {name, uid}] |
    select(length > 0 and all(.[];
      (.name | type) == "string" and (.name | length) > 0 and
      (.uid | type) == "string" and (.uid | length) > 0))
  ' 2>&1); then
    LAST_ERROR="expected a nonempty pod list with valid names and UIDs: $PODS"
    return 1
  fi
}

for ATTEMPT in $(seq 1 "$MAX_RETRIES"); do
  if ! get_pods; then
    sleep "$RETRY_DELAY"
    continue
  fi
  SNAPSHOT="$PODS"
  FIRST_POD=$(printf '%s' "$SNAPSHOT" | jq -r '.[0].name')
  CHECKSUM=""
  ATTEMPT_FAILED=0
  for POD in $(printf '%s' "$SNAPSHOT" | jq -r '.[].name'); do
    if ! OUTPUT=$(kubectl exec -n "$NAMESPACE" "$POD" -c falco -- sha256sum "$FILE_PATH" 2>&1); then
      LAST_ERROR="kubectl exec/sha256sum failed on pod $POD: $OUTPUT"
      ATTEMPT_FAILED=1
      break
    fi
    CURRENT="${OUTPUT%% *}"
    if ! [[ "$CURRENT" =~ ^[a-fA-F0-9]{64}$ ]]; then
      LAST_ERROR="invalid SHA-256 output on pod $POD: $OUTPUT"
      ATTEMPT_FAILED=1
      break
    fi
    if [ -n "$CHECKSUM" ] && [ "$CURRENT" != "$CHECKSUM" ]; then
      LAST_ERROR="file $FILE_PATH differs between pods $FIRST_POD and $POD"
      ATTEMPT_FAILED=1
      break
    fi
    CHECKSUM="$CURRENT"
  done
  if [ "$ATTEMPT_FAILED" -eq 0 ] && get_pods; then
    if [ "$(printf '%s' "$SNAPSHOT" | jq -Sc 'sort_by(.name)')" = "$(printf '%s' "$PODS" | jq -Sc 'sort_by(.name)')" ]; then
      jq -n --arg checksum "$CHECKSUM" --arg file_path "$FILE_PATH" --arg pod "$FIRST_POD" --argjson pods "$SNAPSHOT" \
        '{status: "success", checksum: $checksum, file_path: $file_path, pod: $pod, pods: $pods}'
      exit 0
    fi
    LAST_ERROR="pod membership or UID changed while reading checksums"
  fi
  sleep "$RETRY_DELAY"
done

jq -n --arg message "$LAST_ERROR" --arg file_path "$FILE_PATH" --arg pod "$POD" \
  '{status: "failure", message: $message, file_path: $file_path, pod: $pod}'
exit 1
