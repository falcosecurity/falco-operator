#!/usr/bin/env bash
# Write a local file's content into a file inside a container on EVERY matching Falco pod,
# via kubectl exec. Takes effect immediately on the next read: no ConfigMap/kubelet
# volume-sync propagation delay to wait out.
#
# Writing to ALL pods is required for DaemonSet deployments: each node runs an independent
# per-node sidecar with its own emptyDir, so updating only items[0] leaves other pods' mock
# stale. The aggregate DependenciesSatisfied condition uses "False wins", so one stale pod
# keeps the whole Plugin stuck.
#
# Env vars:
#   NAMESPACE:   Namespace of the Falco pod.
#   FALCO_NAME:  Value of app.kubernetes.io/name label on the Falco pod.
#   CONTAINER:   Container name to exec into.
#   REMOTE_PATH: Path inside the container to write to.
#   LOCAL_FILE:  Local file (relative to the calling test's directory) whose content is piped in.
set -o errexit
set -o nounset
set -o pipefail

NAMESPACE="${NAMESPACE}"
FALCO_NAME="${FALCO_NAME}"
CONTAINER="${CONTAINER}"
REMOTE_PATH="${REMOTE_PATH}"
LOCAL_FILE="${LOCAL_FILE}"

MAX_RETRIES="${MAX_RETRIES:-200}"
RETRY_DELAY="${RETRY_DELAY:-1}"

LAST_ERROR="no attempts made"
PODS=""

for ATTEMPT in $(seq 1 "$MAX_RETRIES"); do
  if ! PODS=$(kubectl get pods -n "$NAMESPACE" -l "app.kubernetes.io/name=$FALCO_NAME" \
      -o jsonpath='{.items[*].metadata.name}' 2>&1); then
    LAST_ERROR="kubectl get pods failed: $PODS"
    sleep "$RETRY_DELAY"
    continue
  fi
  if [ -z "$PODS" ]; then
    LAST_ERROR="no pod found for app.kubernetes.io/name=$FALCO_NAME in $NAMESPACE"
    sleep "$RETRY_DELAY"
    continue
  fi

  # Write to every pod. If any exec fails, abort this attempt and retry the whole loop so
  # we re-discover the pod list (pods may have restarted between attempts).
  ATTEMPT_FAILED=0
  WRITTEN_PODS=""
  for POD in $PODS; do
    if ! OUTPUT=$(kubectl exec -i -n "$NAMESPACE" "$POD" -c "$CONTAINER" -- \
        sh -c "cat > \"$REMOTE_PATH\"" <"$LOCAL_FILE" 2>&1); then
      LAST_ERROR="kubectl exec failed on pod $POD: $OUTPUT"
      ATTEMPT_FAILED=1
      break
    fi
    WRITTEN_PODS="${WRITTEN_PODS:+$WRITTEN_PODS, }$POD"
  done

  if [ "$ATTEMPT_FAILED" -eq 1 ]; then
    sleep "$RETRY_DELAY"
    continue
  fi

  cat <<EOF
{
  "status": "success",
  "message": "File written to all pods",
  "namespace": "$NAMESPACE",
  "falco_name": "$FALCO_NAME",
  "pods": "$WRITTEN_PODS",
  "container": "$CONTAINER",
  "remote_path": "$REMOTE_PATH",
  "local_file": "$LOCAL_FILE",
  "retry_attempt": $ATTEMPT,
  "max_retries": $MAX_RETRIES
}
EOF
  exit 0
done

cat <<EOF
{
  "status": "failure",
  "message": "Failed to write file to all pods after $MAX_RETRIES attempts",
  "namespace": "$NAMESPACE",
  "falco_name": "$FALCO_NAME",
  "pods": "$PODS",
  "container": "$CONTAINER",
  "remote_path": "$REMOTE_PATH",
  "local_file": "$LOCAL_FILE",
  "last_error": $(printf '%s' "$LAST_ERROR" | jq -Rs .),
  "retry_attempt": $MAX_RETRIES,
  "max_retries": $MAX_RETRIES
}
EOF
exit 1
