#!/usr/bin/env bash
# Trigger a genuine DaemonSet rolling restart and wait for it to complete. Unlike deleting a
# Pod directly, this goes through the DaemonSet controller's own updateStrategy (e.g.
# maxSurge/maxUnavailable set on the owning Falco CR), so a surging rollout never leaves a node
# without a Running pod for it.
# Env vars:
#   NAMESPACE:    Namespace of the DaemonSet.
#   DAEMONSET_NAME: Name of the DaemonSet to restart.
#   TIMEOUT:      Max time to wait for the rollout to finish. Default: 120s.
set -o errexit
set -o nounset
set -o pipefail

NAMESPACE="${NAMESPACE}"
DAEMONSET_NAME="${DAEMONSET_NAME}"
TIMEOUT="${TIMEOUT:-120s}"

if ! RESTART_OUTPUT=$(kubectl rollout restart daemonset "$DAEMONSET_NAME" -n "$NAMESPACE" 2>&1); then
  cat <<EOF
{
  "status": "failure",
  "message": "kubectl rollout restart failed",
  "namespace": "$NAMESPACE",
  "daemonset_name": "$DAEMONSET_NAME",
  "error": $(printf '%s' "$RESTART_OUTPUT" | jq -Rs .)
}
EOF
  exit 1
fi

if ! STATUS_OUTPUT=$(kubectl rollout status daemonset "$DAEMONSET_NAME" -n "$NAMESPACE" --timeout="$TIMEOUT" 2>&1); then
  cat <<EOF
{
  "status": "failure",
  "message": "kubectl rollout status did not complete within timeout",
  "namespace": "$NAMESPACE",
  "daemonset_name": "$DAEMONSET_NAME",
  "timeout": "$TIMEOUT",
  "error": $(printf '%s' "$STATUS_OUTPUT" | jq -Rs .)
}
EOF
  exit 1
fi

cat <<EOF
{
  "status": "success",
  "message": "DaemonSet rollout restart completed",
  "namespace": "$NAMESPACE",
  "daemonset_name": "$DAEMONSET_NAME",
  "result": $(printf '%s' "$STATUS_OUTPUT" | jq -Rs .)
}
EOF
