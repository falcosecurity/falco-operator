#!/usr/bin/env bash
# Wait until every pod currently in the namespace reports Ready.
#
# Re-lists pods on every poll instead of snapshotting once (unlike `kubectl wait --all`,
# which fails hard with NotFound if a pod it saw at the start gets deleted before it's
# checked - exactly what happens right after a Falco type switch, when the old
# DaemonSet's pods are still being torn down as the new Deployment's pod comes up).
#
# Env vars:
#   NAMESPACE: Namespace to check.
set -o errexit
set -o nounset
set -o pipefail

NAMESPACE="${NAMESPACE}"
MAX_RETRIES="${MAX_RETRIES:-200}"
RETRY_DELAY="${RETRY_DELAY:-1}"

LAST_ERROR="no attempts made"

for ATTEMPT in $(seq 1 "$MAX_RETRIES"); do
  if ! STATUSES=$(kubectl get pods -n "$NAMESPACE" \
      -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}' 2>&1); then
    LAST_ERROR="kubectl get pods failed: $STATUSES"
    sleep "$RETRY_DELAY"
    continue
  fi

  if [ -z "$STATUSES" ]; then
    LAST_ERROR="no pods found in $NAMESPACE"
    sleep "$RETRY_DELAY"
    continue
  fi

  if ! printf '%s\n' "$STATUSES" | grep -qv ' True$'; then
    echo "{\"status\": \"success\", \"message\": \"all pods ready\", \"namespace\": \"$NAMESPACE\"}"
    exit 0
  fi
  LAST_ERROR="not all pods ready: $(printf '%s' "$STATUSES" | tr '\n' ';')"
  sleep "$RETRY_DELAY"
done

echo "{\"status\": \"failure\", \"message\": \"not all pods ready after $MAX_RETRIES attempts\", \"namespace\": \"$NAMESPACE\", \"last_error\": $(printf '%s' "$LAST_ERROR" | jq -Rs .)}"
exit 1
