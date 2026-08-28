#!/usr/bin/env bash
# Deterministically trigger an execve event (by exec-ing a trivial command into a pod we
# control) and verify it was captured, enriched, and delivered via Falco's http_output to a
# receiver pod we control - rather than waiting on ambient cluster activity (other pods'
# incidental execs) to eventually satisfy the rule, which is slow and non-deterministic.
#
# Falco doesn't necessarily pick up a new http_output route the instant the Config CR is
# applied (config file write + reload can lag a few seconds), so the trigger is re-fired on
# every retry rather than once up front - this covers that window without needing to know
# exactly when the reload completes.
#
# Env vars:
#   NAMESPACE:         Namespace of both the trigger pod and the receiver pod.
#   TRIGGER_POD:       Name of the pod to exec into to produce the execve event.
#   TRIGGER_CONTAINER: Container name within TRIGGER_POD to exec into.
#   RECEIVER_NAME:     Value of app.kubernetes.io/name label on the receiver pod.
#   EXPECTED_CONTENT:  Substring that must appear in the receiver's logs once delivered.
#   TRIGGER_CMD:       Command to exec for the execve event. Optional, default "true".
set -o errexit
set -o nounset
set -o pipefail

NAMESPACE="${NAMESPACE}"
TRIGGER_POD="${TRIGGER_POD}"
TRIGGER_CONTAINER="${TRIGGER_CONTAINER}"
RECEIVER_NAME="${RECEIVER_NAME}"
EXPECTED_CONTENT="${EXPECTED_CONTENT}"
TRIGGER_CMD="${TRIGGER_CMD:-true}"

MAX_RETRIES="${MAX_RETRIES:-200}"
RETRY_DELAY="${RETRY_DELAY:-1}"

LAST_ERROR="no attempts made"
POD=""

for ATTEMPT in $(seq 1 "$MAX_RETRIES"); do
  kubectl exec -n "$NAMESPACE" "$TRIGGER_POD" -c "$TRIGGER_CONTAINER" -- sh -c "$TRIGGER_CMD" >/dev/null 2>&1 || true

  if ! POD=$(kubectl get pods -n "$NAMESPACE" -l "app.kubernetes.io/name=$RECEIVER_NAME" \
      -o jsonpath='{.items[0].metadata.name}' 2>&1); then
    LAST_ERROR="kubectl get pods failed: $POD"
    sleep "$RETRY_DELAY"
    continue
  fi
  if [ -z "$POD" ]; then
    LAST_ERROR="no pod found for app.kubernetes.io/name=$RECEIVER_NAME in $NAMESPACE"
    sleep "$RETRY_DELAY"
    continue
  fi

  if ! LOGS=$(kubectl logs -n "$NAMESPACE" "$POD" 2>&1); then
    LAST_ERROR="kubectl logs failed: $LOGS"
    sleep "$RETRY_DELAY"
    continue
  fi

  if MATCHED=$(printf '%s' "$LOGS" | grep -m1 -F "$EXPECTED_CONTENT"); then
    cat <<EOF
{
  "status": "success",
  "message": "Triggered execve was captured, enriched, and delivered via http_output",
  "namespace": "$NAMESPACE",
  "trigger_pod": "$TRIGGER_POD",
  "receiver_name": "$RECEIVER_NAME",
  "pod": "$POD",
  "expected_content": $(printf '%s' "$EXPECTED_CONTENT" | jq -Rs .),
  "received_content": $(printf '%s' "$MATCHED" | jq -Rs .),
  "retry_attempt": $ATTEMPT,
  "max_retries": $MAX_RETRIES
}
EOF
    exit 0
  fi
  LAST_ERROR="expected content not yet present in receiver logs"
  sleep "$RETRY_DELAY"
done

cat <<EOF
{
  "status": "failure",
  "message": "Triggered execve was not captured/delivered after $MAX_RETRIES attempts",
  "namespace": "$NAMESPACE",
  "trigger_pod": "$TRIGGER_POD",
  "receiver_name": "$RECEIVER_NAME",
  "pod": "$POD",
  "expected_content": $(printf '%s' "$EXPECTED_CONTENT" | jq -Rs .),
  "received_content": $(printf '%s' "${LOGS:-}" | jq -Rs .),
  "last_error": $(printf '%s' "$LAST_ERROR" | jq -Rs .),
  "retry_attempt": $MAX_RETRIES,
  "max_retries": $MAX_RETRIES
}
EOF
exit 1
