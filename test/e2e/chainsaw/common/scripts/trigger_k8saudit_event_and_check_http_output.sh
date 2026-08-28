#!/usr/bin/env bash
# Send a captured, real Kubernetes API server audit event (wrapped as an EventList, exactly the
# shape the API server's own audit webhook backend posts) to the k8saudit plugin's HTTP listener
# inside the Falco pod - deterministically re-triggering a specific known audit event rather than
# depending on a live, audit-webhook-wired cluster - and verify the resulting alert was delivered
# via http_output to a receiver pod we control.
#
# Re-sent on every retry rather than once up front, since Falco's http_output route can take a
# few seconds to load after the Config CR lands.
#
# Env vars:
#   NAMESPACE:         Namespace of the Falco pod and the receiver pod.
#   FALCO_NAME:        Value of app.kubernetes.io/name label on the Falco pod.
#   SAMPLE_EVENT_FILE: Path (relative to the test's own directory) to a JSON file containing an
#                      EventList body to POST to the plugin's webhook endpoint.
#   RECEIVER_NAME:     Value of app.kubernetes.io/name label on the receiver pod.
#   EXPECTED_CONTENT:  Substring that must appear in the receiver's logs once delivered.
#   K8SAUDIT_URL:      URL of the k8saudit plugin's HTTP listener inside the Falco pod. Optional,
#                      default "http://localhost:9765/k8s-audit".
set -o errexit
set -o nounset
set -o pipefail

NAMESPACE="${NAMESPACE}"
FALCO_NAME="${FALCO_NAME}"
SAMPLE_EVENT_FILE="${SAMPLE_EVENT_FILE}"
RECEIVER_NAME="${RECEIVER_NAME}"
EXPECTED_CONTENT="${EXPECTED_CONTENT}"
K8SAUDIT_URL="${K8SAUDIT_URL:-http://localhost:9765/k8s-audit}"

MAX_RETRIES="${MAX_RETRIES:-200}"
RETRY_DELAY="${RETRY_DELAY:-1}"

LAST_ERROR="no attempts made"
FALCO_POD=""
RECEIVER_POD=""

for ATTEMPT in $(seq 1 "$MAX_RETRIES"); do
  if ! FALCO_POD=$(kubectl get pods -n "$NAMESPACE" -l "app.kubernetes.io/name=$FALCO_NAME" \
      -o jsonpath='{.items[0].metadata.name}' 2>&1); then
    LAST_ERROR="kubectl get falco pod failed: $FALCO_POD"
    sleep "$RETRY_DELAY"
    continue
  fi
  if [ -z "$FALCO_POD" ]; then
    LAST_ERROR="no falco pod found for app.kubernetes.io/name=$FALCO_NAME in $NAMESPACE"
    sleep "$RETRY_DELAY"
    continue
  fi

  kubectl exec -i -n "$NAMESPACE" "$FALCO_POD" -c netshoot -- \
    curl -sS -m 5 -X POST -H 'Content-Type: application/json' \
    --data-binary @- "$K8SAUDIT_URL" < "$SAMPLE_EVENT_FILE" >/dev/null 2>&1 || true

  if ! RECEIVER_POD=$(kubectl get pods -n "$NAMESPACE" -l "app.kubernetes.io/name=$RECEIVER_NAME" \
      -o jsonpath='{.items[0].metadata.name}' 2>&1); then
    LAST_ERROR="kubectl get receiver pod failed: $RECEIVER_POD"
    sleep "$RETRY_DELAY"
    continue
  fi
  if [ -z "$RECEIVER_POD" ]; then
    LAST_ERROR="no receiver pod found for app.kubernetes.io/name=$RECEIVER_NAME in $NAMESPACE"
    sleep "$RETRY_DELAY"
    continue
  fi

  if ! LOGS=$(kubectl logs -n "$NAMESPACE" "$RECEIVER_POD" 2>&1); then
    LAST_ERROR="kubectl logs failed: $LOGS"
    sleep "$RETRY_DELAY"
    continue
  fi

  if MATCHED=$(printf '%s' "$LOGS" | grep -m1 -F "$EXPECTED_CONTENT"); then
    cat <<EOF
{
  "status": "success",
  "message": "Sample k8saudit event triggered the expected alert, delivered via http_output",
  "namespace": "$NAMESPACE",
  "falco_pod": "$FALCO_POD",
  "receiver_name": "$RECEIVER_NAME",
  "pod": "$RECEIVER_POD",
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
  "message": "Sample k8saudit event did not trigger the expected alert after $MAX_RETRIES attempts",
  "namespace": "$NAMESPACE",
  "falco_pod": "$FALCO_POD",
  "receiver_name": "$RECEIVER_NAME",
  "pod": "$RECEIVER_POD",
  "expected_content": $(printf '%s' "$EXPECTED_CONTENT" | jq -Rs .),
  "received_content": $(printf '%s' "${LOGS:-}" | jq -Rs .),
  "last_error": $(printf '%s' "$LAST_ERROR" | jq -Rs .),
  "retry_attempt": $MAX_RETRIES,
  "max_retries": $MAX_RETRIES
}
EOF
exit 1
