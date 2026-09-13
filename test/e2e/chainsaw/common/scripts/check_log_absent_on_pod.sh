#!/usr/bin/env bash
# Verify a log line does NOT appear in a container's logs, polling for a settle window
# instead of checking once: a false negative (checking too early) would silently pass a
# real regression, so this actively waits out the window and fails the instant the
# pattern shows up, rather than only sampling the log at one point in time.
# Env vars:
#   NAMESPACE:     Namespace of the pod.
#   FALCO_NAME:    Value of app.kubernetes.io/name label on the pod.
#   CONTAINER:     Container name to read logs from.
#   PATTERN:       Fixed string to grep for (matched with grep -F).
#   MAX_RETRIES:   How many times to poll before declaring success. Default: 200.
#   RETRY_DELAY:   Seconds between polls. Default: 1.
set -o errexit
set -o nounset
set -o pipefail

NAMESPACE="${NAMESPACE}"
FALCO_NAME="${FALCO_NAME}"
CONTAINER="${CONTAINER}"
PATTERN="${PATTERN}"
MAX_RETRIES="${MAX_RETRIES:-200}"
RETRY_DELAY="${RETRY_DELAY:-1}"

POD=$(kubectl get pods -n "$NAMESPACE" -l "app.kubernetes.io/name=$FALCO_NAME" \
  -o jsonpath='{.items[0].metadata.name}')
if [ -z "$POD" ]; then
  echo "no pod found for app.kubernetes.io/name=$FALCO_NAME in $NAMESPACE" >&2
  exit 1
fi

for ATTEMPT in $(seq 1 "$MAX_RETRIES"); do
  if MATCH=$(kubectl logs -n "$NAMESPACE" "$POD" -c "$CONTAINER" 2>/dev/null | grep -F "$PATTERN" || true); then
    if [ -n "$MATCH" ]; then
      cat <<EOF
{
  "status": "failure",
  "message": "Pattern found in pod logs (expected absent)",
  "namespace": "$NAMESPACE",
  "pod": "$POD",
  "container": "$CONTAINER",
  "pattern": $(printf '%s' "$PATTERN" | jq -Rs .),
  "match": $(printf '%s' "$MATCH" | jq -Rs .),
  "retry_attempt": $ATTEMPT,
  "max_retries": $MAX_RETRIES
}
EOF
      exit 1
    fi
  fi
  sleep "$RETRY_DELAY"
done

cat <<EOF
{
  "status": "success",
  "message": "Pattern never appeared in pod logs during the settle window",
  "namespace": "$NAMESPACE",
  "pod": "$POD",
  "container": "$CONTAINER",
  "pattern": $(printf '%s' "$PATTERN" | jq -Rs .),
  "max_retries": $MAX_RETRIES,
  "retry_delay": $RETRY_DELAY
}
EOF
