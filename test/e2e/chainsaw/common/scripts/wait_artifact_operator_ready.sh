#!/usr/bin/env bash
# Waits until the artifact-operator sidecar container of the Falco pod reports Ready: the counterpart of
# stop_artifact_operator_container.sh, once the caller has done what it wanted behind the sidecar's back.
#
# Env vars:
#   NAMESPACE:   Namespace of the Falco pod.
#   FALCO_NAME:  Value of app.kubernetes.io/name label on the Falco pod.
#   MAX_RETRIES: Default: 200.
#   RETRY_DELAY: Seconds between polls. Default: 1.
set -o errexit
set -o nounset
set -o pipefail

NAMESPACE="${NAMESPACE}"
FALCO_NAME="${FALCO_NAME}"
MAX_RETRIES="${MAX_RETRIES:-200}"
RETRY_DELAY="${RETRY_DELAY:-1}"

POD=""
for ATTEMPT in $(seq 1 "$MAX_RETRIES"); do
  POD=$(kubectl get pods -n "$NAMESPACE" -l "app.kubernetes.io/name=$FALCO_NAME" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  if [ -n "$POD" ]; then
    READY=$(kubectl get pod -n "$NAMESPACE" "$POD" \
      -o jsonpath='{.status.containerStatuses[?(@.name=="artifact-operator")].ready}' 2>/dev/null || echo "")
    if [ "$READY" = "true" ]; then
      cat <<EOJ
{
  "status": "success",
  "message": "artifact-operator container is ready",
  "namespace": "$NAMESPACE",
  "pod": "$POD",
  "retry_attempt": $ATTEMPT,
  "max_retries": $MAX_RETRIES
}
EOJ
      exit 0
    fi
  fi
  sleep "$RETRY_DELAY"
done

cat <<EOJ
{
  "status": "failure",
  "message": "artifact-operator container did not become ready in time",
  "namespace": "$NAMESPACE",
  "pod": "$POD",
  "max_retries": $MAX_RETRIES
}
EOJ
exit 1
