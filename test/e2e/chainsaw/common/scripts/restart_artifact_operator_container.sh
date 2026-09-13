#!/usr/bin/env bash
# Forces the artifact-operator sidecar container to restart IN PLACE (same Pod, same UID, same
# emptyDir-backed volumes) instead of deleting/rescheduling the Pod. The directories the
# artifact-operator writes into (falco-configs/falco-rulesfiles/falco-plugins, see
# internal/pkg/resources/falco.go) are EmptyDir volumes: they're destroyed and recreated empty
# whenever the Pod itself is replaced, so any test that wants durable on-disk state to survive
# "a restart" must restart only this container, never the Pod.
#
# Relies on apply-assert-falco.yaml's shareProcessNamespace: true and its "netshoot" sidecar:
# with a shared PID namespace, a process in netshoot can see and signal the artifact-operator
# container's own process even though it lives in a different container. "manager" is the single
# entrypoint binary every falco-operator component image ships (build/Dockerfile's ENTRYPOINT),
# so it's unique within this Pod (only the artifact-operator container runs it).
#
# Env vars:
#   NAMESPACE:   Namespace of the Falco pod.
#   FALCO_NAME:  Value of app.kubernetes.io/name label on the Falco pod.
set -o errexit
set -o nounset
set -o pipefail

NAMESPACE="${NAMESPACE}"
FALCO_NAME="${FALCO_NAME}"

MAX_RETRIES="${MAX_RETRIES:-200}"
RETRY_DELAY="${RETRY_DELAY:-1}"

POD=$(kubectl get pods -n "$NAMESPACE" -l "app.kubernetes.io/name=$FALCO_NAME" \
  -o jsonpath='{.items[0].metadata.name}')
if [ -z "$POD" ]; then
  echo "no pod found for app.kubernetes.io/name=$FALCO_NAME in $NAMESPACE" >&2
  exit 1
fi

BEFORE_COUNT=$(kubectl get pod -n "$NAMESPACE" "$POD" \
  -o jsonpath='{.status.containerStatuses[?(@.name=="artifact-operator")].restartCount}')

if ! kubectl exec -n "$NAMESPACE" "$POD" -c netshoot -- sh -c 'kill -KILL "$(pgrep -x manager)"'; then
  echo "unable to signal the artifact-operator process from netshoot" >&2
  exit 1
fi

for ATTEMPT in $(seq 1 "$MAX_RETRIES"); do
  AFTER_COUNT=$(kubectl get pod -n "$NAMESPACE" "$POD" \
    -o jsonpath='{.status.containerStatuses[?(@.name=="artifact-operator")].restartCount}' 2>/dev/null || echo "")
  READY=$(kubectl get pod -n "$NAMESPACE" "$POD" \
    -o jsonpath='{.status.containerStatuses[?(@.name=="artifact-operator")].ready}' 2>/dev/null || echo "")
  if [ -n "$AFTER_COUNT" ] && [ "$AFTER_COUNT" -gt "$BEFORE_COUNT" ] && [ "$READY" = "true" ]; then
    cat <<EOF
{
  "status": "success",
  "message": "artifact-operator container restarted in place and is ready",
  "namespace": "$NAMESPACE",
  "pod": "$POD",
  "restart_count_before": $BEFORE_COUNT,
  "restart_count_after": $AFTER_COUNT,
  "retry_attempt": $ATTEMPT,
  "max_retries": $MAX_RETRIES
}
EOF
    exit 0
  fi
  sleep "$RETRY_DELAY"
done

cat <<EOF
{
  "status": "failure",
  "message": "artifact-operator container did not restart and become ready in time",
  "namespace": "$NAMESPACE",
  "pod": "$POD",
  "restart_count_before": $BEFORE_COUNT,
  "max_retries": $MAX_RETRIES
}
EOF
exit 1
