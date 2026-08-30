#!/usr/bin/env bash
# Verify the Falco pod's containers have not restarted. A point-in-time check, not a
# retry-until-true wait: the caller is expected to have already waited for the pod to be
# Ready (see wait-falco-pod-ready.yaml), so a restart count above 0 here means something
# actually crashed and recovered, not that the pod hasn't come up yet.
# Env vars:
#   NAMESPACE:  Namespace of the Falco pod.
#   FALCO_NAME: Value of app.kubernetes.io/name label on the Falco pod.
set -o errexit
set -o nounset
set -o pipefail

NAMESPACE="${NAMESPACE}"
FALCO_NAME="${FALCO_NAME}"

if ! POD=$(kubectl get pods -n "$NAMESPACE" -l "app.kubernetes.io/name=$FALCO_NAME" \
    -o jsonpath='{.items[0].metadata.name}' 2>&1); then
  echo "{\"status\": \"failure\", \"message\": \"kubectl get pods failed\", \"error\": $(printf '%s' "$POD" | jq -Rs .)}"
  exit 1
fi
if [ -z "$POD" ]; then
  echo "{\"status\": \"failure\", \"message\": \"no pod found for app.kubernetes.io/name=$FALCO_NAME in $NAMESPACE\"}"
  exit 1
fi

if ! RESTARTS=$(kubectl get pod -n "$NAMESPACE" "$POD" \
    -o jsonpath='{.status.containerStatuses[*].restartCount}' 2>&1); then
  echo "{\"status\": \"failure\", \"message\": \"kubectl get pod failed\", \"pod\": \"$POD\", \"error\": $(printf '%s' "$RESTARTS" | jq -Rs .)}"
  exit 1
fi

for count in $RESTARTS; do
  if [ "$count" != "0" ]; then
    cat <<EOF
{
  "status": "failure",
  "message": "pod container restarted",
  "namespace": "$NAMESPACE",
  "falco_name": "$FALCO_NAME",
  "pod": "$POD",
  "restart_counts": "$RESTARTS"
}
EOF
    exit 1
  fi
done

cat <<EOF
{
  "status": "success",
  "message": "no container restarts",
  "namespace": "$NAMESPACE",
  "falco_name": "$FALCO_NAME",
  "pod": "$POD",
  "restart_counts": "$RESTARTS"
}
EOF
