#!/usr/bin/env bash
# Verify every matching Falco pod's containers have not restarted.
# A point-in-time check, not a retry-until-true wait: callers must first wait for all pods to be
# Ready (see wait-falco-pod-ready.yaml), so a restart count above 0 here means something
# actually restarted. Missing or incomplete status is not evidence of zero restarts.
# Env vars:
#   NAMESPACE:  Namespace of the Falco pod.
#   FALCO_NAME: Value of app.kubernetes.io/name label on the Falco pod.
set -o errexit
set -o nounset
set -o pipefail

NAMESPACE="${NAMESPACE}"
FALCO_NAME="${FALCO_NAME}"

if ! PODS=$(kubectl get pods -n "$NAMESPACE" -l "app.kubernetes.io/name=$FALCO_NAME" -o json 2>&1); then
  jq -n --arg error "$PODS" --arg namespace "$NAMESPACE" --arg falco_name "$FALCO_NAME" \
    '{status: "failure", message: "kubectl get pods failed", error: $error,
      namespace: $namespace, falco_name: $falco_name}'
  exit 1
fi

if ! PODS=$(printf '%s' "$PODS" | jq -ce '
  if (.items | length) == 0 then
    error("expected a nonempty pod list")
  else
    [.items[] |
      if (.status.containerStatuses | length) == 0 or
         ([.spec.containers[].name] | sort) != ([.status.containerStatuses[].name] | sort) then
        error("missing or incomplete container statuses for pod \(.metadata.name)")
      else
        {pod: .metadata.name,
         restart_counts: [.status.containerStatuses[].restartCount]}
      end]
  end
' 2>&1); then
  jq -n --arg error "$PODS" --arg namespace "$NAMESPACE" --arg falco_name "$FALCO_NAME" \
    '{status: "failure", message: "invalid or incomplete pod status", error: $error,
      namespace: $namespace, falco_name: $falco_name}'
  exit 1
fi

STATUS=success
MESSAGE="no container restarts"
if ! printf '%s' "$PODS" | jq -e 'all(.[]; all(.restart_counts[]; . == 0))' >/dev/null; then
  STATUS=failure
  MESSAGE="pod container restarted"
fi

# Preserve the original single-pod fields for callers, with details for every checked pod.
jq -n --arg status "$STATUS" --arg message "$MESSAGE" --arg namespace "$NAMESPACE" \
  --arg falco_name "$FALCO_NAME" --argjson pods "$PODS" \
  '{status: $status, message: $message, namespace: $namespace, falco_name: $falco_name,
    pod: $pods[0].pod, restart_counts: ($pods[0].restart_counts | map(tostring) | join(" ")),
    pods: $pods}'
[ "$STATUS" = success ]
