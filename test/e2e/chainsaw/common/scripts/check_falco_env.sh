#!/usr/bin/env bash
# Check Falco's resolved environment on every non-terminating Pod after rollout.
# NAMESPACE, FALCO_NAME, ENV_STAGE and EXPECTED_HOSTNAME are required.
# HOSTNAME_FROM_NODE=true expects each Pod's node name instead of EXPECTED_HOSTNAME.
set -o errexit
set -o nounset
set -o pipefail

kubectl rollout status "daemonset/$FALCO_NAME" -n "$NAMESPACE" --timeout=180s >&2
PODS=$(kubectl get pods -n "$NAMESPACE" -l "app.kubernetes.io/name=$FALCO_NAME" -o json)
PODS=$(jq '[.items[] | select(.metadata.deletionTimestamp == null)]' <<< "$PODS")
if [ "$(jq 'length' <<< "$PODS")" -eq 0 ]; then
  echo "No Falco Pods found" >&2
  exit 1
fi

while IFS= read -r POD_JSON; do
  POD=$(jq -r '.metadata.name' <<< "$POD_JSON")
  NODE=$(jq -r '.spec.nodeName' <<< "$POD_JSON")
  if ! jq -e --arg stage "$ENV_STAGE" '
    .metadata.annotations["test.falcosecurity.dev/env-stage"] == $stage and
    any(.status.conditions[]; .type == "Ready" and .status == "True")
  ' <<< "$POD_JSON" >/dev/null; then
    echo "Pod $POD is not ready at env stage $ENV_STAGE" >&2
    exit 1
  fi
  HOSTNAME_VALUE="$EXPECTED_HOSTNAME"
  if [ "${HOSTNAME_FROM_NODE:-false}" = true ]; then
    HOSTNAME_VALUE="$NODE"
  fi
  # Separate calls distinguish an explicitly empty value from an unset variable:
  # printenv exits nonzero for the latter and errexit fails the check.
  ACTUAL_HOSTNAME=$(kubectl exec -n "$NAMESPACE" "$POD" -c falco -- printenv FALCO_HOSTNAME)
  ACTUAL_ROOT=$(kubectl exec -n "$NAMESPACE" "$POD" -c falco -- printenv HOST_ROOT)
  ACTUAL_NODE=$(kubectl exec -n "$NAMESPACE" "$POD" -c falco -- printenv FALCO_K8S_NODE_NAME)
  if [ "$ACTUAL_HOSTNAME" != "$HOSTNAME_VALUE" ] || [ "$ACTUAL_ROOT" != /host ] || [ "$ACTUAL_NODE" != "$NODE" ]; then
    echo "Unexpected Falco environment on Pod $POD" >&2
    exit 1
  fi
done < <(jq -c '.[]' <<< "$PODS")

jq -n --argjson pods "$(jq 'length' <<< "$PODS")" '{status: "success", pods: $pods}'
