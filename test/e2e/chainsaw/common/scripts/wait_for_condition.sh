#!/usr/bin/env bash
# Wait for a specific condition to be set on a Kubernetes resource.
#
# Variables (from environment):
#   RESOURCE:   Resource type and name, e.g., "rulesfile/my-rulesfile".
#   CONDITION:  Condition expression for kubectl wait, e.g., "condition=Programmed=True".
#   NAMESPACE:  Namespace of the resource.
#   TIMEOUT:    Wait timeout. Default: 200s.
set -o errexit
set -o nounset
set -o pipefail

RESOURCE="${RESOURCE}"
CONDITION="${CONDITION}"
NAMESPACE="${NAMESPACE}"
TIMEOUT="${TIMEOUT:-200s}"

echo "Waiting for $RESOURCE in $NAMESPACE to satisfy: $CONDITION (timeout: $TIMEOUT)"
kubectl wait "$RESOURCE" \
  --for="$CONDITION" \
  --timeout="$TIMEOUT" \
  -n "$NAMESPACE"

echo "Condition satisfied: $CONDITION on $RESOURCE"
