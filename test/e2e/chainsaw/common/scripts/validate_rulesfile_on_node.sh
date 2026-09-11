#!/usr/bin/env bash
# Validate installed rules with the real Falco binary and the pod's plugin configuration.
# Env vars:
#   NAMESPACE:  Namespace of the Falco pod.
#   FALCO_NAME: Value of app.kubernetes.io/name label on the Falco pod.
#   FILE_PATH:  Exact path to the rulesfile inside the falco container.
set -o errexit
set -o nounset
set -o pipefail

POD=$(kubectl get pods -n "$NAMESPACE" -l "app.kubernetes.io/name=$FALCO_NAME" \
  -o jsonpath='{.items[0].metadata.name}')

if OUTPUT=$(kubectl exec -n "$NAMESPACE" "$POD" -c falco -- /usr/bin/falco -V "$FILE_PATH" 2>&1); then
  jq -n --arg output "$OUTPUT" --arg file_path "$FILE_PATH" --arg pod "$POD" \
    '{status: "success", output: $output, file_path: $file_path, pod: $pod}'
else
  jq -n --arg output "$OUTPUT" --arg file_path "$FILE_PATH" --arg pod "$POD" \
    '{status: "failure", output: $output, file_path: $file_path, pod: $pod}'
  exit 1
fi
