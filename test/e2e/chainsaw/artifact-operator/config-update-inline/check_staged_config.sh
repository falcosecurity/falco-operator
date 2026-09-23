#!/usr/bin/env bash
# Prove staged bytes are neither installed content nor Falco configuration.
set -o errexit
set -o nounset
set -o pipefail

PODS=$(kubectl get pods -n "$NAMESPACE" -l "app.kubernetes.io/name=$FALCO_NAME" \
  -o jsonpath='{.items[*].metadata.name}')
[ -n "$PODS" ]
STAGED_PATH=/etc/falco/config.d/.tmp/50-03-staging-probe-inline.yaml.tmp

cleanup() {
  for POD in $PODS; do
    kubectl exec -n "$NAMESPACE" "$POD" -c falco -- rm -f "$STAGED_PATH" >&2 || true
  done
}
trap cleanup EXIT

# The directory must have been created by the running operator, not by this fixture.
for POD in $PODS; do
  kubectl exec -n "$NAMESPACE" "$POD" -c falco -- test -d /etc/falco/config.d/.tmp
done
CONTAINER=falco REMOTE_PATH="$STAGED_PATH" LOCAL_FILE=staged-config.yaml \
  bash ../../common/scripts/write_file_on_node.sh >&2

if OUTPUT=$(DIR=/etc/falco/config.d CONTENT_PATTERN=staging-must-not-be-loaded \
    FILE_PATTERN=50-03-staging-probe-inline.yaml MAX_RETRIES=1 RETRY_DELAY=0 \
    bash ../../common/scripts/check_content_on_node.sh); then
  echo "content assertion accepted an unpublished staged file: $OUTPUT" >&2
  exit 1
fi
printf '%s' "$OUTPUT" | jq -e \
  '.status == "failure" and (.last_error | startswith("no content matching"))' >&2

# --version parses the real config first, but does not start another capture engine.
# Reading the staged override would fail with an invalid engine kind.
for POD in $PODS; do
  kubectl exec -n "$NAMESPACE" "$POD" -c falco -- /usr/bin/falco --version >&2
done
jq -n '{status: "success", message: "staged configuration ignored by assertions and Falco"}'
