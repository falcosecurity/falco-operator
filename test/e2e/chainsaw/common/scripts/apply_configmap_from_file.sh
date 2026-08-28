#!/usr/bin/env bash
# Create or update a ConfigMap whose data key is loaded from a plain file.
# Env vars:
#   CONFIGMAP_NAME: Name of the ConfigMap to create/update.
#   NAMESPACE:      Namespace for the ConfigMap.
#   SOURCE_FILE:     Path to the file used as the ConfigMap's data key content.
#   DATA_KEY:       ConfigMap data key the file's content is stored under. Default: rules.yaml.
set -o errexit
set -o nounset
set -o pipefail

CONFIGMAP_NAME="${CONFIGMAP_NAME}"
NAMESPACE="${NAMESPACE}"
SOURCE_FILE="${SOURCE_FILE}"
DATA_KEY="${DATA_KEY:-rules.yaml}"

if ! MANIFEST=$(kubectl create configmap "$CONFIGMAP_NAME" -n "$NAMESPACE" \
    --from-file="$DATA_KEY"="$SOURCE_FILE" \
    --dry-run=client -o yaml 2>&1); then
  cat <<EOF
{
  "status": "failure",
  "message": "kubectl create --dry-run=client failed",
  "namespace": "$NAMESPACE",
  "configmap_name": "$CONFIGMAP_NAME",
  "data_key": "$DATA_KEY",
  "source_file": "$SOURCE_FILE",
  "error": $(printf '%s' "$MANIFEST" | jq -Rs .)
}
EOF
  exit 1
fi

if ! OUTPUT=$(echo "$MANIFEST" | kubectl apply -f - 2>&1); then
  cat <<EOF
{
  "status": "failure",
  "message": "kubectl apply failed",
  "namespace": "$NAMESPACE",
  "configmap_name": "$CONFIGMAP_NAME",
  "data_key": "$DATA_KEY",
  "source_file": "$SOURCE_FILE",
  "error": $(printf '%s' "$OUTPUT" | jq -Rs .)
}
EOF
  exit 1
fi

cat <<EOF
{
  "status": "success",
  "message": "ConfigMap applied",
  "namespace": "$NAMESPACE",
  "configmap_name": "$CONFIGMAP_NAME",
  "data_key": "$DATA_KEY",
  "source_file": "$SOURCE_FILE",
  "result": $(printf '%s' "$OUTPUT" | jq -Rs .)
}
EOF
