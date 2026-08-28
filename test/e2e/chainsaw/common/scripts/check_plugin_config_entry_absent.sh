#!/usr/bin/env bash
# Verify the shared plugins-config file on a Falco node is present but no longer contains an
# entry for a specific plugin: the inverse of check_plugin_config_on_node.sh. Since
# RemovePluginConfigByName started keeping this file on disk permanently (see
# internal/pkg/nodeartifacts/pluginconfig.go: Falco's own file-watch on this path does not
# reliably survive the file being deleted and later recreated), "the last plugin was removed" is
# expressed as an empty file ("plugins: []"), not an absent one.
# Parses the file as YAML (via yq) rather than grepping text, so it can't be fooled by another
# plugin's entry sharing a substring with PLUGIN_NAME.
# Env vars:
#   NAMESPACE:   Namespace of the Falco pod.
#   FALCO_NAME:  Value of app.kubernetes.io/name label on the Falco pod.
#   FILE_PATH:   Exact path to the plugins-config file, e.g.
#                /etc/falco/config.d/99-03-plugins-config-inline.yaml.
#   PLUGIN_NAME: Resolved config name that must no longer appear in load_plugins or plugins[].
set -o errexit
set -o nounset
set -o pipefail

NAMESPACE="${NAMESPACE}"
FALCO_NAME="${FALCO_NAME}"
FILE_PATH="${FILE_PATH}"
PLUGIN_NAME="${PLUGIN_NAME}"

MAX_RETRIES="${MAX_RETRIES:-200}"
RETRY_DELAY="${RETRY_DELAY:-1}"

LAST_ERROR="no attempts made"
POD=""
CONFIG_JSON=""

for ATTEMPT in $(seq 1 "$MAX_RETRIES"); do
  if ! POD=$(kubectl get pods -n "$NAMESPACE" -l "app.kubernetes.io/name=$FALCO_NAME" \
      -o jsonpath='{.items[0].metadata.name}' 2>&1); then
    LAST_ERROR="kubectl get pods failed: $POD"
    sleep "$RETRY_DELAY"
    continue
  fi
  if [ -z "$POD" ]; then
    LAST_ERROR="no pod found for app.kubernetes.io/name=$FALCO_NAME in $NAMESPACE"
    sleep "$RETRY_DELAY"
    continue
  fi

  if ! CONTENT=$(kubectl exec -n "$NAMESPACE" "$POD" -c falco -- \
      sh -c "cat $FILE_PATH 2>&1" 2>&1); then
    LAST_ERROR="kubectl exec failed (file may not exist yet): $CONTENT"
    sleep "$RETRY_DELAY"
    continue
  fi

  if ! CONFIG_JSON=$(printf '%s' "$CONTENT" | yq -o=json '.' - 2>&1); then
    LAST_ERROR="failed to parse $FILE_PATH as YAML: $CONFIG_JSON"
    sleep "$RETRY_DELAY"
    continue
  fi

  LOAD_PLUGINS_COUNT=$(printf '%s' "$CONFIG_JSON" | jq --arg name "$PLUGIN_NAME" \
    '[.load_plugins[]? | select(. == $name)] | length')
  PLUGINS_ENTRIES_COUNT=$(printf '%s' "$CONFIG_JSON" | jq --arg name "$PLUGIN_NAME" \
    '[.plugins[]? | select(.name == $name)] | length')

  if [ "$LOAD_PLUGINS_COUNT" -eq 0 ] && [ "$PLUGINS_ENTRIES_COUNT" -eq 0 ]; then
    cat <<EOF
{
  "status": "success",
  "message": "file present with no entry for $PLUGIN_NAME",
  "namespace": "$NAMESPACE",
  "falco_name": "$FALCO_NAME",
  "pod": "$POD",
  "file_path": "$FILE_PATH",
  "plugin_name": "$PLUGIN_NAME",
  "config": $(printf '%s' "$CONFIG_JSON" | jq '.'),
  "retry_attempt": $ATTEMPT,
  "max_retries": $MAX_RETRIES
}
EOF
    exit 0
  fi

  LAST_ERROR="$PLUGIN_NAME still present: load_plugins count=$LOAD_PLUGINS_COUNT, plugins[] count=$PLUGINS_ENTRIES_COUNT"
  sleep "$RETRY_DELAY"
done

cat <<EOF
{
  "status": "failure",
  "message": "$LAST_ERROR after $MAX_RETRIES attempts",
  "namespace": "$NAMESPACE",
  "falco_name": "$FALCO_NAME",
  "pod": "$POD",
  "file_path": "$FILE_PATH",
  "plugin_name": "$PLUGIN_NAME",
  "config": $(printf '%s' "${CONFIG_JSON:-null}" | jq '.' 2>/dev/null || echo null),
  "retry_attempt": $MAX_RETRIES,
  "max_retries": $MAX_RETRIES
}
EOF
exit 1
