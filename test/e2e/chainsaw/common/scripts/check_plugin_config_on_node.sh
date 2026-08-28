#!/usr/bin/env bash
# Verify a plugin's entry in the shared plugins-config file is structurally correct:
#   - the plugin name appears in load_plugins exactly once
#   - there is exactly one entry under plugins: with name == PLUGIN_NAME
#   - if EXPECTED_INIT_CONFIG is set, that entry's init_config deep-equals it
#   - if EXPECTED_OPEN_PARAMS is set, that entry's open_params string-equals it
# Parses the file as YAML (via yq) rather than grepping text, so it can't be fooled by
# other plugins' entries sharing substrings, and catches duplicates/missing entries precisely.
# Env vars:
#   NAMESPACE:            Namespace of the Falco pod.
#   FALCO_NAME:           Value of app.kubernetes.io/name label on the Falco pod.
#   FILE_PATH:            Exact path to the plugins-config file, e.g.
#                         /etc/falco/config.d/99-03-plugins-config-inline.yaml.
#   PLUGIN_NAME:          Plugin name expected in load_plugins and plugins[].name.
#   EXPECTED_INIT_CONFIG: JSON object the plugin's init_config must deep-equal. Optional;
#                         if unset, init_config is not checked.
#   EXPECTED_OPEN_PARAMS: String the plugin's open_params must equal. Optional;
#                         if unset, open_params is not checked.
set -o errexit
set -o nounset
set -o pipefail

NAMESPACE="${NAMESPACE}"
FALCO_NAME="${FALCO_NAME}"
FILE_PATH="${FILE_PATH}"
PLUGIN_NAME="${PLUGIN_NAME}"
EXPECTED_INIT_CONFIG="${EXPECTED_INIT_CONFIG:-}"
EXPECTED_OPEN_PARAMS="${EXPECTED_OPEN_PARAMS:-}"

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
    LAST_ERROR="kubectl exec failed: $CONTENT"
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
  PLUGINS_ENTRIES=$(printf '%s' "$CONFIG_JSON" | jq --arg name "$PLUGIN_NAME" \
    '[.plugins[]? | select(.name == $name)]')
  PLUGINS_ENTRIES_COUNT=$(printf '%s' "$PLUGINS_ENTRIES" | jq 'length')

  FAILURE_REASON=""
  if [ "$LOAD_PLUGINS_COUNT" -ne 1 ]; then
    FAILURE_REASON="load_plugins contains '$PLUGIN_NAME' $LOAD_PLUGINS_COUNT times, expected exactly 1"
  elif [ "$PLUGINS_ENTRIES_COUNT" -ne 1 ]; then
    FAILURE_REASON="plugins: contains $PLUGINS_ENTRIES_COUNT entries with name == '$PLUGIN_NAME', expected exactly 1"
  else
    if [ -n "$EXPECTED_INIT_CONFIG" ]; then
      INIT_CONFIG_MATCHES=$(printf '%s' "$PLUGINS_ENTRIES" | jq --argjson expected "$EXPECTED_INIT_CONFIG" \
        '(.[0].init_config // {}) == $expected')
      if [ "$INIT_CONFIG_MATCHES" != "true" ]; then
        ACTUAL_INIT_CONFIG=$(printf '%s' "$PLUGINS_ENTRIES" | jq -c '.[0].init_config // {}')
        FAILURE_REASON="init_config mismatch: expected $EXPECTED_INIT_CONFIG, got $ACTUAL_INIT_CONFIG"
      fi
    fi
    if [ -z "$FAILURE_REASON" ] && [ -n "$EXPECTED_OPEN_PARAMS" ]; then
      OPEN_PARAMS_MATCHES=$(printf '%s' "$PLUGINS_ENTRIES" | jq --arg expected "$EXPECTED_OPEN_PARAMS" \
        '(.[0].open_params // "") == $expected')
      if [ "$OPEN_PARAMS_MATCHES" != "true" ]; then
        ACTUAL_OPEN_PARAMS=$(printf '%s' "$PLUGINS_ENTRIES" | jq -r '.[0].open_params // ""')
        FAILURE_REASON="open_params mismatch: expected '$EXPECTED_OPEN_PARAMS', got '$ACTUAL_OPEN_PARAMS'"
      fi
    fi
  fi

  if [ -z "$FAILURE_REASON" ]; then
    cat <<EOF
{
  "status": "success",
  "message": "Plugin config entry is structurally correct",
  "namespace": "$NAMESPACE",
  "falco_name": "$FALCO_NAME",
  "pod": "$POD",
  "file_path": "$FILE_PATH",
  "plugin_name": "$PLUGIN_NAME",
  "plugin_entry": $(printf '%s' "$PLUGINS_ENTRIES" | jq '.[0]'),
  "config": $(printf '%s' "$CONFIG_JSON" | jq '.'),
  "retry_attempt": $ATTEMPT,
  "max_retries": $MAX_RETRIES
}
EOF
    exit 0
  fi
  LAST_ERROR="$FAILURE_REASON"
  sleep "$RETRY_DELAY"
done

cat <<EOF
{
  "status": "failure",
  "message": "Plugin config entry was not structurally correct after $MAX_RETRIES attempts",
  "namespace": "$NAMESPACE",
  "falco_name": "$FALCO_NAME",
  "pod": "$POD",
  "file_path": "$FILE_PATH",
  "plugin_name": "$PLUGIN_NAME",
  "config": $(printf '%s' "${CONFIG_JSON:-null}" | jq '.' 2>/dev/null || echo null),
  "last_error": $(printf '%s' "$LAST_ERROR" | jq -Rs .),
  "retry_attempt": $MAX_RETRIES,
  "max_retries": $MAX_RETRIES
}
EOF
exit 1
