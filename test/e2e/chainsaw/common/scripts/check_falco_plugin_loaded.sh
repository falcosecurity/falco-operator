#!/usr/bin/env bash
# Verify a plugin is reported as loaded by Falco's REST API (http://localhost:8765/versions,
# under the nested plugin_versions object). Queried via the netshoot container, which shares
# the pod's network namespace with falco and has curl/jq available.
# Env vars:
#   NAMESPACE:   Namespace of the Falco pod.
#   FALCO_NAME:  Value of app.kubernetes.io/name label on the Falco pod.
#   PLUGIN_NAME: Plugin name expected under plugin_versions (e.g. "container").
# Optional env vars:
#   EXPECTED_PLUGIN_VERSION: Exact version to wait for. Default: any loaded version.
#   ABSENT_PLUGINS: JSON array of plugins that must be absent from the same snapshot.
#                   Default: [] (no absence check).
set -o errexit
set -o nounset
set -o pipefail

NAMESPACE="${NAMESPACE}"
FALCO_NAME="${FALCO_NAME}"
PLUGIN_NAME="${PLUGIN_NAME}"
EXPECTED_PLUGIN_VERSION="${EXPECTED_PLUGIN_VERSION:-}"
ABSENT_PLUGINS="${ABSENT_PLUGINS:-[]}"

MAX_RETRIES="${MAX_RETRIES:-200}"
RETRY_DELAY="${RETRY_DELAY:-1}"

LAST_ERROR="no attempts made"
POD=""

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

  if ! VERSIONS=$(kubectl exec -n "$NAMESPACE" "$POD" -c netshoot -- \
      curl -sS -m 5 http://localhost:8765/versions 2>&1); then
    LAST_ERROR="kubectl exec/curl failed: $VERSIONS"
    sleep "$RETRY_DELAY"
    continue
  fi

  if PLUGIN_VERSION=$(printf '%s' "$VERSIONS" | jq -er \
      --arg name "$PLUGIN_NAME" --arg expected "$EXPECTED_PLUGIN_VERSION" --argjson absent "$ABSENT_PLUGINS" '
        .plugin_versions as $plugins |
        $plugins[$name] |
        select(($expected == "" or . == $expected) and
          all($absent[]; . as $name | $plugins | has($name) | not))
      ' 2>&1); then
    cat <<EOF
{
  "status": "success",
  "message": "Plugin reported as loaded by Falco",
  "namespace": "$NAMESPACE",
  "falco_name": "$FALCO_NAME",
  "pod": "$POD",
  "plugin_name": "$PLUGIN_NAME",
  "plugin_version": $(printf '%s' "$PLUGIN_VERSION" | jq -Rs .),
  "retry_attempt": $ATTEMPT,
  "max_retries": $MAX_RETRIES
}
EOF
    exit 0
  fi
  LAST_ERROR="expected '$PLUGIN_NAME' (version '${EXPECTED_PLUGIN_VERSION:-any}') loaded and $ABSENT_PLUGINS absent; got: $VERSIONS"
  sleep "$RETRY_DELAY"
done

cat <<EOF
{
  "status": "failure",
  "message": "Plugin checks did not succeed after $MAX_RETRIES attempts",
  "namespace": "$NAMESPACE",
  "falco_name": "$FALCO_NAME",
  "pod": "$POD",
  "plugin_name": "$PLUGIN_NAME",
  "plugin_version": null,
  "last_error": $(printf '%s' "$LAST_ERROR" | jq -Rs .),
  "retry_attempt": $MAX_RETRIES,
  "max_retries": $MAX_RETRIES
}
EOF
exit 1
