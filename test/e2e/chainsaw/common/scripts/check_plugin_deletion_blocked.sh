#!/usr/bin/env bash
# Verify that deleting a Plugin referenced by a Rulesfile stays blocked by the
# artifact.falcosecurity.dev/node-objects-in-use finalizer. That finalizer only
# clears once every owned ArtifactNode is actually gone, and each ArtifactNode's
# own per-node artifact operator refuses to remove itself while a Rulesfile on
# that node still structurally depends on the plugin (nodeartifacts.Manager),
# so this finalizer staying put is the real, authoritative signal that deletion
# is blocked, not a name specific to "blocked by a rulesfile".
#
# Issues the delete request (no --wait), waits for the deletionTimestamp +
# finalizer to appear, then polls for HOLD_SECONDS confirming the Plugin object
# persists. Any disappearance of the object within the window is a failure.
#
# Env vars:
#   NAMESPACE:    Namespace of the Plugin.
#   PLUGIN_NAME:  Name of the Plugin CR.
#   HOLD_SECONDS: How long the object must persist after deletion is confirmed blocked (default 10).
set -o errexit
set -o nounset
set -o pipefail

NAMESPACE="${NAMESPACE}"
PLUGIN_NAME="${PLUGIN_NAME}"
HOLD_SECONDS="${HOLD_SECONDS:-10}"

RESOURCE="plugins.artifact.falcosecurity.dev"
FINALIZER="artifact.falcosecurity.dev/node-objects-in-use"

fail() {
  local msg="$1" elapsed="${2:-0}"
  cat <<EOF
{
  "status": "failure",
  "message": "Plugin deletion was not blocked by the finalizer",
  "namespace": "${NAMESPACE}",
  "plugin_name": "${PLUGIN_NAME}",
  "finalizer": "${FINALIZER}",
  "hold_seconds": ${HOLD_SECONDS},
  "seconds_elapsed": ${elapsed},
  "last_error": $(printf '%s' "${msg}" | jq -Rs .)
}
EOF
  exit 1
}

# Send the delete request without waiting for completion.
if ! DELETE_OUTPUT=$(kubectl delete "${RESOURCE}" "${PLUGIN_NAME}" -n "${NAMESPACE}" --wait=false 2>&1); then
  fail "kubectl delete failed for Plugin ${PLUGIN_NAME}: ${DELETE_OUTPUT}"
fi

# Wait up to 15s for the API server to stamp deletionTimestamp and the
# controller to re-assert the finalizer. This avoids a race where the first
# hold-window poll runs before the server has written the timestamp.
WAIT_TIMEOUT=15
for i in $(seq 1 "${WAIT_TIMEOUT}"); do
  if ! PLUGIN_JSON=$(kubectl get "${RESOURCE}" "${PLUGIN_NAME}" -n "${NAMESPACE}" -o json 2>/dev/null); then
    fail "Plugin ${PLUGIN_NAME} disappeared ${i}s after the delete request; the finalizer did not block deletion." "$i"
  fi

  if printf '%s' "${PLUGIN_JSON}" | jq -e --arg f "${FINALIZER}" '
      .metadata.deletionTimestamp != null and
      ((.metadata.finalizers // []) | index($f) != null)' >/dev/null; then
    break
  fi

  if [ "${i}" -eq "${WAIT_TIMEOUT}" ]; then
    fail "Plugin ${PLUGIN_NAME} never got a deletionTimestamp+finalizer within ${WAIT_TIMEOUT}s after delete." "${i}"
  fi
  sleep 1
done

# Hold window: verify the object stays blocked for HOLD_SECONDS.
for i in $(seq 1 "${HOLD_SECONDS}"); do
  if ! PLUGIN_JSON=$(kubectl get "${RESOURCE}" "${PLUGIN_NAME}" -n "${NAMESPACE}" -o json 2>/dev/null); then
    fail "Plugin ${PLUGIN_NAME} disappeared ${i}s into the hold window; the finalizer was unexpectedly removed." "$i"
  fi

  if ! printf '%s' "${PLUGIN_JSON}" | jq -e --arg f "${FINALIZER}" '
      .metadata.deletionTimestamp != null and
      ((.metadata.finalizers // []) | index($f) != null)' >/dev/null; then
    fail "Plugin ${PLUGIN_NAME} lost its deletionTimestamp or finalizer ${i}s into the hold window." "$i"
  fi

  sleep 1
done

cat <<EOF
{
  "status": "success",
  "message": "Plugin deletion blocked by finalizer",
  "namespace": "${NAMESPACE}",
  "plugin_name": "${PLUGIN_NAME}",
  "finalizer": "${FINALIZER}",
  "hold_seconds": ${HOLD_SECONDS}
}
EOF
