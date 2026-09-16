#!/usr/bin/env bash
# Print a resource's current UID as JSON, for binding into a later step via chainsaw's
# `outputs:` (see rulesfile-inline-plugin-dep-alternatives for the $stdout/json_parse pattern).
# Used to capture a "before" UID so a later step can confirm an object was actually deleted and
# recreated (a new UID under the same name), not merely that an object with an acceptable shape
# exists at that name.
# Env vars:
#   NAMESPACE: Namespace of the resource. Omit for cluster-scoped resources.
#   RESOURCE:  Resource type, e.g. "artifactnodes.artifact.falcosecurity.dev".
#   NAME:      Resource name. Use either NAME or SELECTOR, never both.
#   SELECTOR:  Label selector resolving to exactly one resource. Returns its actual name.
#   MAX_RETRIES: Default: 200.
#   RETRY_DELAY: Seconds between polls. Default: 1.
set -o errexit
set -o nounset
set -o pipefail

RESOURCE="${RESOURCE}"
NAME="${NAME:-}"
SELECTOR="${SELECTOR:-}"
NAMESPACE="${NAMESPACE:-}"
MAX_RETRIES="${MAX_RETRIES:-200}"
RETRY_DELAY="${RETRY_DELAY:-1}"

if [ -n "$NAME" ] && [ -z "$SELECTOR" ]; then
  LOOKUP_ARGS=("$NAME")
elif [ -n "$SELECTOR" ] && [ -z "$NAME" ]; then
  LOOKUP_ARGS=(-l "$SELECTOR")
else
  jq -n '{status: "failure", message: "provide exactly one of NAME or SELECTOR"}'
  exit 1
fi

NAMESPACE_ARGS=()
if [ -n "$NAMESPACE" ]; then
  NAMESPACE_ARGS=(-n "$NAMESPACE")
fi

LAST_ERROR="no attempts made"

for ATTEMPT in $(seq 1 "$MAX_RETRIES"); do
  if RESOURCE_JSON=$(kubectl get "$RESOURCE" "${LOOKUP_ARGS[@]}" "${NAMESPACE_ARGS[@]}" -o json 2>&1); then
    if [ -n "$SELECTOR" ]; then
      if ! RESOURCE_JSON=$(printf '%s' "$RESOURCE_JSON" | jq -ce '
        if (.items | length) == 1 then .items[0]
        else error("expected exactly one matching resource, got \(.items | length)") end
      ' 2>&1); then
        LAST_ERROR="selector lookup failed: $RESOURCE_JSON"
        sleep "$RETRY_DELAY"
        continue
      fi
    fi
    if IDENTITY=$(printf '%s' "$RESOURCE_JSON" | jq -ce '
      {name: .metadata.name, uid: .metadata.uid} |
      select((.name | type) == "string" and (.name | length) > 0 and
             (.uid | type) == "string" and (.uid | length) > 0)
    ' 2>&1); then
      jq -n --arg resource "$RESOURCE" --arg namespace "$NAMESPACE" --argjson identity "$IDENTITY" \
        --argjson attempt "$ATTEMPT" --argjson max_retries "$MAX_RETRIES" \
        '$identity + {status: "success", resource: $resource, namespace: $namespace,
          retry_attempt: $attempt, max_retries: $max_retries}'
      exit 0
    fi
    LAST_ERROR="resource did not contain a valid name and UID: $IDENTITY"
  else
    LAST_ERROR="kubectl get failed: $RESOURCE_JSON"
  fi
  sleep "$RETRY_DELAY"
done

cat <<EOF
{
  "status": "failure",
  "message": "unable to get resource UID after $MAX_RETRIES attempts",
  "resource": "$RESOURCE",
  "name": "$NAME",
  "selector": $(printf '%s' "$SELECTOR" | jq -Rs .),
  "namespace": "$NAMESPACE",
  "last_error": $(printf '%s' "$LAST_ERROR" | jq -Rs .),
  "retry_attempt": $MAX_RETRIES,
  "max_retries": $MAX_RETRIES
}
EOF
exit 1
