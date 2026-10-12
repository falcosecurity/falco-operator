#!/usr/bin/env bash
# Deletes a resource the way an operator in a hurry does: finalizers stripped, so that nothing holds it, and the
# deletion waited for. The controllers that would have cleaned up behind the finalizers never get to: a test uses
# this to leave behind exactly what such a deletion leaves behind (installed files, a stale status entry) and see
# how the operator recovers from it.
#
# The deletion is requested first and the finalizers stripped after. The other way round races with the
# controllers: one that still sees a live object puts its finalizer back before the deletion is requested, and
# the deletion then waits for that controller's cleanup after all. Once the object is being deleted, the API
# server refuses any new finalizer, so stripping them then is final.
#
# Env vars:
#   RESOURCE:  Resource type, e.g. "plugins.artifact.falcosecurity.dev".
#   NAMESPACE: Namespace of the resource.
#   NAME:      Resource name. Give either NAME or ALL.
#   ALL:       "true" to delete every resource of the type in the namespace.
set -o errexit
set -o nounset
set -o pipefail

RESOURCE="${RESOURCE}"
NAMESPACE="${NAMESPACE}"
NAME="${NAME:-}"
ALL="${ALL:-false}"

NAMES=()
if [ -n "$NAME" ] && [ "$ALL" != "true" ]; then
  NAMES=("$NAME")
elif [ -z "$NAME" ] && [ "$ALL" = "true" ]; then
  if ! LISTED=$(kubectl get "$RESOURCE" -n "$NAMESPACE" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>&1); then
    jq -n --arg resource "$RESOURCE" --arg error "$LISTED" \
      '{status: "failure", message: "unable to list", resource: $resource, error: $error}'
    exit 1
  fi
  while IFS= read -r ITEM; do
    if [ -n "$ITEM" ]; then NAMES+=("$ITEM"); fi
  done <<<"$LISTED"
else
  jq -n '{status: "failure", message: "provide exactly one of NAME or ALL=true"}'
  exit 1
fi

fail() {
  jq -n --arg resource "$RESOURCE" --arg name "$1" --arg message "$2" --arg error "$3" \
    '{status: "failure", message: $message, resource: $resource, name: $name, error: $error}'
  exit 1
}

for ITEM in "${NAMES[@]}"; do
  # A resource that is already gone is fine at every step: only the outcome matters.
  if ! OUTPUT=$(kubectl delete "$RESOURCE" "$ITEM" -n "$NAMESPACE" --ignore-not-found --wait=false 2>&1); then
    fail "$ITEM" "unable to request deletion" "$OUTPUT"
  fi
  if ! OUTPUT=$(kubectl patch "$RESOURCE" "$ITEM" -n "$NAMESPACE" --type=merge -p '{"metadata":{"finalizers":null}}' 2>&1); then
    printf '%s' "$OUTPUT" | grep -q "NotFound" || fail "$ITEM" "unable to strip finalizers" "$OUTPUT"
  fi
  if ! OUTPUT=$(kubectl wait "$RESOURCE/$ITEM" -n "$NAMESPACE" --for=delete --timeout=60s 2>&1); then
    printf '%s' "$OUTPUT" | grep -q "NotFound" || fail "$ITEM" "deletion did not complete" "$OUTPUT"
  fi
done

if [ "${#NAMES[@]}" -eq 0 ]; then
  NAMES_JSON='[]'
else
  NAMES_JSON=$(printf '%s\n' "${NAMES[@]}" | jq -R . | jq -s .)
fi
jq -n --arg resource "$RESOURCE" --arg namespace "$NAMESPACE" --argjson names "$NAMES_JSON" \
  '{status: "success", message: "deleted with finalizers stripped", resource: $resource, namespace: $namespace, names: $names}'
