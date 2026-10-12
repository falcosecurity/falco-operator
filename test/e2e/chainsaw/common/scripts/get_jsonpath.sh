#!/usr/bin/env bash
# Print one field of a resource, raw, for binding into a later step via chainsaw's `outputs:` or for a
# `check:` on $stdout.
# Env vars:
#   RESOURCE:  Resource type, e.g. "artifactnodes.artifact.falcosecurity.dev".
#   NAME:      Resource name. Use either NAME or SELECTOR.
#   SELECTOR:  Label selector. The JSONPath then applies to the list, e.g. "{.items[0].metadata.uid}".
#   NAMESPACE: Namespace of the resource. Omit for cluster-scoped resources.
#   JSONPATH:  JSONPath expression, e.g. "{.metadata.uid}".
set -o errexit
set -o nounset
set -o pipefail

args=("${RESOURCE}")
[ -n "${NAME:-}" ] && args+=("${NAME}")
[ -n "${SELECTOR:-}" ] && args+=(-l "${SELECTOR}")
[ -n "${NAMESPACE:-}" ] && args+=(-n "${NAMESPACE}")

kubectl get "${args[@]}" -o jsonpath="${JSONPATH}"
