#!/usr/bin/env bash
# Apply a JSON patch (RFC 6902) to a resource, for the changes a chainsaw `patch:` step, which merges, cannot
# express, such as removing a field.
# Env vars:
#   RESOURCE:  Resource type, e.g. "configs.artifact.falcosecurity.dev".
#   NAME:      Resource name.
#   NAMESPACE: Namespace of the resource.
#   PATCH:     The JSON patch, e.g. '[{"op": "remove", "path": "/spec/selector"}]'.
set -o errexit
set -o nounset
set -o pipefail

kubectl patch "${RESOURCE}" "${NAME}" -n "${NAMESPACE}" --type=json -p "${PATCH}"
