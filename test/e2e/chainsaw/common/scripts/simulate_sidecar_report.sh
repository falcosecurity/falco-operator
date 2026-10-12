#!/usr/bin/env bash
# Simulate the artifact operator of one node reporting on the artifacts assigned to it, on a node where no real
# artifact operator runs (a KWOK-simulated fake node). It writes the status of the node's ArtifactNode, which in
# production only the artifact operator on that node does.
#
# For every artifact of the given kinds that the node's spec lists, the status gets an entry carrying the
# artifact's uid (an entry of another uid is ignored by the parent aggregation) and the given conditions. Entries
# of other kinds are left as they are. With WITHDRAW=true the entries of the given kinds are removed instead, as
# the artifact operator does once it has removed an artifact's files.
#
# Env vars:
#   NAMESPACE:   Namespace of the ArtifactNode.
#   NODE_NAME:   Name of the node, which is also the name of its ArtifactNode.
#   KINDS:       Comma-separated artifact kinds to report on, e.g. "Plugin,Rulesfile,Config".
#   CONDITIONS:  Comma-separated Type:Status:Reason triples, e.g. "Programmed:True:SimulatedHealthy". Optional
#                when WITHDRAW=true.
#   MESSAGE:     Message written into every condition (default "Simulated by the e2e test"). Tests asserting
#                on an aggregated condition's message set a per-scenario value here, since the parent
#                aggregate propagates the per-node condition message verbatim.
#   GENERATION:  observedGeneration of the conditions (default 1).
#   WITHDRAW:    "true" removes the entries instead of writing them (default false).
set -o errexit
set -o nounset
set -o pipefail

NAMESPACE="${NAMESPACE}"
NODE_NAME="${NODE_NAME}"
KINDS="${KINDS}"
CONDITIONS="${CONDITIONS:-}"
MESSAGE="${MESSAGE:-Simulated by the e2e test}"
GENERATION="${GENERATION:-1}"
WITHDRAW="${WITHDRAW:-false}"

RESOURCE="artifactnodes.artifact.falcosecurity.dev"

conditions_json=$(printf '%s' "${CONDITIONS}" | jq -R --argjson generation "${GENERATION}" --arg message "${MESSAGE}" '
  if . == "" then []
  else split(",") | map(split(":") | {
    type: .[0], status: .[1], reason: .[2], message: $message,
    observedGeneration: $generation, lastTransitionTime: "2024-01-01T00:00:00Z"
  })
  end')
# jq -R on empty input (WITHDRAW=true leaves CONDITIONS unset) emits nothing; --argjson below
# needs valid JSON even then.
conditions_json="${conditions_json:-[]}"

node_json=$(kubectl get "${RESOURCE}" "${NODE_NAME}" -n "${NAMESPACE}" -o json)

patch=$(jq -n --argjson node "${node_json}" --argjson conditions "${conditions_json}" \
  --arg kinds "${KINDS}" --arg withdraw "${WITHDRAW}" '
  ($kinds | split(",")) as $wanted |
  ($node.status.artifacts // [] | map(select(.kind as $k | ($wanted | index($k)) | not))) as $kept |
  (if $withdraw == "true" then []
   else ($node.spec.artifacts // [] | map(select(.kind as $k | $wanted | index($k))) | map({kind, name, uid, conditions: $conditions}))
   end) as $reported |
  {status: {artifacts: ($kept + $reported)}}')

# A report on nothing would leave the assertions that follow it looking at whatever was there before.
if [ "${WITHDRAW}" != "true" ] && [ "$(jq -n --argjson node "${node_json}" --arg kinds "${KINDS}" \
  '($kinds | split(",")) as $wanted | [$node.spec.artifacts // [] | .[] | select(.kind as $k | $wanted | index($k))] | length')" -eq 0 ]; then
  echo "${RESOURCE}/${NODE_NAME} lists no artifact of kinds ${KINDS}: nothing to report on" >&2
  exit 1
fi

kubectl patch "${RESOURCE}" "${NODE_NAME}" -n "${NAMESPACE}" --subresource=status --type=merge -p "${patch}"
