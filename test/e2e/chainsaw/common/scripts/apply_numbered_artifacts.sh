#!/usr/bin/env bash
# Create a numbered series of minimal artifacts, for the tests that need many of them at once.
# Env vars:
#   NAMESPACE: Namespace of the artifacts.
#   KIND:      "Rulesfile" (one inline rule, selecting the nodes labelled chainsaw-node-group=$NAMESPACE) or
#              "Config" (one inline setting, no selector).
#   PREFIX:    Name prefix; the number follows it.
#   FIRST:     First number of the series.
#   LAST:      Last number of the series. Numbers are zero-padded to its width.
set -o errexit
set -o nounset
set -o pipefail

for i in $(seq -w "${FIRST}" "${LAST}"); do
  case "${KIND}" in
    Rulesfile)
      cat <<YAML
---
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: Rulesfile
metadata:
  name: ${PREFIX}${i}
  namespace: ${NAMESPACE}
spec:
  selector:
    matchLabels:
      chainsaw-node-group: ${NAMESPACE}
  inlineRules:
    - rule: Chainsaw capacity rule ${i}
      desc: Rule used to fill an ArtifactNode.
      condition: "evt.type = execve"
      output: "process=%proc.cmdline marker=capacity-${i}"
      priority: DEBUG
      tags: [test]
YAML
      ;;
    Config)
      cat <<YAML
---
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: Config
metadata:
  name: ${PREFIX}${i}
  namespace: ${NAMESPACE}
spec:
  config:
    json_output: false
YAML
      ;;
    *)
      echo "unsupported KIND ${KIND}" >&2
      exit 1
      ;;
  esac
done | kubectl apply -f -
