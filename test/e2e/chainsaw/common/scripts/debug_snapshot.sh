#!/usr/bin/env bash
# Capture a debug snapshot of the test and operator namespaces when a test fails.
#
# Variables (from environment):
#   TEST_NAME:         Name of the test (for labeling output sections).
#   NAMESPACE:         Primary test namespace to capture.
#   OPERATOR_NAMESPACE: Namespace where the falco-operator runs. Default: falco-operator.
#   OUTPUT_DIR:        Directory for debug output. Default: /tmp/chainsaw.
#
# Layout of a snapshot:
#   <name>.yaml                        resources dumped with -o yaml
#   <name>.txt                         tables, `kubectl describe` and events
#   logs/<app>/<pod>@<node>.<container>.log
#                                      full container logs, one file per pod and container; <node>
#                                      is the node the pod runs on ("unscheduled" if it has none)
#   logs/<app>/<pod>@<node>.<container>.previous.log
#                                      logs of the previous (crashed/restarted) container, if any
set -o errexit
set -o nounset
set -o pipefail

TEST_NAME="${TEST_NAME}"
NAMESPACE="${NAMESPACE}"
OPERATOR_NAMESPACE="${OPERATOR_NAMESPACE:-falco-operator}"
OUTPUT_DIR="${OUTPUT_DIR:-/tmp/chainsaw}"

# Timestamped so re-running the same test (e.g. chainsaw --repeat-count) doesn't
# overwrite an earlier failure's snapshot. Includes nanoseconds since repeats can
# land within the same second.
SNAPSHOT_DIR="$OUTPUT_DIR/$TEST_NAME/$(date -u +%Y%m%dT%H%M%S.%NZ)"
mkdir -p "$SNAPSHOT_DIR"

# capture runs a command and stores its combined output in $SNAPSHOT_DIR/<file>. The caller picks
# the extension: .yaml for `-o yaml` output, .txt for everything else that is not a log. Errors
# are kept in the file so a missing CRD or namespace shows up instead of an empty capture.
capture() {
  local file="$1"
  shift
  echo "=== $file (saved to $SNAPSHOT_DIR/$file) ==="
  "$@" >"$SNAPSHOT_DIR/$file" 2>&1 || true
}

# capture_pod_logs dumps the full logs of every container (init containers included) of every pod
# of one app into $SNAPSHOT_DIR/logs/<app>/, one file per pod and container. A pod's containers
# are listed from its spec rather than assumed, so sidecars are never missed: the Falco DaemonSet
# pod hosts "falco", "artifact-operator" and, in some tests, "mock-falco-versions", and its only
# stable labels are app.kubernetes.io/name and app.kubernetes.io/instance, both set to the
# per-test Falco CR name (which this script is never given). An empty selector therefore selects
# every pod in the namespace.
#
# Logs are always fetched with --tail=-1: kubectl defaults to the last 10 lines when a label
# selector is used, which is far too little to follow a reconcile. The previous container's log
# is kept only when one exists.
capture_pod_logs() {
  local app="$1" namespace="$2" selector="${3:-}"
  local dir="$SNAPSHOT_DIR/logs/$app"
  local -a selector_args=()
  if [[ -n "$selector" ]]; then
    selector_args=(-l "$selector")
  fi
  # One line per pod: "<pod>|<node>|<init containers...> <containers...>". "|" rather than
  # whitespace separates the first fields: a pod that is not scheduled yet has an empty node,
  # which whitespace splitting would collapse, shifting the containers into the node variable.
  local pod_containers='{range .items[*]}{.metadata.name}{"|"}{.spec.nodeName}{"|"}{.spec.initContainers[*].name}{" "}{.spec.containers[*].name}{"\n"}{end}'
  echo "=== $app logs (saved to $dir) ==="
  mkdir -p "$dir"

  local pod node containers container file
  while IFS='|' read -r pod node containers; do
    [[ -n "$pod" ]] || continue
    for container in $containers; do
      file="$dir/$pod@${node:-unscheduled}.$container"
      kubectl logs -n "$namespace" "$pod" -c "$container" --timestamps --tail=-1 \
        >"$file.log" 2>&1 || true
      kubectl logs -n "$namespace" "$pod" -c "$container" --timestamps --tail=-1 --previous \
        >"$file.previous.log" 2>/dev/null || rm -f "$file.previous.log"
    done
  done < <(kubectl get pods -n "$namespace" "${selector_args[@]}" -o jsonpath="$pod_containers" 2>/dev/null || true)
}

capture falco-crs.txt kubectl get falco,rulesfiles,plugins,configs,artifactnodes -n "$NAMESPACE" -o wide
capture falco.yaml kubectl get falco -n "$NAMESPACE" -o yaml
capture rulesfiles.yaml kubectl get rulesfiles -n "$NAMESPACE" -o yaml
capture plugins.yaml kubectl get plugins -n "$NAMESPACE" -o yaml
capture artifactnodes.yaml kubectl get artifactnodes -n "$NAMESPACE" -o yaml
capture daemonsets.yaml kubectl get daemonsets -n "$NAMESPACE" -o yaml
capture deployments.yaml kubectl get deployments -n "$NAMESPACE" -o yaml
capture controllerrevisions.yaml kubectl get controllerrevisions -n "$NAMESPACE" -o yaml
capture pods.txt kubectl get pods -n "$NAMESPACE" -o wide
capture pods-describe.txt kubectl describe pods -n "$NAMESPACE"
# Cluster-scoped, covers real and KWOK-simulated fake nodes. Tells us whether KWOK ever
# finished staging a fake Node (see apply-fake-node.yaml).
capture nodes.txt kubectl get nodes -o wide
capture nodes-describe.txt kubectl describe nodes
capture operator-pods.txt kubectl get pods -n "$OPERATOR_NAMESPACE" -o wide

# KWOK's own controller log. Absent if KWOK isn't installed for this test category.
capture_pod_logs kwok-controller kube-system app=kwok-controller
# The instance-operator ("manager" container) is the Deployment in OPERATOR_NAMESPACE, possibly
# with several replicas (leader election), and each replica's log matters.
# control-plane=falco-operator is a hardcoded pod-template label (see
# chart/falco-operator/templates/deployment.yaml), not derived from the Helm release name, so
# it's stable regardless of how the chart was installed.
capture_pod_logs instance-operator "$OPERATOR_NAMESPACE" control-plane=falco-operator
# Every pod of the test namespace: the Falco pods with their "falco" and "artifact-operator"
# sidecars (artifact-operator is not a separate deployment in OPERATOR_NAMESPACE) and, in tests
# using apply-assert-falco-mock-versions.yaml, "mock-falco-versions". busybox httpd (-f,
# foreground) logs each request by default, so that one shows whether the artifact-operator's
# polls are even reaching it and what it's serving.
capture_pod_logs test-pods "$NAMESPACE"

capture events.txt kubectl get events -n "$NAMESPACE" --sort-by=.lastTimestamp
# Per-kind event slices: the combined "events" capture above is dominated by pod/DaemonSet
# noise, which buries the handful of Rulesfile/Plugin/Config/ArtifactNode events (e.g.
# DependenciesNotSatisfied, OCIArtifactStored) that actually explain a reconcile decision.
capture rulesfiles-events.txt kubectl get events -n "$NAMESPACE" --field-selector involvedObject.kind=Rulesfile --sort-by=.lastTimestamp
capture plugins-events.txt kubectl get events -n "$NAMESPACE" --field-selector involvedObject.kind=Plugin --sort-by=.lastTimestamp
capture configs-events.txt kubectl get events -n "$NAMESPACE" --field-selector involvedObject.kind=Config --sort-by=.lastTimestamp
capture artifactnodes-events.txt kubectl get events -n "$NAMESPACE" --field-selector involvedObject.kind=ArtifactNode --sort-by=.lastTimestamp
capture operator-events.txt kubectl get events -n "$OPERATOR_NAMESPACE" --sort-by=.lastTimestamp

echo "Debug snapshot saved to $SNAPSHOT_DIR"
