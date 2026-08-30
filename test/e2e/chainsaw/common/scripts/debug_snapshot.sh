#!/usr/bin/env bash
# Capture a debug snapshot of the test and operator namespaces when a test fails.
#
# Variables (from environment):
#   TEST_NAME:         Name of the test (for labeling output sections).
#   NAMESPACE:         Primary test namespace to capture.
#   OPERATOR_NAMESPACE: Namespace where the falco-operator runs. Default: falco-operator.
#   OUTPUT_DIR:        Directory for debug output. Default: /tmp/chainsaw.
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

capture() {
  local name="$1"
  shift
  local file="$SNAPSHOT_DIR/$name.log"
  echo "=== $name (saved to $file) ==="
  "$@" >"$file" 2>&1 || true
}

# capture_container_logs dumps logs for one container name from every pod in a
# namespace that has it. Unlike capture(), it can't rely on a label selector:
# the Falco DaemonSet pod's only stable labels are app.kubernetes.io/name and
# app.kubernetes.io/instance, both set to the per-test Falco CR name (which
# this script is never given), and "artifact-operator"/"falco" are sidecar
# containers *within* that pod, not standalone deployments, so there is no
# label that identifies them across arbitrary test namespaces.
capture_container_logs() {
  local name="$1" namespace="$2" container="$3"
  local file="$SNAPSHOT_DIR/$name.log"
  echo "=== $name (saved to $file) ==="
  : >"$file"
  local pod
  for pod in $(kubectl get pods -n "$namespace" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
    if kubectl get pod "$pod" -n "$namespace" -o jsonpath='{.spec.containers[*].name}' 2>/dev/null | grep -qw "$container"; then
      {
        echo "--- pod: $pod container: $container ---"
        kubectl logs -n "$namespace" "$pod" -c "$container"
      } >>"$file" 2>&1 || true
    fi
  done
}

capture falco-crs kubectl get falco,rulesfiles,plugins,configs,artifactnodes -n "$NAMESPACE" -o wide
capture falco kubectl get falco -n "$NAMESPACE" -o yaml
capture rulesfiles kubectl get rulesfiles -n "$NAMESPACE" -o yaml
capture plugins kubectl get plugins -n "$NAMESPACE" -o yaml
capture artifactnodes kubectl get artifactnodes -n "$NAMESPACE" -o yaml
capture daemonsets kubectl get daemonsets -n "$NAMESPACE" -o yaml
capture deployments kubectl get deployments -n "$NAMESPACE" -o yaml
capture controllerrevisions kubectl get controllerrevisions -n "$NAMESPACE" -o yaml
capture pods kubectl get pods -n "$NAMESPACE" -o wide
capture pods-describe kubectl describe pods -n "$NAMESPACE"
# Cluster-scoped, covers real and KWOK-simulated fake nodes. Tells us whether KWOK ever
# finished staging a fake Node (see apply-fake-node.yaml).
capture nodes kubectl get nodes -o wide
capture nodes-describe kubectl describe nodes
# KWOK's own controller log. Absent if KWOK isn't installed for this test category.
capture kwok-controller-logs kubectl logs -n kube-system -l app=kwok-controller --tail=200
capture operator-pods kubectl get pods -n "$OPERATOR_NAMESPACE" -o wide
# The instance-operator ("manager" container) is the single Deployment in
# OPERATOR_NAMESPACE; control-plane=falco-operator is a hardcoded pod-template
# label (see chart/falco-operator/templates/deployment.yaml), not derived from
# the Helm release name, so it's stable regardless of how the chart was installed.
capture instance-operator-logs kubectl logs -n "$OPERATOR_NAMESPACE" -l control-plane=falco-operator
# artifact-operator is a sidecar inside the Falco DaemonSet pod(s) in NAMESPACE,
# not a separate deployment in OPERATOR_NAMESPACE.
capture_container_logs artifact-operator-logs "$NAMESPACE" artifact-operator
capture_container_logs falco-pod-logs "$NAMESPACE" falco
# mock-falco-versions only exists in tests using apply-assert-falco-mock-versions.yaml; a no-op
# elsewhere. busybox httpd (-f, foreground) logs each request by default, so this shows whether
# the artifact-operator's polls are even reaching it and what it's serving.
capture_container_logs mock-falco-versions-logs "$NAMESPACE" mock-falco-versions
capture events kubectl get events -n "$NAMESPACE" --sort-by=.lastTimestamp
# Per-kind event slices: the combined "events" capture above is dominated by pod/DaemonSet
# noise, which buries the handful of Rulesfile/Plugin/Config/ArtifactNode events (e.g.
# DependenciesNotSatisfied, OCIArtifactStored) that actually explain a reconcile decision.
capture rulesfiles-events kubectl get events -n "$NAMESPACE" --field-selector involvedObject.kind=Rulesfile --sort-by=.lastTimestamp
capture plugins-events kubectl get events -n "$NAMESPACE" --field-selector involvedObject.kind=Plugin --sort-by=.lastTimestamp
capture configs-events kubectl get events -n "$NAMESPACE" --field-selector involvedObject.kind=Config --sort-by=.lastTimestamp
capture artifactnodes-events kubectl get events -n "$NAMESPACE" --field-selector involvedObject.kind=ArtifactNode --sort-by=.lastTimestamp
capture operator-events kubectl get events -n "$OPERATOR_NAMESPACE" --sort-by=.lastTimestamp

echo "Debug snapshot saved to $SNAPSHOT_DIR"
