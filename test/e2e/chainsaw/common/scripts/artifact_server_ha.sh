#!/usr/bin/env bash
# Dedicated, opt-in fixture for artifact-server-ha. Never restores over a changed
# Deployment or mutates the Service. The backup survives individual Chainsaw steps.
set -o errexit
set -o nounset
set -o pipefail

if [ "${CHAINSAW_ENABLE_HA_TEST:-}" != "true" ]; then
  echo "artifact-server-ha requires CHAINSAW_ENABLE_HA_TEST=true" >&2
  exit 1
fi

NAMESPACE="${NAMESPACE}"
ACTION="${ACTION}"
OPERATOR_NAMESPACE="${OPERATOR_NAMESPACE:-falco-operator}"
OPERATOR_NAME="${OPERATOR_NAME:-falco-operator}"
SERVICE_NAME="${OPERATOR_SERVICE_NAME:-$OPERATOR_NAME}"
MAX_RETRIES="${MAX_RETRIES:-90}"
RETRY_DELAY="${RETRY_DELAY:-1}"
BACKUP_NAME=artifact-server-ha-backup
PROBE_NAME=artifact-server-ha-probe
RULESFILE_NAME=artifact-server-ha-rules
LEASE_NAME=1d54f32f.falcosecurity.dev
SERVING_LABEL=artifact.falcosecurity.dev/serving
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
WORK_DIR=$(mktemp -d)
DEADLINE=$((SECONDS + 240))
trap 'rm -f "$WORK_DIR"/*; rmdir "$WORK_DIR"' EXIT

kube() {
  kubectl --request-timeout=10s "$@"
}

fail() {
  echo "$*" >&2
  exit 1
}

retry_pause() {
  [ "$SECONDS" -lt "$DEADLINE" ] || fail "HA fixture action timed out"
  sleep "$RETRY_DELAY"
}

load_backup() {
  kube get configmap -n "$NAMESPACE" "$BACKUP_NAME" -o json > "$WORK_DIR/backup.json"
  jq -er '.data.snapshot' "$WORK_DIR/backup.json" > "$WORK_DIR/snapshot.json"
  SELECTOR=$(jq -r '.selector' "$WORK_DIR/snapshot.json")
}

wait_for_deployment() {
  local replicas=$1
  for _ in $(seq 1 "$MAX_RETRIES"); do
    kube get deployment -n "$OPERATOR_NAMESPACE" "$OPERATOR_NAME" -o json > "$WORK_DIR/deployment.json"
    if jq -e --argjson replicas "$replicas" '
      .status.observedGeneration == .metadata.generation and
      .status.replicas == $replicas and .status.updatedReplicas == $replicas and
      .status.readyReplicas == $replicas and .status.availableReplicas == $replicas
    ' "$WORK_DIR/deployment.json" > /dev/null; then
      return
    fi
    retry_pause
  done
  fail "operator Deployment did not converge to $replicas Ready replicas"
}

prepare() {
  wait_for_deployment 1
  kube get deployment -n "$OPERATOR_NAMESPACE" "$OPERATOR_NAME" -o json > "$WORK_DIR/original.json"
  jq -e '.spec.replicas == 1 and
    ([.spec.template.spec.containers[] | select(.name == "manager")] | length) == 1 and
    ([.spec.template.spec.containers[] | select(.name == "artifact-ha-control")] | length) == 0
  ' "$WORK_DIR/original.json" > /dev/null || fail "HA fixture requires a single-replica operator Deployment without its observer"
  kube get service -n "$OPERATOR_NAMESPACE" "$SERVICE_NAME" -o json > "$WORK_DIR/service.json"
  jq -e --arg label "$SERVING_LABEL" '.spec.selector[$label] == "true"' \
    "$WORK_DIR/service.json" > /dev/null || fail "artifact Service lacks its serving selector"

  jq '
    (.spec.template.spec.containers[] | select(.name == "manager") |
      .securityContext.runAsUser) as $managerUID |
    .spec.replicas = 2 |
    .spec.template.spec.shareProcessNamespace = true |
    (.spec.template.spec.containers[] | select(.name == "manager")) |=
      (.args = ((.args // [] | map(select(test("^--leader-elect(=|$)") | not))) +
        ["--leader-elect=true"]) | del(.livenessProbe)) |
    .spec.template.spec.containers += [{
      name: "artifact-ha-control", image: "nicolaka/netshoot",
      command: ["sleep", "infinity"],
      securityContext: {
        runAsUser: ($managerUID // .spec.template.spec.securityContext.runAsUser // 65532),
        runAsNonRoot: true, allowPrivilegeEscalation: false,
        capabilities: {drop: ["ALL"]}
      }
    }] |
    [
      {op: "test", path: "/metadata/uid", value: .metadata.uid},
      {op: "test", path: "/metadata/resourceVersion", value: .metadata.resourceVersion},
      {op: "replace", path: "/spec", value: .spec}
    ]
  ' "$WORK_DIR/original.json" > "$WORK_DIR/patch.json"
  kube patch deployment -n "$OPERATOR_NAMESPACE" "$OPERATOR_NAME" --type=json \
    --patch-file "$WORK_DIR/patch.json" --dry-run=server -o json > "$WORK_DIR/prepared.json"
  jq -n --slurpfile original "$WORK_DIR/original.json" \
    --slurpfile prepared "$WORK_DIR/prepared.json" --slurpfile service "$WORK_DIR/service.json" '{
      uid: $original[0].metadata.uid,
      original: $original[0].spec,
      prepared: $prepared[0].spec,
      serviceUID: $service[0].metadata.uid,
      port: ($service[0].spec.ports[] | select(.name == "artifact-server") | .port),
      tls: ([$original[0].spec.template.spec.containers[] | select(.name == "manager") |
        .args[] | select(startswith("--artifact-server-client-ca-file"))] | length > 0),
      selector: ($original[0].spec.selector.matchLabels | to_entries |
        map(.key + "=" + .value) | join(","))
    }' > "$WORK_DIR/snapshot.json"
  kube create configmap -n "$NAMESPACE" "$BACKUP_NAME" \
    --from-file=snapshot="$WORK_DIR/snapshot.json" > /dev/null
  kube patch deployment -n "$OPERATOR_NAMESPACE" "$OPERATOR_NAME" --type=json \
    --patch-file "$WORK_DIR/patch.json" > /dev/null
  wait_for_deployment 2
}

# Refresh every observation. A transport error is an error, never proof that a
# follower or stale endpoint disappeared.
observe() {
  kube get pods -n "$OPERATOR_NAMESPACE" -l "$SELECTOR" -o json > "$WORK_DIR/pods.json"
  kube get lease -n "$OPERATOR_NAMESPACE" "$LEASE_NAME" -o json > "$WORK_DIR/lease.json"
  kube get service -n "$OPERATOR_NAMESPACE" "$SERVICE_NAME" -o json > "$WORK_DIR/service.json"
  jq -e --slurpfile snapshot "$WORK_DIR/snapshot.json" --arg label "$SERVING_LABEL" '
    .metadata.uid == $snapshot[0].serviceUID and .spec.selector[$label] == "true"
  ' "$WORK_DIR/service.json" > /dev/null || fail "artifact Service changed during the HA test"
  kube get endpointslices -n "$OPERATOR_NAMESPACE" \
    -l "kubernetes.io/service-name=$SERVICE_NAME" -o json > "$WORK_DIR/endpoints.json"
}

routing_matches() {
  local both_ready=$1 expected_leader=${2:-}
  jq -e --arg label "$SERVING_LABEL" --arg expected "$expected_leader" \
    --argjson bothReady "$both_ready" --slurpfile lease "$WORK_DIR/lease.json" \
    --slurpfile endpoints "$WORK_DIR/endpoints.json" '
    [.items[] | select(.metadata.deletionTimestamp == null)] as $pods |
    [$pods[] | select(.metadata.labels[$label] == "true")] as $serving |
    [$endpoints[0].items[].endpoints[] | select(.conditions.ready == true) |
      .targetRef.uid] | unique as $targets |
    ($pods | length) == 2 and ($serving | length) == 1 and
    ($expected == "" or $serving[0].metadata.name == $expected) and
    ($lease[0].spec.holderIdentity | startswith($serving[0].metadata.name + "_")) and
    $targets == [$serving[0].metadata.uid] and
    (if $bothReady then all($pods[];
      any(.status.conditions[]; .type == "Ready" and .status == "True")) else true end)
  ' "$WORK_DIR/pods.json" > /dev/null
}

wait_for_routing() {
  local both_ready=$1 expected_leader=${2:-}
  for _ in $(seq 1 "$MAX_RETRIES"); do
    observe
    if routing_matches "$both_ready" "$expected_leader"; then
      return
    fi
    retry_pause
  done
  fail "Service endpoints, serving labels and leader Lease did not converge"
}

read_digest() {
  kube get rulesfile -n "$NAMESPACE" "$RULESFILE_NAME" -o json |
    jq -er '.status.artifactMeta.digest | select(length > 0)'
}

check_download() {
  local digest=$1 port scheme=http
  local tls_args=()
  port=$(jq -r '.port' "$WORK_DIR/snapshot.json")
  if jq -e '.tls' "$WORK_DIR/snapshot.json" > /dev/null; then
    scheme=https
    tls_args=(--cacert /etc/artifact-client/ca.crt --cert /etc/artifact-client/tls.crt --key /etc/artifact-client/tls.key)
  fi
  # Match how push-artifacts.sh constructs this existing OCI fixture.
  printf '%s\n' "$(cat "$SCRIPT_DIR/../../../../../.github/e2e/oci-artifacts/fixtures/rule-basic.yaml")" > "$WORK_DIR/expected"
  for _ in $(seq 1 "$MAX_RETRIES"); do
    if kube exec -n "$NAMESPACE" "$PROBE_NAME" -c netshoot -- curl --fail --silent --show-error --max-time 5 \
      ${tls_args[@]+"${tls_args[@]}"} \
      "$scheme://$SERVICE_NAME.$OPERATOR_NAMESPACE.svc.cluster.local:$port/v1/artifacts/rulesfiles/$NAMESPACE/$RULESFILE_NAME?digest=$digest" \
      > "$WORK_DIR/download"; then
      cmp -s "$WORK_DIR/expected" "$WORK_DIR/download" || fail "Service returned different rulesfile content"
      return
    fi
    retry_pause
  done
  fail "artifact download through the Service did not recover"
}

failover() {
  wait_for_routing true
  local digest leader follower uid count pid
  digest=$(read_digest)
  check_download "$digest"
  leader=$(jq -r --arg label "$SERVING_LABEL" '.items[] | select(.metadata.deletionTimestamp == null and .metadata.labels[$label] == "true") | .metadata.name' "$WORK_DIR/pods.json")
  follower=$(jq -r --arg leader "$leader" '.items[] | select(.metadata.deletionTimestamp == null and .metadata.name != $leader) | .metadata.name' "$WORK_DIR/pods.json")
  uid=$(jq -r --arg leader "$leader" '.items[] | select(.metadata.name == $leader) | .metadata.uid' "$WORK_DIR/pods.json")
  count=$(jq -r --arg leader "$leader" '.items[] | select(.metadata.name == $leader) |
    .status.containerStatuses[] | select(.name == "manager") | .restartCount' "$WORK_DIR/pods.json")
  pid=$(kube exec -n "$OPERATOR_NAMESPACE" "$leader" -c artifact-ha-control -- pgrep -x manager)
  [[ "$pid" =~ ^[0-9]+$ ]] || fail "expected exactly one manager process"
  jq -n --arg pod "$leader" --arg uid "$uid" --arg pid "$pid" \
    '{data: {stopped: ({pod: $pod, uid: $uid, pid: $pid} | tojson)}}' > "$WORK_DIR/stopped.json"
  kube patch configmap -n "$NAMESPACE" "$BACKUP_NAME" --type=merge --patch-file "$WORK_DIR/stopped.json" > /dev/null
  kube exec -n "$OPERATOR_NAMESPACE" "$leader" -c artifact-ha-control -- sh -c 'kill -STOP "$1"' sh "$pid"
  wait_for_routing false "$follower"
  check_download "$digest"
  kube get pod -n "$OPERATOR_NAMESPACE" "$leader" -o json |
    jq -e --arg uid "$uid" '.metadata.uid == $uid' > /dev/null || fail "old leader Pod was replaced"
  kube exec -n "$OPERATOR_NAMESPACE" "$leader" -c artifact-ha-control -- sh -c 'kill -KILL "$1"' sh "$pid"
  for _ in $(seq 1 "$MAX_RETRIES"); do
    observe
    jq -e --arg pod "$leader" --arg uid "$uid" '
      any(.items[]; .metadata.name == $pod and .metadata.uid == $uid)
    ' "$WORK_DIR/pods.json" > /dev/null || fail "old leader Pod was replaced"
    if routing_matches true "$follower" && jq -e --arg pod "$leader" --argjson count "$count" '
      .items[] | select(.metadata.name == $pod) | .status.containerStatuses[] |
      select(.name == "manager") | .restartCount > $count and .ready
    ' "$WORK_DIR/pods.json" > /dev/null; then
      check_download "$digest"
      jq -n --arg leader "$follower" --arg restarted "$leader" --arg uid "$uid" --arg digest "$digest" \
        '{status: "success", leader: $leader, restarted_pod: $restarted, restarted_uid: $uid, digest: $digest}'
      return
    fi
    retry_pause
  done
  fail "old leader did not restart as a Ready follower in the same Pod"
}

restore() {
  kube get configmap -n "$NAMESPACE" "$BACKUP_NAME" --ignore-not-found -o json > "$WORK_DIR/backup.json"
  [ -s "$WORK_DIR/backup.json" ] || return 0
  jq -er '.data.snapshot' "$WORK_DIR/backup.json" > "$WORK_DIR/snapshot.json"
  if jq -e '.data.stopped' "$WORK_DIR/backup.json" > /dev/null; then
    local pod uid pid
    pod=$(jq -r '.data.stopped | fromjson | .pod' "$WORK_DIR/backup.json")
    uid=$(jq -r '.data.stopped | fromjson | .uid' "$WORK_DIR/backup.json")
    pid=$(jq -r '.data.stopped | fromjson | .pid' "$WORK_DIR/backup.json")
    kube get pod -n "$OPERATOR_NAMESPACE" "$pod" --ignore-not-found -o json > "$WORK_DIR/stopped-pod.json"
    if [ -s "$WORK_DIR/stopped-pod.json" ] && jq -e --arg uid "$uid" '.metadata.uid == $uid' "$WORK_DIR/stopped-pod.json" > /dev/null; then
      kube exec -n "$OPERATOR_NAMESPACE" "$pod" -c artifact-ha-control -- \
        sh -c 'if [ -d "/proc/$1" ]; then kill -CONT "$1"; fi' sh "$pid"
    fi
  fi
  for _ in $(seq 1 5); do
    kube get deployment -n "$OPERATOR_NAMESPACE" "$OPERATOR_NAME" -o json > "$WORK_DIR/current.json"
    jq -e --slurpfile snapshot "$WORK_DIR/snapshot.json" \
      '.metadata.uid == $snapshot[0].uid' "$WORK_DIR/current.json" > /dev/null || fail "refusing to restore a replacement Deployment"
    if jq -e --slurpfile snapshot "$WORK_DIR/snapshot.json" \
      '.spec == $snapshot[0].original' "$WORK_DIR/current.json" > /dev/null; then
      wait_for_deployment 1
      return
    fi
    jq -e --slurpfile snapshot "$WORK_DIR/snapshot.json" \
      '.spec == $snapshot[0].prepared' "$WORK_DIR/current.json" > /dev/null || fail "refusing to overwrite a concurrent Deployment spec change"
    jq --slurpfile snapshot "$WORK_DIR/snapshot.json" '[
      {op: "test", path: "/metadata/uid", value: .metadata.uid},
      {op: "test", path: "/metadata/resourceVersion", value: .metadata.resourceVersion},
      {op: "test", path: "/spec", value: .spec},
      {op: "replace", path: "/spec", value: $snapshot[0].original}
    ]' "$WORK_DIR/current.json" > "$WORK_DIR/restore.json"
    if kube patch deployment -n "$OPERATOR_NAMESPACE" "$OPERATOR_NAME" --type=json \
      --patch-file "$WORK_DIR/restore.json" > /dev/null; then
      wait_for_deployment 1
      return
    fi
    retry_pause
  done
  fail "could not restore the operator Deployment after concurrent API updates"
}

case "$ACTION" in
  guard) ;;
  prepare) prepare ;;
  verify)
    load_backup
    wait_for_routing true
    check_download "$(read_digest)"
    ;;
  failover)
    load_backup
    failover
    ;;
  restore) restore ;;
  *) fail "unknown HA fixture action: $ACTION" ;;
esac
