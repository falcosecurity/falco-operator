#!/usr/bin/env bash
# Takes the artifact-operator sidecar container down and keeps it down for a while, IN PLACE (same Pod, same
# UID, same emptyDir-backed volumes), so that a test can change the cluster behind the sidecar's back. What
# the sidecar then finds on restart is what any sidecar finds after an outage during which the cluster moved
# on: an ArtifactNode that is gone, an artifact deleted and recreated under the same name, and so on.
#
# kubelet restarts a killed container at once the first time, then holds it back in CrashLoopBackOff for a
# growing delay (10s, then 20s, ...). The process is killed, and killed again once it is back, until kubelet
# reports that state with at least MIN_REMAINING seconds of the back-off left: the caller has that long to act
# in, and it can check that the container is still waiting once it is done (see the tests using this).
#
# What is left is computed, not read: kubelet reports the back-off late, often most of the way through it, so
# a status saying "back-off 20s" may mean a restart one second later. The back-off runs from the moment the
# killed container finished, which the status records, so the restart is due at finishedAt + back-off. The caller waits for the
# sidecar to be back with wait_artifact_operator_ready.sh.
#
# Success is judged on the very container that was killed: its ID is read from the killed process's cgroup
# and must be the last terminated container while kubelet reports CrashLoopBackOff. The pod status lags
# behind the kills, by 10s and more: right after a kill it can still show the back-off of an earlier
# container, from before that came back and was killed again, and taking that as success would leave the
# caller with a container that is merely terminated.
#
# After a kill the script therefore waits as long as it takes for kubelet to report what it did with the
# killed container, and kills again only once kubelet has restarted it. Killing a container that has just
# come back from a back-off must be avoided: kubelet then tends to leave it reported as terminated for its
# whole next back-off, never as CrashLoopBackOff, which is the state the callers check.
#
# Like restart_artifact_operator_container.sh, this relies on apply-assert-falco.yaml's shareProcessNamespace
# and its netshoot sidecar to signal the artifact-operator process, "manager", from another container.
#
# Env vars:
#   NAMESPACE:   Namespace of the Falco pod.
#   FALCO_NAME:  Value of app.kubernetes.io/name label on the Falco pod.
#   MAX_KILLS:   How many times to kill the process before giving up. Default: 6.
#   TIMEOUT:     Seconds to wait for kubelet to report on one killed container. Default: 90.
#   MIN_REMAINING: Seconds of back-off the caller must be left with. Default: 5. The second kill usually
#                leaves about 13s: kubelet reports its 10s back-off within a couple of seconds. Later back-offs
#                (20s, 40s, ...) tend to be reported only just before the restart, so asking for much more than
#                the second kill gives mostly buys further kills, each waiting out a longer back-off.
set -o errexit
set -o nounset
set -o pipefail

NAMESPACE="${NAMESPACE}"
FALCO_NAME="${FALCO_NAME}"
MAX_KILLS="${MAX_KILLS:-6}"
TIMEOUT="${TIMEOUT:-90}"
MIN_REMAINING="${MIN_REMAINING:-5}"

POD=$(kubectl get pods -n "$NAMESPACE" -l "app.kubernetes.io/name=$FALCO_NAME" \
  -o jsonpath='{.items[0].metadata.name}')
if [ -z "$POD" ]; then
  echo "no pod found for app.kubernetes.io/name=$FALCO_NAME in $NAMESPACE" >&2
  exit 1
fi

# container_state prints the artifact-operator container's state and the ID of its last terminated container,
# read together so that they come from one version of the pod status:
# "<running since>|<waiting reason>|<waiting message>|<last terminated container ID>|<last terminated at>".
container_state() {
  kubectl get pod -n "$NAMESPACE" "$POD" -o jsonpath='{range .status.containerStatuses[?(@.name=="artifact-operator")]}{.state.running.startedAt}{"|"}{.state.waiting.reason}{"|"}{.state.waiting.message}{"|"}{.lastState.terminated.containerID}{"|"}{.lastState.terminated.finishedAt}{end}' 2>/dev/null || true
}

# backoff_seconds prints the back-off kubelet announces in a CrashLoopBackOff message ("back-off 20s restarting
# failed container=..."), in seconds, and 0 when there is none. kubelet writes it as a Go duration: "10s", "1m20s".
backoff_seconds() {
  local duration minutes=0 seconds=0
  duration=$(printf '%s' "$1" | sed -n 's/^back-off \([0-9ms]*\) .*/\1/p')
  case "$duration" in
    *m*s) minutes=${duration%%m*}; seconds=${duration#*m}; seconds=${seconds%s} ;;
    *m) minutes=${duration%m} ;;
    *s) seconds=${duration%s} ;;
  esac
  echo $((minutes * 60 + seconds))
}

WAITING_REASON=""
for KILL in $(seq 1 "$MAX_KILLS"); do
  # Kill the process once it is there: right after a kill, kubelet may not have restarted it yet. The ID of
  # its container is printed first, from its cgroup (".../docker-<id>.scope", ".../cri-containerd-<id>.scope").
  KILLED_ID=""
  for _ in $(seq 1 60); do
    if KILLED_ID=$(kubectl exec -n "$NAMESPACE" "$POD" -c netshoot -- sh -c \
      'pid=$(pgrep -xo manager) && [ -n "$pid" ] && id=$(grep -oE "[0-9a-f]{64}" /proc/$pid/cgroup | tail -n 1) && [ -n "$id" ] && kill -KILL $pid && echo $id' \
      2>/dev/null) && [ -n "$KILLED_ID" ]; then
      break
    fi
    KILLED_ID=""
    sleep 0.5
  done
  if [ -z "$KILLED_ID" ]; then
    echo "unable to find and signal the artifact-operator process from netshoot" >&2
    exit 1
  fi
  # kubelet either restarts the container right away (the first time) or holds it back. Either way the
  # killed container becomes the last terminated one; which of the two happened is then in the state.
  DEADLINE=$((SECONDS + TIMEOUT))
  RESTARTED=0
  while [ "$SECONDS" -lt "$DEADLINE" ]; do
    IFS='|' read -r RUNNING WAITING_REASON WAITING_MESSAGE LAST_ID FINISHED_AT <<<"$(container_state)"
    if [ "${LAST_ID##*/}" = "$KILLED_ID" ]; then
      BACKOFF=$(backoff_seconds "$WAITING_MESSAGE")
      REMAINING=0
      if [ -n "$FINISHED_AT" ]; then
        REMAINING=$(($(date -d "$FINISHED_AT" +%s) + BACKOFF - $(date +%s)))
      fi
      if [ "$WAITING_REASON" = "CrashLoopBackOff" ] && [ "$REMAINING" -ge "$MIN_REMAINING" ]; then
        cat <<EOJ
{
  "status": "success",
  "message": "artifact-operator container is down and held back by kubelet",
  "namespace": "$NAMESPACE",
  "pod": "$POD",
  "waiting_reason": "$WAITING_REASON",
  "backoff_seconds": $BACKOFF,
  "remaining_seconds": $REMAINING,
  "kills": $KILL
}
EOJ
        exit 0
      fi
      if [ -n "$RUNNING" ]; then
        # Restarted, after no back-off or with too little of it left when reported: kill it again.
        RESTARTED=1
        break
      fi
    fi
    sleep 0.5
  done
  if [ "$RESTARTED" -ne 1 ]; then
    echo "kubelet did not report on the killed artifact-operator container within ${TIMEOUT}s" >&2
    break
  fi
done

cat <<EOJ
{
  "status": "failure",
  "message": "kubelet did not hold the artifact-operator container back after $MAX_KILLS kills",
  "namespace": "$NAMESPACE",
  "pod": "$POD",
  "waiting_reason": "$WAITING_REASON"
}
EOJ
exit 1
