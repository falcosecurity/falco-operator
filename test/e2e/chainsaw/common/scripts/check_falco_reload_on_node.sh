#!/usr/bin/env bash
# Observe Falco 0.44.1's reload epoch through /metrics in the netshoot container.
# A changed epoch proves a new Falco run, not which watcher initiated it or every
# artifact that run loaded. Optional rules name/hash checks use the same snapshot.
# Required env vars: NAMESPACE, FALCO_NAME.
# MODE: capture (default), wait (different epoch), or hold (unchanged epoch).
# wait requires BASELINE_EPOCH and POD_UID from a capture in the same Chainsaw step.
# RULE_FILE_NAME and RULE_SHA256: optional pair that must be loaded throughout the check.
# MAX_RETRIES / RETRY_DELAY: capture and wait bounds (defaults: 180 / 1 second).
# SETTLE_SECONDS / HOLD_SECONDS: hold waits for pending setup reloads, then requires
# continuous successful observations with one epoch (defaults: 75 / 130 seconds).
# A Pod replacement or a failed observation during hold is an error, never success.
set -o errexit
set -o nounset
set -o pipefail

NAMESPACE="${NAMESPACE}"
FALCO_NAME="${FALCO_NAME}"
MODE="${MODE:-capture}"
BASELINE_EPOCH="${BASELINE_EPOCH:-}"
POD_UID="${POD_UID:-}"
RULE_FILE_NAME="${RULE_FILE_NAME:-}"
RULE_SHA256="${RULE_SHA256:-}"
MAX_RETRIES="${MAX_RETRIES:-180}"
RETRY_DELAY="${RETRY_DELAY:-1}"
SETTLE_SECONDS="${SETTLE_SECONDS:-75}"
HOLD_SECONDS="${HOLD_SECONDS:-130}"
POD=""
EPOCH=""
LAST_ERROR="no attempts made"

fail() {
  jq -n --arg message "$1" --arg pod "$POD" --arg uid "$POD_UID" --arg epoch "$EPOCH" \
    '{status: "failure", message: $message, pod: $pod, pod_uid: $uid, epoch: $epoch}'
  exit 1
}

case "$MODE" in
  capture|hold) ;;
  wait)
    if [ -z "$BASELINE_EPOCH" ] || [ -z "$POD_UID" ]; then
      fail "wait requires BASELINE_EPOCH and POD_UID"
    fi
    ;;
  *) fail "MODE must be capture, wait, or hold" ;;
esac
if { [ -n "$RULE_FILE_NAME" ] && [ -z "$RULE_SHA256" ]; } || \
   { [ -z "$RULE_FILE_NAME" ] && [ -n "$RULE_SHA256" ]; }; then
  fail "provide both RULE_FILE_NAME and RULE_SHA256"
fi
if ! [[ "$MAX_RETRIES" =~ ^[1-9][0-9]*$ && "$HOLD_SECONDS" =~ ^[1-9][0-9]*$ &&
        "$SETTLE_SECONDS" =~ ^[0-9]+$ && "$RETRY_DELAY" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  fail "invalid retry or observation duration"
fi

observe() {
  local pods identity observed_uid metrics
  if ! pods=$(kubectl get pods -n "$NAMESPACE" -l "app.kubernetes.io/name=$FALCO_NAME" -o json 2>&1); then
    LAST_ERROR="kubectl get pods failed: $pods"
    return 1
  fi
  if ! identity=$(printf '%s' "$pods" | jq -cer '
    select((.items | length) == 1) | .items[0].metadata |
    select((.name | type) == "string" and (.name | length) > 0 and
           (.uid | type) == "string" and (.uid | length) > 0) | [.name, .uid] | @tsv
  ' 2>&1); then
    LAST_ERROR="expected exactly one pod with a valid name and UID: $identity"
    return 1
  fi
  IFS=$'\t' read -r POD observed_uid <<< "$identity"
  if [ -n "$POD_UID" ] && [ "$observed_uid" != "$POD_UID" ]; then
    fail "pod UID changed from $POD_UID to $observed_uid; replacement is not a Falco reload"
  fi
  POD_UID="$observed_uid"
  if ! metrics=$(kubectl exec -n "$NAMESPACE" "$POD" -c netshoot -- \
      curl -fsS -m 5 http://localhost:8765/metrics 2>&1); then
    LAST_ERROR="kubectl exec/curl failed: $metrics"
    return 1
  fi
  if ! EPOCH=$(printf '%s\n' "$metrics" | awk '
    $1 == "#" && $2 == "TYPE" && $3 == "falcosecurity_falco_reload_timestamp_nanoseconds" {
      types++
      gauge = ($4 == "gauge")
    }
    $1 == "falcosecurity_falco_reload_timestamp_nanoseconds" {
      count++
      if (NF == 2 && $2 ~ /^[0-9]+([.][0-9]+)?([eE][+-]?[0-9]+)?$/ && $2 + 0 > 0) value = $2
    }
    END {
      if (types != 1 || !gauge || count != 1 || value == "") exit 1
      printf "%.0f\n", value
    }
  '); then
    LAST_ERROR="metrics did not contain one valid reload timestamp gauge"
    return 1
  fi
  if ! [[ "$EPOCH" =~ ^[1-9][0-9]*$ ]]; then
    LAST_ERROR="reload timestamp is not finite and positive: $EPOCH"
    return 1
  fi
  if [ -n "$RULE_FILE_NAME" ] && ! printf '%s\n' "$metrics" | awk \
      -v name="$RULE_FILE_NAME" -v hash="$RULE_SHA256" '
        index($1, "falcosecurity_falco_sha256_rules_files_info{") == 1 &&
        index($1, "file_name=\"" name "\"") && index($1, "sha256=\"" hash "\"") && $2 == 1 { found = 1 }
        END { exit !found }
      '; then
    LAST_ERROR="rules metric does not contain $RULE_FILE_NAME with hash $RULE_SHA256"
    return 1
  fi
}

if [ "$MODE" == hold ]; then
  sleep "$SETTLE_SECONDS"
  observe || fail "$LAST_ERROR"
  BASELINE_EPOCH="$EPOCH"
  HOLD_START=$SECONDS
  while [ "$((SECONDS - HOLD_START))" -lt "$HOLD_SECONDS" ]; do
    sleep "$RETRY_DELAY"
    observe || fail "$LAST_ERROR"
    if [ "$EPOCH" != "$BASELINE_EPOCH" ]; then
      fail "Falco reloaded without a new write: epoch changed from $BASELINE_EPOCH to $EPOCH"
    fi
  done
else
  MATCHED=false
  for ATTEMPT in $(seq 1 "$MAX_RETRIES"); do
    if observe; then
      if [ "$MODE" == capture ] || [ "$EPOCH" != "$BASELINE_EPOCH" ]; then
        MATCHED=true
        break
      fi
      LAST_ERROR="Falco still reports baseline epoch $BASELINE_EPOCH"
    fi
    sleep "$RETRY_DELAY"
  done
  if [ "$MATCHED" != true ]; then
    fail "$LAST_ERROR"
  fi
fi

jq -n --arg mode "$MODE" --arg pod "$POD" --arg uid "$POD_UID" --arg epoch "$EPOCH" \
  --arg rule "$RULE_FILE_NAME" --arg hash "$RULE_SHA256" --arg hold "$HOLD_SECONDS" \
  '{status: "success", mode: $mode, pod: $pod, pod_uid: $uid, epoch: $epoch,
    rule_file_name: $rule, rule_sha256: $hash, hold_seconds: $hold}'
