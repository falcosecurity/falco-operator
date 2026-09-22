#!/usr/bin/env bash
# Controlled cache endpoint for the download-timeout test. Runs in the existing
# netshoot container; only this test's sidecar uses it. No registry or TLS proxying.
# Local control: NAMESPACE, FALCO_NAME and ACTION=start|arm|started|cancelled|recover|status.
# Install this script and the two OCI fixture files under /tmp before starting it.
set -o errexit
set -o nounset
set -o pipefail

case "${1:-control}" in
  serve)
    exec socat TCP-LISTEN:18082,bind=127.0.0.1,reuseaddr,fork \
      EXEC:'bash /tmp/artifact-download-server.sh handle',pipes
    ;;
  handle)
    read -r method target protocol
    while IFS= read -r header && [ "$header" != $'\r' ]; do :; done
    if [ "$target" = /ready ]; then
      printf 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK'
      exit 0
    fi
    digest="${target##*digest=}"
    digest="${digest//%3A/:}"
    digest="${digest//%3a/:}"
    if [ "$method" != GET ] || [[ ! "$digest" =~ ^sha256:[a-f0-9]{64}$ ]]; then
      printf 'HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
      exit 0
    fi
    mode=$(cat /tmp/artifact-download-mode)
    file=/tmp/artifact-download-old.yaml
    if [ "$mode" != initial ]; then file=/tmp/artifact-download-new.yaml; fi
    length=$(wc -c < "$file")
    printf 'HTTP/1.1 200 OK\r\nX-Artifact-Digest: %s\r\nContent-Length: %s\r\nConnection: close\r\n\r\n' "$digest" "$length"
    if [ "$mode" = stalled ]; then
      head -c 3 "$file"
      touch /tmp/artifact-download-started
      # Wait for client cancellation, never for an arbitrary sleep to expire.
      cat >/dev/null
      touch /tmp/artifact-download-cancelled
    else
      cat "$file"
    fi
    exit 0
    ;;
  start)
    if ! curl --fail --silent --max-time 1 http://127.0.0.1:18082/ready >/dev/null; then
      printf initial >/tmp/artifact-download-mode
      nohup bash /tmp/artifact-download-server.sh serve >/tmp/artifact-download-server.log 2>&1 </dev/null &
    fi
    curl --fail --silent --max-time 1 http://127.0.0.1:18082/ready >/dev/null
    exit 0
    ;;
  arm)
    printf stalled >/tmp/artifact-download-mode
    exit 0
    ;;
  started)
    test -f /tmp/artifact-download-started
    exit 0
    ;;
  cancelled)
    test -f /tmp/artifact-download-cancelled
    exit 0
    ;;
  recover)
    printf recovered >/tmp/artifact-download-mode
    exit 0
    ;;
  status)
    curl --fail --silent --max-time 1 http://127.0.0.1:18082/ready >/dev/null
    exit 0
    ;;
  control) ;;
  *) echo "unknown action" >&2; exit 1 ;;
esac

case "${ACTION:?}" in start|arm|started|cancelled|recover|status) ;; *) exit 1 ;; esac
last_error="no attempt made"
for attempt in $(seq 1 "${MAX_RETRIES:-120}"); do
  if pods=$(kubectl get pods -n "${NAMESPACE:?}" -l "app.kubernetes.io/name=${FALCO_NAME:?}" -o json 2>&1) &&
      identities=$(printf '%s' "$pods" | jq -ce '[.items[] | {name: .metadata.name, uid: .metadata.uid}] | sort_by(.name) | select(length > 0)'); then
    succeeded=true
    for pod in $(printf '%s' "$identities" | jq -r '.[].name'); do
      if ! last_error=$(kubectl exec -n "$NAMESPACE" "$pod" -c netshoot -- \
          bash /tmp/artifact-download-server.sh "$ACTION" 2>&1); then
        succeeded=false
        break
      fi
    done
    if [ "$succeeded" = true ]; then
      jq -n --arg action "$ACTION" --argjson pods "$identities" '{action: $action, pods: $pods}'
      exit 0
    fi
  else
    last_error="$pods"
  fi
  sleep "${RETRY_DELAY:-1}"
done
printf '%s\n' "$last_error" >&2
exit 1
