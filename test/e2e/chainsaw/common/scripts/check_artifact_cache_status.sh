#!/usr/bin/env bash
# Verify the instance operator's artifact HTTP server reports a given plugin/rulesfile as
# cached (200) or not-yet/no-longer cached (503), curled directly from the test runner's own
# host, never via an in-cluster probe pod.
#
# Reaching the server: if ARTIFACT_SERVER_URL is set, it's used as-is: this is the escape
# hatch for the instance operator running OUTSIDE the cluster (e.g. via `make
# telepresence.connect`, where a locally-run operator is reachable straight from the host, or
# any other manually-arranged tunnel). If it's unset, this script port-forwards directly to the
# real instance-operator pod (found via its control-plane=falco-operator label) and curls
# through that tunnel instead, deliberately not the artifact-server Service: a Service's
# ClusterIP only has live endpoints when something backs it with a running Pod, which isn't
# guaranteed depending on how the operator is currently deployed, whereas a Pod-targeted
# port-forward only depends on the pod itself existing.
#
# mTLS: detected automatically from the operator pod's own container args
# (--artifact-server-client-ca-file present means the server requires client certs). When
# detected, this script needs a client identity the server's SPIFFE authorizer will accept
# (a cert alone, even CA-signed, isn't sufficient: see internal/pkg/artifactserver's
# Authorizer). It gets one by ensuring a small, otherwise-unused Falco CR exists in
# ARTIFACT_NAMESPACE (name: MTLS_TEST_FALCO_NAME, default below) purely so cert-manager issues
# it a per-instance client certificate, and reuses that Falco CR's Secret across every
# invocation in the same namespace (create-if-missing, no explicit cleanup here: it's cleaned
# up when the test's own namespace is torn down, same as every other resource these tests
# create). The Falco CR's DaemonSet/pod never needs to become Ready for this: the Certificate
# is issued independently of that.
#
# Env vars:
#   ARTIFACT_SERVER_URL: Optional. Base URL of an already-reachable artifact server
#                        (e.g. "http://localhost:8082"). Skips the port-forward entirely.
#   OPERATOR_NAMESPACE:  Namespace the instance operator pod runs in. Ignored if
#                        ARTIFACT_SERVER_URL is set.
#   ARTIFACT_TYPE:       "plugins" or "rulesfiles".
#   ARTIFACT_NAMESPACE:  Namespace of the Plugin/Rulesfile CR (the artifact server's {ns} path
#                        segment), also where the mTLS test identity Falco CR is created.
#   ARTIFACT_NAME:       Name of the Plugin/Rulesfile CR.
#   EXPECTED_STATUS:     HTTP status code to wait for (e.g. "200" once cached, "503" once evicted).
#   MTLS_TEST_FALCO_NAME: Optional. Name of the throwaway Falco CR used for the mTLS test
#                        identity (default: "artifact-cache-status-mtls-client"). Only used
#                        when mTLS is detected.
#   NODE_OS/NODE_ARCH:   Optional, plugins only. When both are set, used directly as the
#                        os/arch query params instead of auto-discovering them from the first
#                        `kubectl get nodes` entry, needed to target a specific node (e.g. a
#                        KWOK fake node) when the cluster has more than one architecture.
set -o errexit
set -o nounset
set -o pipefail

ARTIFACT_SERVER_URL="${ARTIFACT_SERVER_URL:-}"
OPERATOR_NAMESPACE="${OPERATOR_NAMESPACE:-falco-operator}"
ARTIFACT_TYPE="${ARTIFACT_TYPE}"
ARTIFACT_NAMESPACE="${ARTIFACT_NAMESPACE}"
ARTIFACT_NAME="${ARTIFACT_NAME}"
EXPECTED_STATUS="${EXPECTED_STATUS}"
MTLS_TEST_FALCO_NAME="${MTLS_TEST_FALCO_NAME:-artifact-cache-status-mtls-client}"

MAX_RETRIES="${MAX_RETRIES:-200}"
RETRY_DELAY="${RETRY_DELAY:-1}"

PF_PID=""
cleanup() {
  if [ -n "$PF_PID" ]; then
    kill "$PF_PID" >/dev/null 2>&1 || true
    wait "$PF_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

BASE_URL="$ARTIFACT_SERVER_URL"
OPERATOR_POD=""

if [ -z "$BASE_URL" ]; then
  OPERATOR_POD=$(kubectl get pods -n "$OPERATOR_NAMESPACE" -l control-plane=falco-operator \
    -o jsonpath='{.items[0].metadata.name}')
  if [ -z "$OPERATOR_POD" ]; then
    echo "no instance-operator pod found in namespace $OPERATOR_NAMESPACE (set ARTIFACT_SERVER_URL if it's running outside the cluster)" >&2
    exit 1
  fi

  PF_LOG=$(mktemp)
  kubectl port-forward -n "$OPERATOR_NAMESPACE" "pod/$OPERATOR_POD" :8082 >"$PF_LOG" 2>&1 &
  PF_PID=$!

  LOCAL_PORT=""
  for _ in $(seq 1 30); do
    LOCAL_PORT=$(grep -oE '127\.0\.0\.1:[0-9]+' "$PF_LOG" | head -1 | cut -d: -f2 || true)
    if [ -n "$LOCAL_PORT" ]; then
      break
    fi
    sleep 0.5
  done
  if [ -z "$LOCAL_PORT" ]; then
    echo "port-forward to pod/$OPERATOR_POD in $OPERATOR_NAMESPACE never became ready: $(cat "$PF_LOG")" >&2
    exit 1
  fi
fi

# mTLS detection + client identity setup. Only meaningful (and only attempted) when we're
# talking to a real, discoverable operator pod; ARTIFACT_SERVER_URL callers are expected to
# pass an already-TLS-appropriate URL and handle their own client auth, if any.
CURL_TLS_OPTS=()
SCHEME="http"

if [ -n "$OPERATOR_POD" ]; then
  OPERATOR_ARGS=$(kubectl get pod -n "$OPERATOR_NAMESPACE" "$OPERATOR_POD" \
    -o jsonpath='{.spec.containers[0].args}' 2>/dev/null || echo "")
  if echo "$OPERATOR_ARGS" | grep -q -- "--artifact-server-client-ca-file"; then
    SCHEME="https"
    CERT_SECRET_NAME="${MTLS_TEST_FALCO_NAME}-artifact-client-tls"

    if ! kubectl get falco "$MTLS_TEST_FALCO_NAME" -n "$ARTIFACT_NAMESPACE" >/dev/null 2>&1; then
      kubectl apply -f - <<EOF
apiVersion: instance.falcosecurity.dev/v1alpha1
kind: Falco
metadata:
  name: $MTLS_TEST_FALCO_NAME
  namespace: $ARTIFACT_NAMESPACE
spec: {}
EOF
    fi

    # kubectl wait --for=condition requires the resource to already exist; the Falco
    # controller needs its own reconcile cycle to create the Certificate, so poll for its
    # existence first rather than racing a `kubectl apply` that only just returned.
    for _ in $(seq 1 60); do
      if kubectl get certificate -n "$ARTIFACT_NAMESPACE" "$CERT_SECRET_NAME" >/dev/null 2>&1; then
        break
      fi
      sleep 1
    done
    kubectl wait -n "$ARTIFACT_NAMESPACE" "certificate/${CERT_SECRET_NAME}" \
      --for=condition=Ready --timeout=60s

    CERT_DIR=$(mktemp -d)
    kubectl get secret -n "$ARTIFACT_NAMESPACE" "$CERT_SECRET_NAME" -o jsonpath='{.data.tls\.crt}' | base64 -d > "$CERT_DIR/tls.crt"
    kubectl get secret -n "$ARTIFACT_NAMESPACE" "$CERT_SECRET_NAME" -o jsonpath='{.data.tls\.key}' | base64 -d > "$CERT_DIR/tls.key"
    kubectl get secret -n "$ARTIFACT_NAMESPACE" "$CERT_SECRET_NAME" -o jsonpath='{.data.ca\.crt}' | base64 -d > "$CERT_DIR/ca.crt"
    CURL_TLS_OPTS=(--cacert "$CERT_DIR/ca.crt" --cert "$CERT_DIR/tls.crt" --key "$CERT_DIR/tls.key")

    # The server's cert SAN is its Service DNS name (falco-operator.go's Certificate template),
    # not "127.0.0.1" or the pod's own name; curl must be told to verify against that hostname
    # while still actually connecting to the port-forward's loopback address.
    SERVICE_NAME=$(kubectl get service -n "$OPERATOR_NAMESPACE" -l control-plane=falco-operator \
      -o jsonpath='{.items[0].metadata.name}')
    SERVER_HOSTNAME="${SERVICE_NAME}.${OPERATOR_NAMESPACE}.svc.cluster.local"
    CURL_TLS_OPTS+=(--resolve "${SERVER_HOSTNAME}:${LOCAL_PORT}:127.0.0.1")
  fi
fi

if [ -z "$BASE_URL" ]; then
  if [ "$SCHEME" = "https" ]; then
    BASE_URL="${SCHEME}://${SERVER_HOSTNAME}:${LOCAL_PORT}"
  else
    BASE_URL="${SCHEME}://127.0.0.1:${LOCAL_PORT}"
  fi
fi

QUERY=""
if [ "$ARTIFACT_TYPE" = "plugins" ]; then
  NODE_OS="${NODE_OS:-}"
  NODE_ARCH="${NODE_ARCH:-}"
  if [ -z "$NODE_OS" ] || [ -z "$NODE_ARCH" ]; then
    NODE_OS=$(kubectl get nodes -o jsonpath='{.items[0].metadata.labels.kubernetes\.io/os}')
    NODE_ARCH=$(kubectl get nodes -o jsonpath='{.items[0].metadata.labels.kubernetes\.io/arch}')
  fi
  QUERY="?os=${NODE_OS}&arch=${NODE_ARCH}"
fi

URL="${BASE_URL}/v1/artifacts/${ARTIFACT_TYPE}/${ARTIFACT_NAMESPACE}/${ARTIFACT_NAME}${QUERY}"

LAST_ERROR="no attempts made"
LAST_STATUS=""

for ATTEMPT in $(seq 1 "$MAX_RETRIES"); do
  if ! LAST_STATUS=$(curl -sS -m 5 "${CURL_TLS_OPTS[@]}" -o /dev/null -w '%{http_code}' "$URL" 2>&1); then
    LAST_ERROR="curl failed: $LAST_STATUS"
    sleep "$RETRY_DELAY"
    continue
  fi

  if [ "$LAST_STATUS" = "$EXPECTED_STATUS" ]; then
    cat <<EOF
{
  "status": "success",
  "message": "Artifact server reported the expected status",
  "url": "$URL",
  "expected_status": "$EXPECTED_STATUS",
  "retry_attempt": $ATTEMPT,
  "max_retries": $MAX_RETRIES
}
EOF
    exit 0
  fi
  LAST_ERROR="got HTTP $LAST_STATUS, want $EXPECTED_STATUS"
  sleep "$RETRY_DELAY"
done

cat <<EOF
{
  "status": "failure",
  "message": "Artifact server never reported the expected status after $MAX_RETRIES attempts",
  "url": "$URL",
  "expected_status": "$EXPECTED_STATUS",
  "last_error": $(printf '%s' "$LAST_ERROR" | jq -Rs .),
  "retry_attempt": $MAX_RETRIES,
  "max_retries": $MAX_RETRIES
}
EOF
exit 1
