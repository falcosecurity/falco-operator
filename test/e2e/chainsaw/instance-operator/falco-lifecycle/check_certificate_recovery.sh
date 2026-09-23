#!/usr/bin/env bash
# Exercise the generated client Certificate's recovery without editing its Falco owner.
set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
COMMON="$SCRIPT_DIR/../../common/scripts"
CERTIFICATE_NAME="$FALCO_NAME-artifact-client-tls"

check_download() {
  ARTIFACT_TYPE=rulesfiles ARTIFACT_NAMESPACE="$NAMESPACE" \
    ARTIFACT_NAME="$RULESFILE_NAME" MTLS_TEST_FALCO_NAME="$FALCO_NAME" EXPECTED_STATUS=200 \
    bash "$COMMON/check_artifact_cache_status.sh" >&2
}

check_download
PODS=$(kubectl get pods -n "$NAMESPACE" -l "app.kubernetes.io/name=$FALCO_NAME" -o json)
MTLS=$(printf '%s' "$PODS" | jq -er '
  [.items[].spec.containers[] | select(.name == "artifact-operator") |
    any(.env[]; .name == "ARTIFACT_CLIENT_CERT_PATH" and .value != "")] |
  if length == 0 then error("no artifact-operator containers")
  elif all(.[]; . == true) then "enabled"
  elif all(.[]; . == false) then "disabled"
  else error("inconsistent TLS settings across Falco Pods") end')
if [ "$MTLS" = disabled ]; then
  jq -n '{status: "success", mode: "http", message: "HTTP download verified; no Certificate dependency"}'
  exit 0
fi

OWNER_BEFORE=$(kubectl get falco -n "$NAMESPACE" "$FALCO_NAME" -o json |
  jq -c '{uid: .metadata.uid, generation: .metadata.generation}')
CERTIFICATE=$(NAMESPACE="$NAMESPACE" RESOURCE=certificates.cert-manager.io NAME="$CERTIFICATE_NAME" \
  bash "$COMMON/get_resource_uid.sh")
OLD_UID=$(printf '%s' "$CERTIFICATE" | jq -er '.uid')
kubectl delete certificate -n "$NAMESPACE" "$CERTIFICATE_NAME" --wait=true --timeout=60s >&2
RESOURCE=certificates.cert-manager.io NAME="$CERTIFICATE_NAME" OLD_UID="$OLD_UID" \
  bash "$COMMON/wait_for_resource_uid_changed.sh" >&2
kubectl wait -n "$NAMESPACE" "certificate/$CERTIFICATE_NAME" --for=condition=Ready --timeout=120s >&2
kubectl get certificate -n "$NAMESPACE" "$CERTIFICATE_NAME" -o json |
  jq -e --argjson owner "$OWNER_BEFORE" --arg old "$OLD_UID" '
    .metadata.uid != $old and
    any(.metadata.ownerReferences[]; .controller == true and .kind == "Falco" and .uid == $owner.uid)
  ' >&2
OWNER_AFTER=$(kubectl get falco -n "$NAMESPACE" "$FALCO_NAME" -o json |
  jq -c '{uid: .metadata.uid, generation: .metadata.generation}')
[ "$OWNER_BEFORE" = "$OWNER_AFTER" ]
check_download
jq -n '{status: "success", mode: "mtls", message: "Certificate recreated and authenticated download recovered without a Falco edit"}'
