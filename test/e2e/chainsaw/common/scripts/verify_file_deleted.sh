#!/bin/bash
# Verify that a file has been removed from the Falco pod.
# Can be run standalone for debugging.
#
# Variables (from environment):
#   NAMESPACE: (Required) The namespace where the Falco pod is running.
#   FILE_PATH: (Required) The file path that should no longer exist inside the Falco pod.
#   FALCO_LABEL: (Optional) Label selector for the Falco pod. Default: app.kubernetes.io/instance=falco-test.
#   RETRY_COUNT: (Optional) Number of retries. Default: 30.
#   RETRY_DELAY: (Optional) Delay between retries in seconds. Default: 2.
#
# Example:
#   NAMESPACE=default FILE_PATH=/etc/falco/rules.d/50-01-rulesfile-oci-oci.yaml \
#   bash verify_file_deleted.sh

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

echo "Waiting for file ${FILE_PATH} to be deleted..."
for i in $(seq 1 "${RETRY_COUNT}"); do
  if ! exec_in_falco "test -f '${FILE_PATH}'" 2>/dev/null; then
    echo "OK: File deleted (attempt ${i}/${RETRY_COUNT})"
    verify_falco_running
    echo '{"status": "ok", "message": "File deleted", "file": "'"${FILE_PATH}"'"}'
    exit 0
  fi
  sleep "${RETRY_DELAY}"
done

echo '{"error": "File still exists after '"${RETRY_COUNT}"' attempts", "file": "'"${FILE_PATH}"'"}' >&2
exit 1
