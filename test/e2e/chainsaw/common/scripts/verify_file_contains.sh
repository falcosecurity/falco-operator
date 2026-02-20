#!/bin/bash
# Verify that a file exists in the Falco pod and contains an expected pattern.
# Can be run standalone for debugging.
#
# Variables (from environment):
#   NAMESPACE: (Required) The namespace where the Falco pod is running.
#   FILE_PATH: (Required) The file path to check inside the Falco pod.
#   EXPECTED_CONTENT: (Required) The grep pattern to search for in the file.
#   FALCO_LABEL: (Optional) Label selector for the Falco pod. Default: app.kubernetes.io/instance=falco-test.
#   RETRY_COUNT: (Optional) Number of retries. Default: 30.
#   RETRY_DELAY: (Optional) Delay between retries in seconds. Default: 2.
#
# Example:
#   NAMESPACE=default FILE_PATH=/etc/falco/config.d/50-config-test.yaml \
#   EXPECTED_CONTENT=json_output bash verify_file_contains.sh

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

wait_for_file "${FILE_PATH}" "file at ${FILE_PATH}"
verify_file_contains "${FILE_PATH}" "${EXPECTED_CONTENT}" "expected content '${EXPECTED_CONTENT}'"
verify_falco_running

echo '{"status": "ok", "file_path": "'"${FILE_PATH}"'", "pattern_found": "'"${EXPECTED_CONTENT}"'"}'
