#!/bin/bash
# Verify that a file exists and has a minimum size (for OCI artifact downloads).
# Can be run standalone for debugging.
#
# Variables (from environment):
#   NAMESPACE: (Required) The namespace where the Falco pod is running.
#   FILE_PATH: (Required) The file path to check inside the Falco pod.
#   MIN_SIZE: (Required) The minimum expected file size in bytes.
#   RULES_FILE_NAME: (Optional) If set, also verifies Falco loaded this rules file from logs.
#   FALCO_LABEL: (Optional) Label selector for the Falco pod. Default: app.kubernetes.io/instance=falco-test.
#   RETRY_COUNT: (Optional) Number of retries. Default: 30.
#   RETRY_DELAY: (Optional) Delay between retries in seconds. Default: 2.
#
# Example:
#   NAMESPACE=default FILE_PATH=/etc/falco/rules.d/50-01-rulesfile-oci-oci.yaml \
#   MIN_SIZE=100 bash verify_file_size.sh

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

wait_for_file "${FILE_PATH}" "file at ${FILE_PATH}"

echo "Verifying file size..."
FILE_SIZE=$(get_file_size "${FILE_PATH}")
if [ "${FILE_SIZE}" -gt "${MIN_SIZE}" ]; then
  echo "OK: File has valid size (${FILE_SIZE} bytes > ${MIN_SIZE} bytes)"
else
  echo '{"error": "File too small", "file_path": "'"${FILE_PATH}"'", "actual_size": '"${FILE_SIZE}"', "min_size": '"${MIN_SIZE}"'}' >&2
  exit 1
fi

verify_falco_running

if [ -n "${RULES_FILE_NAME:-}" ]; then
  verify_falco_loaded_rules "${RULES_FILE_NAME}"
fi

echo '{"status": "ok", "file_path": "'"${FILE_PATH}"'", "file_size": '"${FILE_SIZE}"'}'
