#!/bin/bash
# Verify that a file was renamed (old path gone, new path exists).
# Used when changing artifact priority causes a file rename.
# Can be run standalone for debugging.
#
# Variables (from environment):
#   NAMESPACE: (Required) The namespace where the Falco pod is running.
#   OLD_FILE_PATH: (Required) The old file path that should no longer exist.
#   NEW_FILE_PATH: (Required) The new file path that should exist.
#   FALCO_LABEL: (Optional) Label selector for the Falco pod. Default: app.kubernetes.io/instance=falco-test.
#   RETRY_COUNT: (Optional) Number of retries. Default: 30.
#   RETRY_DELAY: (Optional) Delay between retries in seconds. Default: 2.
#
# Example:
#   NAMESPACE=default OLD_FILE_PATH=/etc/falco/rules.d/50-01-rulesfile-oci-oci.yaml \
#   NEW_FILE_PATH=/etc/falco/rules.d/60-01-rulesfile-oci-oci.yaml \
#   bash verify_file_rename.sh

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

wait_for_file_rename "${OLD_FILE_PATH}" "${NEW_FILE_PATH}"
verify_falco_running

echo "Rules directory after rename:"
exec_in_falco "ls -la /etc/falco/rules.d/" 2>/dev/null || true

echo '{"status": "ok", "old_path": "'"${OLD_FILE_PATH}"'", "new_path": "'"${NEW_FILE_PATH}"'"}'
