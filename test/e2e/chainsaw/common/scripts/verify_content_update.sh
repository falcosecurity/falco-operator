#!/bin/bash
# Verify that a file content was updated (new content present, old content absent).
# Can be run standalone for debugging.
#
# Variables (from environment):
#   NAMESPACE: (Required) The namespace where the Falco pod is running.
#   FILE_PATH: (Required) The file path to check inside the Falco pod.
#   NEW_CONTENT: (Required) The grep pattern for the new expected content.
#   OLD_CONTENT: (Required) The grep pattern for the old content that should be absent.
#   FALCO_LABEL: (Optional) Label selector for the Falco pod. Default: app.kubernetes.io/instance=falco-test.
#   RETRY_COUNT: (Optional) Number of retries. Default: 30.
#   RETRY_DELAY: (Optional) Delay between retries in seconds. Default: 2.
#
# Example:
#   NAMESPACE=default FILE_PATH=/etc/falco/config.d/50-config-test.yaml \
#   NEW_CONTENT="json_output: false" OLD_CONTENT="json_output: true" \
#   bash verify_content_update.sh

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

wait_for_content_update "${FILE_PATH}" "${NEW_CONTENT}" "${OLD_CONTENT}"
verify_falco_running

echo '{"status": "ok", "file_path": "'"${FILE_PATH}"'", "new_content": "'"${NEW_CONTENT}"'"}'
