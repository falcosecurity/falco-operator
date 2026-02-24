#!/bin/bash
# Wait for a plugin .so file to be downloaded and verify its size.
# Can be run standalone for debugging.
#
# Variables (from environment):
#   NAMESPACE: (Required) The namespace where the Falco pod is running.
#   PLUGIN_DIR: (Required) The directory where plugins are stored.
#   MIN_SIZE: (Optional) Minimum plugin file size in bytes. Default: 1000.
#   FALCO_LABEL: (Optional) Label selector for the Falco pod. Default: app.kubernetes.io/instance=falco-test.
#   RETRY_COUNT: (Optional) Number of retries. Default: 30.
#   RETRY_DELAY: (Optional) Delay between retries in seconds. Default: 2.
#
# Example:
#   NAMESPACE=default PLUGIN_DIR=/usr/share/falco/plugins bash wait_for_plugin.sh

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

MIN_SIZE="${MIN_SIZE:-1000}"

PLUGIN_FILE=$(wait_for_plugin "${PLUGIN_DIR}" "${MIN_SIZE}")

verify_falco_running

echo "Plugin directory contents:"
exec_in_falco "ls -la ${PLUGIN_DIR}" 2>/dev/null || true

FILE_SIZE=$(get_file_size "${PLUGIN_FILE}")
echo '{"status": "ok", "plugin_file": "'"${PLUGIN_FILE}"'", "file_size": '"${FILE_SIZE}"'}'
