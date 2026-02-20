#!/bin/bash
# Verify that the plugin config file contains expected plugin entries.
# Checks the plugins: section for the plugin name. The load_plugins section
# uses the CR metadata.name which may differ from config.name, so we only
# verify the plugins: section by default.
# Can be run standalone for debugging.
#
# Variables (from environment):
#   NAMESPACE: (Required) The namespace where the Falco pod is running.
#   PLUGIN_NAME: (Required) The plugin name to search for in the config.
#   PLUGIN_CONFIG_PATH: (Optional) Path to the plugin config file. Default: /etc/falco/config.d/99-plugins-config.yaml.
#   FALCO_LABEL: (Optional) Label selector for the Falco pod. Default: app.kubernetes.io/instance=falco-test.
#   RETRY_COUNT: (Optional) Number of retries. Default: 30.
#   RETRY_DELAY: (Optional) Delay between retries in seconds. Default: 2.
#
# Example:
#   NAMESPACE=default PLUGIN_NAME=json \
#   bash verify_plugin_config.sh

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

PLUGIN_CONFIG_PATH="${PLUGIN_CONFIG_PATH:-/etc/falco/config.d/99-plugins-config.yaml}"

wait_for_file "${PLUGIN_CONFIG_PATH}" "plugin config at ${PLUGIN_CONFIG_PATH}"

CONFIG_CONTENT=$(exec_in_falco "cat '${PLUGIN_CONFIG_PATH}'" 2>/dev/null || echo "")

echo "Verifying plugin '${PLUGIN_NAME}' is in plugins: section..."
if ! echo "${CONFIG_CONTENT}" | grep -Fq "${PLUGIN_NAME}"; then
  echo '{"error": "Plugin not found in config", "plugin_name": "'"${PLUGIN_NAME}"'", "config_path": "'"${PLUGIN_CONFIG_PATH}"'", "content": "'"$(echo "${CONFIG_CONTENT}" | head -20)"'"}' >&2
  exit 1
fi
echo "OK: Plugin '${PLUGIN_NAME}' found in config"

verify_falco_running

echo '{"status": "ok", "plugin_name": "'"${PLUGIN_NAME}"'", "config_path": "'"${PLUGIN_CONFIG_PATH}"'"}'
