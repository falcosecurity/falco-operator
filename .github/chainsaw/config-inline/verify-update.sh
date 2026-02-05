#!/bin/bash
set -e

# Source common functions - chainsaw runs from test directory
source ../scripts/common.sh

CONFIG_FILE="/etc/falco/config.d/50-config-test.yaml"

# Wait for content to be updated (json_output changed from true to false)
wait_for_content_update "$CONFIG_FILE" "json_output: false" "json_output: true"

verify_falco_running

echo "Update verification passed"
