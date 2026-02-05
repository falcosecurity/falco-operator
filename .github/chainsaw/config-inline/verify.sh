#!/bin/bash
set -e

# Source common functions - chainsaw runs from test directory
source ../scripts/common.sh

CONFIG_FILE="/etc/falco/config.d/50-config-test.yaml"

wait_for_file "$CONFIG_FILE" "inline config file"
verify_file_contains "$CONFIG_FILE" "json_output" "expected configuration"
verify_falco_running

# List config directory for verification
echo "Config directory contents:"
exec_in_falco "ls -la /etc/falco/config.d/" 2>/dev/null || true

echo "All verifications passed"
