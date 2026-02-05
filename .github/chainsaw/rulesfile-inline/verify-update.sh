#!/bin/bash
set -e

# Source common functions - chainsaw runs from test directory
source ../scripts/common.sh

RULES_FILE="/etc/falco/rules.d/50-03-rulesfile-inline-inline.yaml"

# Wait for content to be updated (check for "Updated" which only exists in new version)
wait_for_content_update "$RULES_FILE" "Rule Updated"

verify_falco_running

echo "Update verification passed"
