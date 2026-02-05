#!/bin/bash
set -e

# Source common functions - chainsaw runs from test directory
source ../scripts/common.sh

RULES_FILE="/etc/falco/rules.d/50-03-rulesfile-inline-inline.yaml"

wait_for_file "$RULES_FILE" "inline rules file"
verify_file_contains "$RULES_FILE" "Test Inline Rule" "expected rule definition"
verify_falco_running
verify_falco_loaded_rules "50-03-rulesfile-inline-inline.yaml"

echo "All verifications passed"
