#!/bin/bash
set -e

# Source common functions - chainsaw runs from test directory
source ../scripts/common.sh

OLD_RULES_FILE="/etc/falco/rules.d/50-01-rulesfile-oci-oci.yaml"
NEW_RULES_FILE="/etc/falco/rules.d/60-01-rulesfile-oci-oci.yaml"

# Wait for file to be renamed (priority changed from 50 to 60)
wait_for_file_rename "$OLD_RULES_FILE" "$NEW_RULES_FILE"

verify_falco_running

echo "Update verification passed"
