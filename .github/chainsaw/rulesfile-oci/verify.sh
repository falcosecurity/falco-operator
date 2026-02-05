#!/bin/bash
set -e

# Source common functions - chainsaw runs from test directory
source ../scripts/common.sh

RULES_FILE="/etc/falco/rules.d/50-01-rulesfile-oci-oci.yaml"

wait_for_file "$RULES_FILE" "OCI rules file"

# Verify file is not empty and has reasonable size
echo "Verifying rules file content..."
FILE_SIZE=$(get_file_size "$RULES_FILE")
if [ "$FILE_SIZE" -gt 100 ]; then
  echo "OK: Rules file has content (size: $FILE_SIZE bytes)"
else
  echo "FAIL: Rules file seems empty or too small (size: $FILE_SIZE bytes)"
  exit 1
fi

verify_falco_running
verify_falco_loaded_rules "50-01-rulesfile-oci-oci.yaml"

echo "All verifications passed"
