#!/bin/bash
set -e

# Source common functions - chainsaw runs from test directory
source ../scripts/common.sh

PLUGIN_DIR="/usr/share/falco/plugins"

# Wait for plugin file to be downloaded
PLUGIN_FILE=$(wait_for_plugin "$PLUGIN_DIR")

# Verify plugin file has valid size
echo "Verifying plugin file..."
FILE_SIZE=$(get_file_size "$PLUGIN_FILE")
if [ "$FILE_SIZE" -gt 1000 ]; then
  echo "OK: Plugin file has valid size ($FILE_SIZE bytes)"
else
  echo "FAIL: Plugin file seems invalid (size: $FILE_SIZE bytes)"
  exit 1
fi

verify_falco_running

# List plugin directory for verification
echo "Plugin directory contents:"
exec_in_falco "ls -la $PLUGIN_DIR" 2>/dev/null || true

echo "All verifications passed"
