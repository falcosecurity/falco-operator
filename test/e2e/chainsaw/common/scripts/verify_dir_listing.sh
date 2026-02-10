#!/bin/bash
# List files in a directory inside the Falco pod and verify expected files exist.
# Can be run standalone for debugging.
#
# Variables (from environment):
#   NAMESPACE: (Required) The namespace where the Falco pod is running.
#   DIR_PATH: (Required) The directory path to list inside the Falco pod.
#   EXPECTED_FILES: (Required) Comma-separated list of filenames expected in the directory.
#   FALCO_LABEL: (Optional) Label selector for the Falco pod. Default: app.kubernetes.io/instance=falco-test.
#   RETRY_COUNT: (Optional) Number of retries. Default: 30.
#   RETRY_DELAY: (Optional) Delay between retries in seconds. Default: 2.
#
# Example:
#   NAMESPACE=default DIR_PATH=/etc/falco/rules.d \
#   EXPECTED_FILES="50-01-rules.yaml,50-02-rules.yaml" \
#   bash verify_dir_listing.sh

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

echo "Waiting for directory ${DIR_PATH} to exist..."
for i in $(seq 1 "${RETRY_COUNT}"); do
  if exec_in_falco "test -d '${DIR_PATH}'" 2>/dev/null; then
    echo "OK: Directory found (attempt ${i}/${RETRY_COUNT})"
    break
  fi
  if [ "${i}" -eq "${RETRY_COUNT}" ]; then
    echo '{"error": "Directory not found after '"${RETRY_COUNT}"' attempts", "dir_path": "'"${DIR_PATH}"'"}' >&2
    exit 1
  fi
  sleep "${RETRY_DELAY}"
done

echo "Listing files in ${DIR_PATH}..."
MISSING_FILES=""
IFS=',' read -ra FILES <<< "${EXPECTED_FILES}"

for attempt in $(seq 1 "${RETRY_COUNT}"); do
  FILE_LIST=$(exec_in_falco "ls -1 '${DIR_PATH}'" 2>/dev/null || echo "")
  MISSING_FILES=""
  for expected in "${FILES[@]}"; do
    expected=$(echo "${expected}" | xargs)
    if ! echo "${FILE_LIST}" | grep -Fxq "${expected}"; then
      if [ -n "${MISSING_FILES}" ]; then
        MISSING_FILES="${MISSING_FILES}, ${expected}"
      else
        MISSING_FILES="${expected}"
      fi
    fi
  done

  if [ -z "${MISSING_FILES}" ]; then
    break
  fi

  if [ "${attempt}" -eq "${RETRY_COUNT}" ]; then
    echo '{"error": "Expected files missing", "dir_path": "'"${DIR_PATH}"'", "missing_files": "'"${MISSING_FILES}"'", "actual_files": "'"$(echo "${FILE_LIST}" | tr '\n' ',')"'"}' >&2
    exit 1
  fi
  sleep "${RETRY_DELAY}"
done

verify_falco_running

echo '{"status": "ok", "dir_path": "'"${DIR_PATH}"'", "files": "'"$(echo "${FILE_LIST}" | tr '\n' ',')"'"}'
