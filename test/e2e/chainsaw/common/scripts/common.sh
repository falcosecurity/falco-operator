#!/bin/bash
# Common utility functions for Falco operator e2e test scripts.
#
# This library provides shared functions for pod operations, file verification,
# and Falco process checks. All scripts in this directory source this file.
#
# Variables (from environment):
#   NAMESPACE: (Required) The namespace where the Falco pod is running.
#   FALCO_LABEL: (Optional) Label selector for the Falco pod. Default: app.kubernetes.io/instance=falco-test.
#   RETRY_COUNT: (Optional) Number of retries. Default: 30.
#   RETRY_DELAY: (Optional) Delay between retries in seconds. Default: 2.

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FALCO_LABEL="${FALCO_LABEL:-app.kubernetes.io/instance=falco-test}"
RETRY_COUNT="${RETRY_COUNT:-30}"
RETRY_DELAY="${RETRY_DELAY:-2}"
_CACHED_POD=""

# get_pod returns the name of the Falco pod matching the label selector.
# The result is cached for the lifetime of the script (one shell invocation).
get_pod() {
  if [ -n "${_CACHED_POD}" ]; then
    echo "${_CACHED_POD}"
    return 0
  fi
  local pod
  pod=$(kubectl get pods -n "${NAMESPACE}" -l "${FALCO_LABEL}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
  if [ -z "${pod}" ]; then
    echo '{"error": "No Falco pod found", "namespace": "'"${NAMESPACE}"'", "label": "'"${FALCO_LABEL}"'"}' >&2
    return 1
  fi
  _CACHED_POD="${pod}"
  echo "${pod}"
}

# exec_in_falco runs a command inside the Falco container.
exec_in_falco() {
  local pod
  pod=$(get_pod)
  kubectl exec -n "${NAMESPACE}" "${pod}" -c falco -- sh -c "$1"
}

# wait_for_file waits for a file to exist in the Falco pod.
# Arguments: $1 = file path, $2 = description (for logging)
wait_for_file() {
  local file_path="$1"
  local description="${2:-file}"
  local pod
  pod=$(get_pod)

  echo "Waiting for ${description} at ${file_path}..."
  for i in $(seq 1 "${RETRY_COUNT}"); do
    if kubectl exec -n "${NAMESPACE}" "${pod}" -c falco -- test -f "${file_path}" 2>/dev/null; then
      echo "OK: ${description} found (attempt ${i}/${RETRY_COUNT})"
      return 0
    fi
    sleep "${RETRY_DELAY}"
  done

  echo '{"error": "File not found after '"${RETRY_COUNT}"' attempts", "file_path": "'"${file_path}"'", "description": "'"${description}"'", "kubectl_command": "kubectl exec -n '"${NAMESPACE}"' '"${pod}"' -c falco -- test -f '"${file_path}"'"}' >&2
  return 1
}

# verify_file_contains checks that a file in the Falco pod contains a pattern.
# Arguments: $1 = file path, $2 = grep pattern, $3 = description
verify_file_contains() {
  local file_path="$1"
  local pattern="$2"
  local description="${3:-expected content}"
  local pod
  pod=$(get_pod)

  echo "Verifying ${file_path} contains ${description}..."
  if kubectl exec -n "${NAMESPACE}" "${pod}" -c falco -- grep -q "${pattern}" "${file_path}" 2>/dev/null; then
    echo "OK: ${description} found in ${file_path}"
    return 0
  fi

  local actual_content
  actual_content=$(kubectl exec -n "${NAMESPACE}" "${pod}" -c falco -- cat "${file_path}" 2>/dev/null || echo "<unable to read>")
  echo '{"error": "Pattern not found in file", "file_path": "'"${file_path}"'", "pattern": "'"${pattern}"'", "actual_content": "'"$(echo "${actual_content}" | head -20)"'"}' >&2
  return 1
}

# verify_falco_running checks that the Falco process is running in the pod.
verify_falco_running() {
  local pod
  pod=$(get_pod)

  echo "Verifying Falco process is running..."
  if kubectl exec -n "${NAMESPACE}" "${pod}" -c falco -- pgrep falco >/dev/null 2>&1; then
    echo "OK: Falco process is running"
    return 0
  fi

  echo '{"error": "Falco process not running", "namespace": "'"${NAMESPACE}"'", "pod": "'"${pod}"'"}' >&2
  return 1
}

# verify_falco_loaded_rules checks that Falco loaded a specific rules file.
# Arguments: $1 = rules filename
verify_falco_loaded_rules() {
  local rules_file="$1"
  local pod
  pod=$(get_pod)

  echo "Verifying Falco loaded rules from ${rules_file}..."
  if kubectl logs -n "${NAMESPACE}" "${pod}" -c falco 2>/dev/null | grep -q "${rules_file}"; then
    echo "OK: Falco loaded rules from ${rules_file}"
    return 0
  fi

  echo '{"error": "Rules file not found in Falco logs", "rules_file": "'"${rules_file}"'", "kubectl_command": "kubectl logs -n '"${NAMESPACE}"' '"${pod}"' -c falco"}' >&2
  return 1
}

# get_file_size returns the size of a file in the Falco pod in bytes.
# Arguments: $1 = file path
get_file_size() {
  local file_path="$1"
  local pod
  pod=$(get_pod)
  kubectl exec -n "${NAMESPACE}" "${pod}" -c falco -- stat -c%s "${file_path}" 2>/dev/null || echo "0"
}

# wait_for_content_update waits for a file to contain new content and not old content.
# Arguments: $1 = file path, $2 = new content pattern, $3 = old content pattern
wait_for_content_update() {
  local file_path="$1"
  local new_content="$2"
  local old_content="$3"
  local pod
  pod=$(get_pod)

  echo "Waiting for content update in ${file_path}..."
  for i in $(seq 1 "${RETRY_COUNT}"); do
    local content
    content=$(kubectl exec -n "${NAMESPACE}" "${pod}" -c falco -- cat "${file_path}" 2>/dev/null || echo "")
    if echo "${content}" | grep -q "${new_content}" && ! echo "${content}" | grep -q "${old_content}"; then
      echo "OK: Content updated (attempt ${i}/${RETRY_COUNT})"
      return 0
    fi
    sleep "${RETRY_DELAY}"
  done

  echo '{"error": "Content not updated after '"${RETRY_COUNT}"' attempts", "file_path": "'"${file_path}"'", "expected_new": "'"${new_content}"'", "expected_absent": "'"${old_content}"'"}' >&2
  return 1
}

# wait_for_file_rename waits for a file to be renamed (old file gone, new file exists).
# Arguments: $1 = old file path, $2 = new file path
wait_for_file_rename() {
  local old_path="$1"
  local new_path="$2"
  local pod
  pod=$(get_pod)

  echo "Waiting for file rename from ${old_path} to ${new_path}..."
  for i in $(seq 1 "${RETRY_COUNT}"); do
    local old_exists new_exists
    old_exists=$(kubectl exec -n "${NAMESPACE}" "${pod}" -c falco -- test -f "${old_path}" 2>/dev/null && echo "yes" || echo "no")
    new_exists=$(kubectl exec -n "${NAMESPACE}" "${pod}" -c falco -- test -f "${new_path}" 2>/dev/null && echo "yes" || echo "no")

    if [ "${old_exists}" = "no" ] && [ "${new_exists}" = "yes" ]; then
      echo "OK: File renamed successfully (attempt ${i}/${RETRY_COUNT})"
      return 0
    fi
    sleep "${RETRY_DELAY}"
  done

  echo '{"error": "File rename not detected after '"${RETRY_COUNT}"' attempts", "old_path": "'"${old_path}"'", "new_path": "'"${new_path}"'"}' >&2
  return 1
}

# wait_for_plugin waits for a .so plugin file to appear in a directory.
# Arguments: $1 = plugin directory
# Returns: the full path to the plugin file via stdout
wait_for_plugin() {
  local plugin_dir="$1"
  local pod
  pod=$(get_pod)

  echo "Waiting for plugin in ${plugin_dir}..." >&2
  for i in $(seq 1 "${RETRY_COUNT}"); do
    local plugin_file
    plugin_file=$(kubectl exec -n "${NAMESPACE}" "${pod}" -c falco -- find "${plugin_dir}" -name "*.so" -type f 2>/dev/null | head -1)
    if [ -n "${plugin_file}" ]; then
      echo "OK: Plugin found at ${plugin_file} (attempt ${i}/${RETRY_COUNT})" >&2
      echo "${plugin_file}"
      return 0
    fi
    sleep "${RETRY_DELAY}"
  done

  echo '{"error": "Plugin not found after '"${RETRY_COUNT}"' attempts", "plugin_dir": "'"${plugin_dir}"'", "kubectl_command": "kubectl exec -n '"${NAMESPACE}"' '"${pod}"' -c falco -- find '"${plugin_dir}"' -name *.so"}' >&2
  return 1
}
