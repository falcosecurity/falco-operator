#!/bin/bash
# Common functions for chainsaw e2e test verification scripts

# Get the Falco pod name
# Usage: POD=$(get_pod)
get_pod() {
  kubectl get pod -l app.kubernetes.io/instance=falco-test -n "$NAMESPACE" -o jsonpath='{.items[0].metadata.name}'
}

# Wait for a file to exist and be non-empty
# Usage: wait_for_file "/path/to/file" "description"
# Returns: 0 on success, 1 on timeout
wait_for_file() {
  local file_path="$1"
  local description="${2:-file}"
  local pod
  pod=$(get_pod)

  echo "Waiting for $description at $file_path..."
  for i in $(seq 1 30); do
    if kubectl exec "$pod" -n "$NAMESPACE" -c falco -- test -s "$file_path" 2>/dev/null; then
      echo "OK: $description created at $file_path"
      return 0
    fi
    if [ "$i" -eq 30 ]; then
      echo "FAIL: $description not created after 60 seconds"
      return 1
    fi
    sleep 2
  done
}

# Verify Falco process is running
# Usage: verify_falco_running
# Returns: 0 if running, 1 if not
verify_falco_running() {
  local pod
  pod=$(get_pod)

  echo "Verifying Falco process..."
  if kubectl exec "$pod" -n "$NAMESPACE" -c falco -- pgrep falco > /dev/null 2>&1; then
    echo "OK: Falco process is running"
    return 0
  else
    echo "FAIL: Falco process not running"
    return 1
  fi
}

# Verify file contains expected content
# Usage: verify_file_contains "/path/to/file" "pattern" "description"
# Returns: 0 if found, 1 if not
verify_file_contains() {
  local file_path="$1"
  local pattern="$2"
  local description="${3:-expected content}"
  local pod
  pod=$(get_pod)

  echo "Verifying $description..."
  if kubectl exec "$pod" -n "$NAMESPACE" -c falco -- grep -q "$pattern" "$file_path" 2>/dev/null; then
    echo "OK: File contains $description"
    return 0
  else
    echo "FAIL: File does not contain $description"
    kubectl exec "$pod" -n "$NAMESPACE" -c falco -- cat "$file_path" 2>/dev/null || true
    return 1
  fi
}

# Verify Falco loaded a rules file (check logs)
# Usage: verify_falco_loaded_rules "filename-pattern"
# Returns: 0 if loaded, 1 if not
verify_falco_loaded_rules() {
  local filename_pattern="$1"
  local pod
  pod=$(get_pod)

  echo "Verifying Falco loaded the rules..."
  sleep 3
  if kubectl logs "$pod" -n "$NAMESPACE" -c falco --tail=50 | grep -q "$filename_pattern"; then
    echo "OK: Falco loaded the rules file"
    return 0
  else
    echo "FAIL: Falco did not load the rules file"
    kubectl logs "$pod" -n "$NAMESPACE" -c falco --tail=30
    return 1
  fi
}

# Get file size in bytes
# Usage: size=$(get_file_size "/path/to/file")
get_file_size() {
  local file_path="$1"
  local pod
  pod=$(get_pod)

  kubectl exec "$pod" -n "$NAMESPACE" -c falco -- stat -c%s "$file_path" 2>/dev/null || echo "0"
}

# Execute command in Falco container
# Usage: exec_in_falco "command"
exec_in_falco() {
  local cmd="$1"
  local pod
  pod=$(get_pod)

  kubectl exec "$pod" -n "$NAMESPACE" -c falco -- $cmd
}

# Wait for file content to be updated (contains new pattern, doesn't contain old)
# Usage: wait_for_content_update "/path/to/file" "new_pattern" "old_pattern"
# Returns: 0 on success, 1 on timeout
wait_for_content_update() {
  local file_path="$1"
  local new_pattern="$2"
  local old_pattern="${3:-}"
  local pod
  pod=$(get_pod)

  echo "Waiting for content update in $file_path..."
  for i in $(seq 1 30); do
    # Check if new content is present
    if kubectl exec "$pod" -n "$NAMESPACE" -c falco -- grep -q "$new_pattern" "$file_path" 2>/dev/null; then
      # If old_pattern specified, verify it's gone
      if [ -n "$old_pattern" ]; then
        if ! kubectl exec "$pod" -n "$NAMESPACE" -c falco -- grep -q "$old_pattern" "$file_path" 2>/dev/null; then
          echo "OK: Content updated (new pattern found, old pattern removed)"
          return 0
        fi
      else
        echo "OK: Content updated (new pattern found)"
        return 0
      fi
    fi
    if [ "$i" -eq 30 ]; then
      echo "FAIL: Content not updated after 60 seconds"
      kubectl exec "$pod" -n "$NAMESPACE" -c falco -- cat "$file_path" 2>/dev/null || true
      return 1
    fi
    sleep 2
  done
}

# Wait for file to be renamed (old file removed, new file created)
# Usage: wait_for_file_rename "/old/path" "/new/path"
# Returns: 0 on success, 1 on timeout
wait_for_file_rename() {
  local old_path="$1"
  local new_path="$2"
  local pod
  pod=$(get_pod)

  echo "Waiting for file rename from $old_path to $new_path..."
  for i in $(seq 1 30); do
    # Check new file exists and old file is gone
    if kubectl exec "$pod" -n "$NAMESPACE" -c falco -- test -s "$new_path" 2>/dev/null; then
      if ! kubectl exec "$pod" -n "$NAMESPACE" -c falco -- test -e "$old_path" 2>/dev/null; then
        echo "OK: File renamed successfully"
        return 0
      fi
    fi
    if [ "$i" -eq 30 ]; then
      echo "FAIL: File not renamed after 60 seconds"
      echo "Old file exists: $(kubectl exec "$pod" -n "$NAMESPACE" -c falco -- test -e "$old_path" 2>/dev/null && echo "yes" || echo "no")"
      echo "New file exists: $(kubectl exec "$pod" -n "$NAMESPACE" -c falco -- test -e "$new_path" 2>/dev/null && echo "yes" || echo "no")"
      return 1
    fi
    sleep 2
  done
}

# Wait for a plugin file to exist in directory
# Usage: plugin_file=$(wait_for_plugin "/path/to/plugins")
# Returns: plugin file path on stdout, exit 1 on timeout
wait_for_plugin() {
  local plugin_dir="$1"
  local pod
  pod=$(get_pod)

  echo "Waiting for plugin file in $plugin_dir..." >&2
  for i in $(seq 1 30); do
    # Use sh -c to ensure glob is expanded inside the container
    PLUGIN_FILE=$(kubectl exec "$pod" -n "$NAMESPACE" -c falco -- sh -c "ls ${plugin_dir}/*.so 2>/dev/null" | head -1)
    if [ -n "$PLUGIN_FILE" ]; then
      echo "OK: Plugin file found at $PLUGIN_FILE" >&2
      echo "$PLUGIN_FILE"
      return 0
    fi
    if [ "$i" -eq 30 ]; then
      echo "FAIL: Plugin file not found after 60 seconds" >&2
      return 1
    fi
    sleep 2
  done
}
