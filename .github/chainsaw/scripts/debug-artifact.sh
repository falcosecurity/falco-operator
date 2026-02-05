#!/bin/bash
# Generic debug script for artifact tests
# Shows all relevant directories and logs for debugging failures

echo "=== Debug: Test failed ==="
POD=$(kubectl get pod -l app.kubernetes.io/instance=falco-test -n "$NAMESPACE" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "unknown")

echo "=== Pod Status ==="
kubectl get pod -l app.kubernetes.io/instance=falco-test -n "$NAMESPACE" -o wide 2>/dev/null || true

echo "=== Rules Directory ==="
kubectl exec "$POD" -n "$NAMESPACE" -c falco -- ls -la /etc/falco/rules.d/ 2>/dev/null || true

echo "=== Config Directory ==="
kubectl exec "$POD" -n "$NAMESPACE" -c falco -- ls -la /etc/falco/config.d/ 2>/dev/null || true

echo "=== Plugin Directory ==="
kubectl exec "$POD" -n "$NAMESPACE" -c falco -- ls -la /usr/share/falco/plugins/ 2>/dev/null || true

echo "=== Artifact Operator Logs ==="
kubectl logs "$POD" -n "$NAMESPACE" -c artifact-operator --tail=30 2>/dev/null || true

echo "=== Falco Logs ==="
kubectl logs "$POD" -n "$NAMESPACE" -c falco --tail=30 2>/dev/null || true
