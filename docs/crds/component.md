# Component CRD Reference

**API Version**: `instance.falcosecurity.dev/v1alpha1`
**Kind**: `Component`

## Description

The `Component` Custom Resource manages ecosystem components that work alongside Falco. The operator reconciles each Component CR into a Deployment with sensible defaults for the selected component type.

Supported component types:

| Type | Component | Description |
|------|-----------|-------------|
| `metacollector` | [k8s-metacollector](https://github.com/falcosecurity/k8s-metacollector) | Centralized Kubernetes metadata for Falco instances |
| `falcosidekick` | [Falcosidekick](https://github.com/falcosecurity/falcosidekick) | Fan-out daemon for Falco events (70+ output integrations) |
| `falcosidekick-ui` | [Falcosidekick UI](https://github.com/falcosecurity/falcosidekick-ui) | Web dashboard for real-time event visualization |

## Spec

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `component.type` | `string` | — | **Required.** Component type: `metacollector`, `falcosidekick`, or `falcosidekick-ui` |
| `component.version` | `string` | — | Component version. If omitted, uses the version bundled with the operator |
| `replicas` | `*int32` | `1` | Number of replicas |
| `podTemplateSpec` | `*corev1.PodTemplateSpec` | *(operator defaults)* | Custom pod template |
| `strategy` | `*appsv1.DeploymentStrategy` | — | Deployment update strategy |

## Status

| Field | Type | Description |
|-------|------|-------------|
| `resourceType` | `string` | Resolved resource type (always `Deployment`) |
| `version` | `string` | Resolved component version |
| `desiredReplicas` | `int32` | Desired replica count |
| `availableReplicas` | `int32` | Ready replica count |
| `conditions` | `[]metav1.Condition` | `Reconciled` and `Available` conditions |

## Component Defaults

### metacollector

| Setting | Value |
|---------|-------|
| Image | `docker.io/falcosecurity/k8s-metacollector:0.1.1` |
| Ports | 8080 (metrics), 8081 (health), 45000 (broker-grpc) |
| Resources | Requests: 100m CPU, 128Mi memory; Limits: 250m CPU, 256Mi memory |
| Security | Non-root (uid 1000), drop all capabilities |
| RBAC | ClusterRole: get/list/watch on nodes, pods, services, deployments, etc. |

### falcosidekick

| Setting | Value |
|---------|-------|
| Image | `docker.io/falcosecurity/falcosidekick:2.32.0` |
| Default replicas | 2 |
| Port | 2801 (http) |
| Probes | `/ping` on port 2801, initialDelay 10s, period 5s |
| Security | uid/gid 1234 |
| RBAC | Role: get on endpoints |

### falcosidekick-ui

| Setting | Value |
|---------|-------|
| Image | `docker.io/falcosecurity/falcosidekick-ui:2.2.0` |
| Default replicas | 2 |
| Port | 2802 (http) |
| Probes | `/api/v1/healthz` on port 2802, initialDelay 10s, period 5s |
| Security | uid/gid 1234 |
| Init container | `wait-redis` — blocks until Redis is reachable |
| Default Redis address | `falcosidekick-ui-redis:6379` |

> **Important**: `falcosidekick-ui` requires an external Redis instance. The operator does NOT deploy Redis. If Redis is not available, the `wait-redis` init container blocks and the pod stays in `Init:0/1` state. See the [Redis setup](#falcosidekick-ui-with-redis) section below.

## Examples

### metacollector

```yaml
apiVersion: instance.falcosecurity.dev/v1alpha1
kind: Component
metadata:
  name: metacollector
spec:
  component:
    type: metacollector
    version: "0.1.1"
  replicas: 1
```

### falcosidekick

```yaml
apiVersion: instance.falcosecurity.dev/v1alpha1
kind: Component
metadata:
  name: sidekick
spec:
  component:
    type: falcosidekick
    version: "2.32.0"
  replicas: 2
```

### falcosidekick-ui (external Redis)

Override the Redis address via `podTemplateSpec`:

```yaml
apiVersion: instance.falcosecurity.dev/v1alpha1
kind: Component
metadata:
  name: sidekick-ui
spec:
  component:
    type: falcosidekick-ui
    version: "2.2.0"
  replicas: 2
  podTemplateSpec:
    spec:
      initContainers:
        - name: wait-redis
          env:
            - name: REDIS_ADDR
              value: "my-redis-service:6379"
      containers:
        - name: falcosidekick-ui
          args:
            - "-r"
            - "my-redis-service:6379"
```

### falcosidekick-ui with Redis

Complete example that deploys a Redis StatefulSet alongside the UI:

```yaml
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: falcosidekick-ui-redis
  labels:
    app.kubernetes.io/name: falcosidekick-ui-redis
spec:
  serviceName: falcosidekick-ui-redis
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: falcosidekick-ui-redis
  template:
    metadata:
      labels:
        app.kubernetes.io/name: falcosidekick-ui-redis
    spec:
      containers:
        - name: redis
          image: docker.io/redis/redis-stack:7.2.0-v11
          ports:
            - containerPort: 6379
              name: redis
          livenessProbe:
            tcpSocket:
              port: 6379
            initialDelaySeconds: 5
            periodSeconds: 5
          readinessProbe:
            tcpSocket:
              port: 6379
            initialDelaySeconds: 5
            periodSeconds: 5
  volumeClaimTemplates:
    - metadata:
        name: redis-data
      spec:
        accessModes: ["ReadWriteOnce"]
        resources:
          requests:
            storage: 1Gi
---
apiVersion: v1
kind: Service
metadata:
  name: falcosidekick-ui-redis
spec:
  type: ClusterIP
  ports:
    - port: 6379
      targetPort: 6379
      name: redis
  selector:
    app.kubernetes.io/name: falcosidekick-ui-redis
---
apiVersion: instance.falcosecurity.dev/v1alpha1
kind: Component
metadata:
  name: sidekick-ui
spec:
  component:
    type: falcosidekick-ui
    version: "2.2.0"
  replicas: 2
```

## Notes

- All component types are Deployment-only (no DaemonSet support).
- The Component controller shares reconciliation logic with the Falco controller: ServiceAccount, ClusterRole, ClusterRoleBinding, Service, and Deployment are created automatically.
- Use `podTemplateSpec` to customize any aspect of the component pod (resource limits, node selectors, tolerations, extra env vars, etc.).
- Sample manifests are available in [`config/samples/`](https://github.com/falcosecurity/falco-operator/tree/main/config/samples).
