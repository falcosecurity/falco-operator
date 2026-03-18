# Falco CRD Reference

**API Version**: `instance.falcosecurity.dev/v1alpha1`
**Kind**: `Falco`
**Short Name**: `falco`
**Category**: `falcosecurity`

## Description

The `Falco` Custom Resource defines a Falco instance in the cluster. The operator reconciles each Falco CR into either a DaemonSet or a Deployment, complete with RBAC, a Service, a base ConfigMap, the Artifact Operator sidecar, and a DriverLoader init container.

## Spec

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | `*string` | `DaemonSet` | Deployment mode: `DaemonSet` or `Deployment` |
| `replicas` | `*int32` | `1` | Number of replicas (Deployment mode only) |
| `version` | `*string` | *(auto-detected)* | Falco version to deploy |
| `podTemplateSpec` | `*corev1.PodTemplateSpec` | *(operator defaults)* | Custom pod template to override defaults |
| `updateStrategy` | `*appsv1.DaemonSetUpdateStrategy` | — | Update strategy for DaemonSet mode |
| `strategy` | `*appsv1.DeploymentStrategy` | — | Update strategy for Deployment mode |

## Status

| Field | Type | Description |
|-------|------|-------------|
| `conditions` | `[]metav1.Condition` | `Reconciled` and `Available` conditions |
| `resourceType` | `string` | Resolved deployment type (`DaemonSet` or `Deployment`) |
| `version` | `string` | Resolved Falco version |

## PrintColumns

`kubectl get falco` displays:

| Column | Source |
|--------|--------|
| Type | `.status.resourceType` |
| Version | `.status.version` |
| Reconciled | `.status.conditions[?(@.type=="Reconciled")].status` |
| Available | `.status.conditions[?(@.type=="Available")].status` |
| Age | `.metadata.creationTimestamp` |

## Examples

### Minimal (all defaults)

```yaml
apiVersion: instance.falcosecurity.dev/v1alpha1
kind: Falco
metadata:
  name: falco
spec: {}
```

Deploys Falco as a DaemonSet with `modern_ebpf` engine on every node.

### DaemonSet with rolling update

```yaml
apiVersion: instance.falcosecurity.dev/v1alpha1
kind: Falco
metadata:
  name: falco
spec:
  type: DaemonSet
  updateStrategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
```

### Deployment mode

```yaml
apiVersion: instance.falcosecurity.dev/v1alpha1
kind: Falco
metadata:
  name: falco-plugins
  namespace: falco-plugins
spec:
  type: Deployment
  replicas: 2
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
      maxSurge: 1
```

### Custom pod template

```yaml
apiVersion: instance.falcosecurity.dev/v1alpha1
kind: Falco
metadata:
  name: falco-custom
spec:
  podTemplateSpec:
    spec:
      containers:
        - name: falco
          image: falcosecurity/falco:0.43.0
          resources:
            requests:
              cpu: 200m
              memory: 1Gi
            limits:
              cpu: 2000m
              memory: 2Gi
```

## Notes

- When `type` is omitted, the operator defaults to `DaemonSet` mode.
- When `version` is omitted, the operator resolves the version from the container image tag or uses a built-in default.
- The `podTemplateSpec` allows full customization of the Falco pod, including the Artifact Operator sidecar (init container named `artifact-operator`) and the Falco container (named `falco`).
- Only one Falco CR should be created per namespace to avoid conflicts.
