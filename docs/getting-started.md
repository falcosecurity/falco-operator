# Getting Started

This guide walks you through deploying Falco using the operator and configuring detection rules.

## 1. Install the Operator

If you haven't already, install the operator:

```bash
kubectl apply -f https://github.com/falcosecurity/falco-operator/releases/latest/download/install.yaml
kubectl wait pods --for=condition=Ready --all -n falco-operator
```

See [Installation](installation.md) for details.

## 2. Deploy a Falco Instance

Create a Falco instance with default settings:

```bash
cat <<EOF | kubectl apply -f -
apiVersion: instance.falcosecurity.dev/v1alpha1
kind: Falco
metadata:
  name: falco
spec: {}
EOF
```

This deploys Falco as a DaemonSet on every node using the `modern_ebpf` driver. Check the status:

```bash
kubectl get falco
kubectl get pods -l app.kubernetes.io/name=falco
```

> **Note**: Falco starts in idle mode — it will not actively monitor until you provide detection rules.

## 3. Add the Container Plugin

The official Falco rules use fields like `container.id` and `container.image.repository` that require the [container plugin](https://github.com/falcosecurity/plugins/tree/main/plugins/container). Load it first:

```bash
cat <<EOF | kubectl apply -f -
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: Plugin
metadata:
  name: container
spec:
  ociArtifact:
    image:
      repository: falcosecurity/plugins/plugin/container
      tag: latest
    registry:
      name: ghcr.io
EOF
```

## 4. Add Detection Rules

Load the official Falco rules from the OCI registry:

```bash
cat <<EOF | kubectl apply -f -
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: Rulesfile
metadata:
  name: falco-rules
spec:
  ociArtifact:
    image:
      repository: falcosecurity/rules/falco-rules
      tag: latest
    registry:
      name: ghcr.io
  priority: 50
EOF
```

Check the rulesfile status:

```bash
kubectl get rulesfiles
```

Falco will automatically pick up the rules and start monitoring.

> **Note**: The `registry.name` field defaults to `ghcr.io` when omitted. The `image.tag` field defaults to `latest`.

## 5. Verify Falco is Working

Check the Falco logs to confirm rules are loaded and events are being monitored:

```bash
kubectl logs -l app.kubernetes.io/name=falco -c falco --tail=20
```

You should see log lines indicating that rules have been loaded and Falco is running.

## 6. Customize Configuration (Optional)

Override Falco settings with a Config resource:

```bash
cat <<EOF | kubectl apply -f -
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: Config
metadata:
  name: enable-debug
spec:
  config:
    libs_logger:
      enabled: true
      severity: debug
  priority: 50
EOF
```

## 7. Add Falcosidekick (Optional)

Deploy [Falcosidekick](https://github.com/falcosecurity/falcosidekick) to fan out Falco events to 70+ output integrations (Slack, Elasticsearch, S3, Kafka, etc.):

```bash
cat <<EOF | kubectl apply -f -
apiVersion: instance.falcosecurity.dev/v1alpha1
kind: Component
metadata:
  name: sidekick
spec:
  component:
    type: falcosidekick
    version: "2.32.0"
  replicas: 2
EOF
```

Then configure Falco to send events to Falcosidekick via a Config resource:

```bash
cat <<EOF | kubectl apply -f -
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: Config
metadata:
  name: sidekick-output
spec:
  config:
    json_output: true
    http_output:
      enabled: true
      url: "http://sidekick:2801"
  priority: 60
EOF
```

For the web dashboard, see the [Falcosidekick UI component reference](crds/component.md#falcosidekick-ui-with-redis).

## Deployment Mode: Plugin-only

For workloads that only need plugin-based event sources (no kernel instrumentation), use Deployment mode:

```bash
cat <<EOF | kubectl apply -f -
apiVersion: instance.falcosecurity.dev/v1alpha1
kind: Falco
metadata:
  name: falco-plugins
  namespace: falco-plugins
spec:
  type: Deployment
  replicas: 1
EOF
```

## What's Next

- [CRD Reference](crds/) — Full reference for all Custom Resources
- [Configuration](configuration.md) — Default settings and customization options
- [Architecture](architecture.md) — How the operator works internally
