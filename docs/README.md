# Falco Operator Documentation

Complete documentation for the [Falco Operator](https://github.com/falcosecurity/falco-operator) — the Kubernetes-native way to deploy and manage [Falco](https://falco.org).

## Contents

| Document | Description |
|----------|-------------|
| [Installation](installation.md) | Install the operator and prerequisites |
| [Getting Started](getting-started.md) | Deploy Falco and add rules in minutes |
| [Architecture](architecture.md) | Components, interactions, and design decisions |
| [Configuration](configuration.md) | Default settings and customization |
| [Migration Guide](migration-guide.md) | Upgrade from v0.1.x to v0.2.0 |
| [Contributing](contributing.md) | Development setup, testing, and PR guidelines |

| CRD Reference | Description |
|-------------------|-------------|
| &nbsp;&nbsp;[Falco](crds/falco.md) | Falco instance lifecycle management |
| &nbsp;&nbsp;[Rulesfile](crds/rulesfile.md) | Detection rules from OCI, inline, or ConfigMap |
| &nbsp;&nbsp;[Plugin](crds/plugin.md) | Plugin management from OCI registries |
| &nbsp;&nbsp;[Config](crds/config.md) | Configuration fragments |
| &nbsp;&nbsp;[Component](crds/component.md) | Companion components (e.g., k8s-metacollector) |


## Quick Links

- **Source code**: [github.com/falcosecurity/falco-operator](https://github.com/falcosecurity/falco-operator)
- **Issues**: [GitHub Issues](https://github.com/falcosecurity/falco-operator/issues)
- **Releases**: [GitHub Releases](https://github.com/falcosecurity/falco-operator/releases)
- **Falco website**: [falco.org](https://falco.org)
- **Falco Slack**: [#falco on Kubernetes Slack](https://kubernetes.slack.com/messages/falco)
