# Falco Operator

[![Falco Ecosystem Repository](https://raw.githubusercontent.com/falcosecurity/evolution/refs/heads/main/repos/badges/falco-ecosystem-blue.svg)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#ecosystem-scope) [![Incubating](https://img.shields.io/badge/status-incubating-orange?style=for-the-badge)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#incubating)
[![Last Release](https://img.shields.io/github/v/release/falcosecurity/falco-operator?style=for-the-badge)](https://github.com/falcosecurity/falco-operator/releases/latest)

![licence](https://img.shields.io/github/license/falcosecurity/falco-operator?style=for-the-badge
)

> **Note:** This project is a work in progress.

The Falco Operator is a Kubernetes operator that manages the lifecycle of Falco, a cloud-native runtime security tool. It automates the deployment, configuration, and management of Falco instances within a Kubernetes cluster.

## Getting Started

### Prerequisites

- Go 1.23 or later
- Docker (for building and running containers)
- Kubernetes cluster (v1.16.0+)
- kubectl (v1.16.0+)
- kustomize (v3.1.0+)
- controller-gen (v0.4.0+)

### Installation

1. **Clone the repository:**

    ```sh
    git clone https://github.com/falcosecurity/falco-operator.git
    cd falco-operator
    ```

2. **Install CRDs:**

    ```sh
    make install
    ```

3. **Deploy the controller to the cluster:**

    ```sh
    make deploy
    ```

### Building

To build the project, run:

```sh
make build
```

## License

Falco Kubernetes Operator is licensed to you under the [Apache 2.0](./LICENSE) open source license.