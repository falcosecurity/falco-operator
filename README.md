# Falco Operator

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