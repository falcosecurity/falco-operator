# Falco Operator

[![Falco Ecosystem Repository](https://raw.githubusercontent.com/falcosecurity/evolution/refs/heads/main/repos/badges/falco-ecosystem-blue.svg)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#ecosystem-scope) [![Incubating](https://img.shields.io/badge/status-incubating-orange?style=for-the-badge)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#incubating)
[![Last Release](https://img.shields.io/github/v/release/falcosecurity/falco-operator?style=for-the-badge)](https://github.com/falcosecurity/falco-operator/releases/latest)

![licence](https://img.shields.io/github/license/falcosecurity/falco-operator?style=for-the-badge
)

> **Note:** This project is a work in progress.

## Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Features](#features)
4. [Installation](#installation)
6. [Usage Guide](#usage-guide)
11. [License](#license)

## Overview

The Falco Operator represents a natural evolution in managing Falco deployments in Kubernetes environments. It brings two key components that work together to enhance Falco's usability and management:

### Core Components
- **Falco Operator**: Manages Falco deployments and their lifecycle;
- **Artifact Operator**: Handles rules, configurations, and plugins.

### Key Benefits

**For Users**
- **Simplified Management**: Deploy and configure Falco through Kubernetes custom resources instead of manual configuration;
- **Flexible Deployment Options**:
   - DaemonSet mode for cluster-wide monitoring;
   - Deployment mode for targeted security observations using plugins.
- **Unified Configuration**: Custom Resources (CRs) provide a single, declarative way to specify both Falco instances and their configurations;
- **Version Control**: Track and manage changes to security rules and configurations;
- **Automated Updates**: Rolling updates of Falco instances and configurations without service interruption.

**For Falco**
- **Enhanced Accessibility**: Standardized deployment method reduces adoption barriers;
- **Better Integration**: Native Kubernetes integration improves operational consistency;
- **Configuration Consistency**: Automated management ensures proper configuration across deployments;
- **Scale Management**: Efficiently handle Falco deployments across large clusters.

The Falco Operator transforms Falco from a powerful security tool into a fully integrated Kubernetes security solution, making it more accessible and manageable for teams of all sizes.

## Architecture
The Falco Operator architecture consists of two main components that work together to manage Falco deployments and configurations. The architecture is designed to scale and adapt to various kubernetes environments, providing flexibility and ease of use.
The following diagram illustrates the architecture of the Falco Operator: 

![image](docs/images/falco-operator-architecture.svg "Falco Operator Architecture")

### Falco Operator 
This component is responsible for managing the lifecycle of Falco instances. It handles CR of type `Falco` in group `instance` and ensures that the Falco deployment is created, updated, and deleted as needed. The operator watches for changes in the CR instance and applies the necessary updates to the Falco deployment. Some of the key features of the Falco Operator include:
- **Lifecycle Management**: Automatically manages the lifecycle of Falco instances, including creation, updates, and deletion.
- **Declarative Configuration**: Uses Kubernetes custom resources to define and manage Falco instances, making it easy to deploy and configure Falco in a Kubernetes environment.
- **PodTemplateSpec Management**: Allows users to specify the pod template for the Falco deployment, enabling customization of the Falco instance at every level.
- **Multiple Deployment Modes**: Supports both DaemonSet and Deployment modes, allowing users to choose the best deployment strategy for their use case.
- ** Multiple Instances**: Supports multiple Falco instances in the same cluster, enabling users to run different configurations or versions of Falco as needed.

Falco Operator does not handle the configuration of Falco rules, plugins, or other settings. Instead, it relies on the Artifact Operator to manage these aspects. This separation of concerns allows for a more modular and flexible architecture, where users can choose how they want to manage their Falco configurations. As a result, the Falco Operator deploys the Falco instance with a default configuration, which can be customized through the Artifact Operator.

### Artifact Operator
The Artifact Operator is responsible for managing the rules, configurations, and plugins used by Falco. It handles CR of type `rulesfile`, `plugin`, and `config` in group `artifact` and ensures that the necessary resources are created and updated as needed. The Artifact Operator provides a unified way to manage all aspects of Falco configurations, including:
- **Rules Management**: Allows users to define and manage Falco rules through custom resources, making it easy to customize the security policies enforced by Falco.
- **Plugin Management**: Supports the management of Falco plugins, enabling users to extend Falco's functionality with custom plugins.
- **Configuration Management**: Provides a way to manage Falco configurations, allowing users to customize the behavior of Falco instances.

### Interaction Between Components
The Falco Operator is the primary interface for users to interact with Falco in a Kubernetes environment. It is the only component that users install and manage directly. The Artifact Operator is not directly managed by users but is instead deployed alongside the Falco instance as a sidecar. It ensures that the artifacts are available to the Falco instance and that they are updated as needed. Artifacts are made available to the Falco instance through shared directories (emptyDir volumes) that are mounted in the Falco container. This allows the Falco instance to access the rules, plugins, and configurations managed by the Artifact Operator. Along with the Artifact Operator, the Falco Operator also deploys an init container, DriverLoader, that is responsible for setting up the necessary drivers.

## Features

### Core Deployment Capabilities
- **Declarative Management**: Define and manage Falco configurations using Kubernetes-native declarative approach;
- **Multi-Instance Support**: Deploy and manage multiple Falco instances within the same cluster;
- **Multi-Deployment Modes**: Choose between DaemonSet for cluster-wide monitoring or Deployment for targeted security observations using plugins;
- **Flexible Pod Configuration**: Use PodSpecTemplate to customize Falco deployments at any level, including:
  - Resource allocation;
  - Security contexts;
  - Node placement;
  - Volume configurations;

### Advanced Artifact Management
- **Multiple Source Support**:
  - Inline YAML configurations;
  - OCI artifacts.
- **OCI-Credential Management**:
  - Securely manage OCI artifact credentials using Kubernetes secrets;
  - Support for multiple OCI registries.
- **Priority System**:
  - Primary artifact priorities for ordered configuration application;
  - Sub-priorities within artifact sources (e.g., rules from OCI artifacts and inline rules);
  - Guarantees consistent and predictable policy application.
- **Label-Based Selection**:
  - Use labels to select specific Falco instances for artifact application;

## Installation
Installing the Falco Operator is straightforward and can be done by applying the provided manifests. The operator is designed to be installed in the `falco-operator` namespace, but you can choose a different namespace if needed.
All the necessary resources, including the CRDs, are included in the manifests. To install the Falco Operator, run:
````bash
kubectl apply -f https://github.com/falcosecurity/falco-operator/releases/latest/download/install.yaml
````
After running this command, you can verify that the Falco Operator is running by checking the status of the pods in the `falco-operator` namespace:
```bash
kubectl get pods -n falco-operator
```
The following resources will be created:

1. **Custom Resource Definitions (CRDs)**:
  - `falcos.instance.falcosecurity.dev`
  - `configs.artifact.falcosecurity.dev`
  - `plugins.artifact.falcosecurity.dev`
  - `rulesfiles.artifact.falcosecurity.dev`

2. **Operator Resources**:
  - Namespace: `falco-operator`
  - ServiceAccount: `falco-operator`
  - ClusterRole: `falco-operator-role`
  - ClusterRoleBinding: `falco-operator-rolebinding`
  - Deployment: `falco-operator`

### Required Permissions

The following table outlines the permissions required by the Falco Operator to manage resources in your cluster:

| API Group | Resources | Permissions |
|-----------|-----------|-------------|
| `""` (core) | - pods<br>- nodes<br>- configmaps<br>- secrets<br>- serviceaccounts | - get<br>- list<br>- watch<br>- create<br>- update<br>- delete |
| `apps` | - daemonsets<br>- deployments | - get<br>- list<br>- watch<br>- create<br>- update<br>- delete |
| `instance.falcosecurity.dev` | - falcos | - get<br>- list<br>- watch<br>- create<br>- update<br>- patch<br>- delete |
| `artifact.falcosecurity.dev` | - configs<br>- plugins<br>- rulesfiles | - get<br>- list<br>- watch<br>- create<br>- update<br>- patch<br>- delete |

These permissions are necessary for the operator to manage Falco instances and their associated resources effectively in your Kubernetes cluster.

## Usage Guide
### Creating a Falco Instance
To create a Falco instance, you need to define a custom resource of type `Falco` in the `instance.falcosecurity.dev` API group. Below is an example of how to create a Falco instance using a YAML manifest:

```yaml
apiVersion: instance.falcosecurity.dev/v1alpha1
kind: Falco
metadata:
  labels:
    app.kubernetes.io/name: falco-operator
    app.kubernetes.io/managed-by: kustomize
  name: falco-sample
spec: {}
```
This manifest creates a Falco instance named `falco-sample` with default settings. You can customize the `spec` section to configure the Falco instance according to your requirements.
By default, the Falco Operator will deploy a Falco instance in DaemonSet mode, which means it will run on every node in the cluster. If you want to deploy Falco in Deployment mode, you can specify the `type` field in the `spec` section:

```yaml
apiVersion: instance.falcosecurity.dev/v1alpha1
kind: Falco
metadata:
  labels:
    app.kubernetes.io/name: falco
  name: falco-deployment
  namespace: falco-deployment
spec:
    type: Deployment
```

Obviously, you can customize the `spec` section further to suit your needs, such as specifying resource limits, node selectors, and more. An example that overrides the default PodSpecTemplate is shown below:

```yaml
apiVersion: instance.falcosecurity.dev/v1alpha1
kind: Falco
metadata:
  labels:
    app.kubernetes.io/name: falco
  name: falco-deployment
  namespace: falco-deployment
spec:
    type: Deployment
    podTemplateSpec:
      spec:
        initContainers:
          - name: artifact-operator
            image: my-custom-artifact-image:latest
            imagePullPolicy: Always
        containers:
          - name: falco
            tty: true
            image: my-custom-falco-image:latest
```

**Note:**
Keep in mind that after creating the Falco instance, the Falco Operator will automatically deploy the necessary resources, including the Falco deployment, service account, and any required configurations but not the rules, plugins, or other artifacts. These will be managed by the Artifact Operator. Falco will start in idle mode, meaning it will not actively monitor the system until you provide the necessary rules and configurations.

### Managing Rulesfiles
To manage Falco rules, you can create custom resources of type `Rulesfile` in the `artifact.falcosecurity.dev` API group. Below is an example of how to create a rulesfile:

```yaml
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: Rulesfile
metadata:
  labels:
    app.kubernetes.io/name: falco-operator
  name: falco-rules
spec:
 ociArtifact:
   reference: ghcr.io/falcosecurity/rules/falco-rules:latest
```
This manifest creates a rulesfile named `falco-rules` that references an OCI artifact containing the Falco rules. The Artifact Operator will automatically apply these rules to the Falco instance.

Rulesfiles can also be created inline, as shown below:

```yaml
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: Rulesfile
metadata:
  labels:
    app.kubernetes.io/name: falco-operator
  name: falco-rules
spec:
 inlineRules: |-
   [rules body]
```

### Managing Plugins
To manage Falco plugins, you can create custom resources of type `Plugin` in the `artifact.falcosecurity.dev` API group. Below is an example of how to create a plugin:

```yaml
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: Plugin
metadata:
  labels:
    app.kubernetes.io/name: artifact-plugin
  name: container
spec:
  ociArtifact:
    reference: ghcr.io/falcosecurity/plugins/plugin/container:0.2.4
  config:
    initConfig:
      label_max_len: "100"
      with_size: "false"
```

This manifest creates a plugin named `container` that references an OCI artifact containing the Falco plugin. The Artifact Operator will automatically apply this plugin to the Falco instance and make it available for use. At the same time, it will create the plugin configuration as specified in the `config` section and use it to configure the plugin in Falco.

### Managing Configurations
To manage Falco configurations, you can create custom resources of type `Config` in the `artifact.falcosecurity.dev` API group. Below is an example of how to create a configuration:

```yaml
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: Config
metadata:
  labels:
    app.kubernetes.io/name: falco-config
  name: config-label-selector
  namespace: default
spec:
  config: |-
    libs_logger:
      enabled: true
      severity: debug
  selector:
    matchLabels:
      kubernetes.io/hostname: "node1"
```

This manifest creates a configuration named `config-label-selector` that applies to the Falco instance running on the node with the label `kubernetes.io/hostname: "node1"`. The Artifact Operator will automatically apply this configuration to the Falco instance. As you can see, using the selector field, you can target specific Falco instances based on labels. This allows for fine-grained control over which configurations apply to which Falco instances.

### Label-Based Selection
You can use labels to select specific Falco instances for artifact application. This allows you to apply rules, plugins, or configurations to specific Falco instances based on their labels. For example, if you want to apply a rulesfile only to Falco instances with a specific label, you can use the `selector` field in the rulesfile manifest:

```yaml
apiVersion: artifact.falcosecurity.dev/v1alpha1
kind: Rulesfile
metadata:
  labels:
    app.kubernetes.io/name: falco-operator
  name: CustomRulesForSpecificNode
spec:
    ociArtifact:
        reference: ghcr.io/falcosecurity/rules/custom-rules:latest
    selector:
        matchLabels:
        kubernetes.io/hostname: "node1"
```

## License

This project is licensed to you under the [Apache 2.0](https://github.com/falcosecurity/falco-operator/blob/main/LICENSE) license.
