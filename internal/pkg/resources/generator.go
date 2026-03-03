// Copyright (C) 2026 The Falco Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package resources

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/falcosecurity/falco-operator/internal/pkg/builders"
)

// GenerateWorkload builds a base Deployment or DaemonSet from defaults and CR params.
func GenerateWorkload(resourceType string, meta *metav1.ObjectMeta, defs *InstanceDefaults, nativeSidecar bool) (runtime.Object, error) {
	switch resourceType {
	case ResourceTypeDeployment:
		return generateDeployment(meta, defs, nativeSidecar), nil
	case ResourceTypeDaemonSet:
		if !defs.SupportsDaemonSet {
			return nil, fmt.Errorf("resource type %s is not supported for this instance type", resourceType)
		}
		return generateDaemonSet(meta, defs, nativeSidecar), nil
	default:
		return nil, fmt.Errorf("unsupported resource type: %s", resourceType)
	}
}

// generateDeployment builds a base Deployment from defaults only.
func generateDeployment(meta *metav1.ObjectMeta, defs *InstanceDefaults, nativeSidecar bool) *appsv1.Deployment {
	b := builders.NewDeployment().
		WithName(meta.Name).
		WithNamespace(meta.Namespace).
		WithSelector(forgeSelectorLabels(meta.Name)).
		WithReplicas(defs.Replicas).
		WithPodTemplateLabels(forgeSelectorLabels(meta.Name)).
		WithTolerations(defs.Tolerations).
		WithServiceAccount(meta.Name).
		WithPodSecurityContext(defs.PodSecurityContext).
		WithVolumes(forgeVolumes(meta.Name, defs)).
		AddContainer(forgeMainContainer(defs)).
		WithStrategy(forgeDeploymentStrategy(defs.DeploymentStrategy))

	addSidecarContainers(b, nativeSidecar, defs)

	return b.Build()
}

// generateDaemonSet builds a base DaemonSet from defaults only.
func generateDaemonSet(meta *metav1.ObjectMeta, defs *InstanceDefaults, nativeSidecar bool) *appsv1.DaemonSet {
	b := builders.NewDaemonSet().
		WithName(meta.Name).
		WithNamespace(meta.Namespace).
		WithSelector(forgeSelectorLabels(meta.Name)).
		WithPodTemplateLabels(forgeSelectorLabels(meta.Name)).
		WithTolerations(defs.Tolerations).
		WithServiceAccount(meta.Name).
		WithPodSecurityContext(defs.PodSecurityContext).
		WithVolumes(forgeVolumes(meta.Name, defs)).
		AddContainer(forgeMainContainer(defs)).
		WithUpdateStrategy(forgeDaemonSetUpdateStrategy(defs.DaemonSetUpdateStrategy))

	addSidecarContainers(b, nativeSidecar, defs)

	return b.Build()
}

// addSidecarContainers adds the sidecar containers from defaults to the builder.
func addSidecarContainers(b any, nativeSidecar bool, defs *InstanceDefaults) {
	for i := range defs.SidecarContainers {
		sidecar := defs.SidecarContainers[i]
		switch builder := b.(type) {
		case *builders.DeploymentBuilder:
			if nativeSidecar {
				builder.AddInitContainer(&sidecar)
			} else {
				sidecar.RestartPolicy = nil
				builder.AddContainer(&sidecar)
			}
		case *builders.DaemonSetBuilder:
			if nativeSidecar {
				builder.AddInitContainer(&sidecar)
			} else {
				sidecar.RestartPolicy = nil
				builder.AddContainer(&sidecar)
			}
		}
	}
}

// GenerateService generates a Service from the given object and defaults.
func GenerateService(obj client.Object, defs *InstanceDefaults) runtime.Object {
	b := builders.NewService().
		WithName(obj.GetName()).
		WithNamespace(obj.GetNamespace()).
		WithLabels(obj.GetLabels()).
		WithType(corev1.ServiceTypeClusterIP).
		WithSelector(forgeSelectorLabels(obj.GetName()))

	for i := range defs.ServicePorts {
		b.AddPort(&defs.ServicePorts[i])
	}

	return b.Build()
}

// GenerateServiceAccount generates a ServiceAccount for the given object.
func GenerateServiceAccount(obj client.Object) runtime.Object {
	return builders.NewServiceAccount().
		WithName(obj.GetName()).
		WithNamespace(obj.GetNamespace()).
		WithLabels(obj.GetLabels()).
		Build()
}

// GenerateClusterRole generates a ClusterRole from the given defaults.
func GenerateClusterRole(obj client.Object, defs *InstanceDefaults) runtime.Object {
	resourceName := GenerateUniqueName(obj.GetName(), obj.GetNamespace())

	b := builders.NewClusterRole().
		WithName(resourceName).
		WithLabels(obj.GetLabels())

	for i := range defs.ClusterRoleRules {
		b.AddRule(&defs.ClusterRoleRules[i])
	}

	return b.Build()
}

// GenerateClusterRoleBinding generates a ClusterRoleBinding for the given object.
func GenerateClusterRoleBinding(obj client.Object) runtime.Object {
	resourceName := GenerateUniqueName(obj.GetName(), obj.GetNamespace())

	return builders.NewClusterRoleBinding().
		WithName(resourceName).
		WithLabels(obj.GetLabels()).
		AddSubject(rbacv1.Subject{
			Kind:      "ServiceAccount",
			Name:      obj.GetName(),
			Namespace: obj.GetNamespace(),
		}).
		WithRoleRef(rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     resourceName,
			APIGroup: "rbac.authorization.k8s.io",
		}).
		Build()
}

// GenerateRole generates a Role from the given defaults.
func GenerateRole(obj client.Object, defs *InstanceDefaults) runtime.Object {
	b := builders.NewRole().
		WithName(obj.GetName()).
		WithNamespace(obj.GetNamespace()).
		WithLabels(obj.GetLabels())

	for i := range defs.RoleRules {
		b.AddRule(&defs.RoleRules[i])
	}

	return b.Build()
}

// GenerateRoleBinding generates a RoleBinding for the given object.
func GenerateRoleBinding(obj client.Object) runtime.Object {
	return builders.NewRoleBinding().
		WithName(obj.GetName()).
		WithNamespace(obj.GetNamespace()).
		WithLabels(obj.GetLabels()).
		AddSubject(rbacv1.Subject{
			Kind:      "ServiceAccount",
			Name:      obj.GetName(),
			Namespace: obj.GetNamespace(),
		}).
		WithRoleRef(rbacv1.RoleRef{
			Kind:     "Role",
			Name:     obj.GetName(),
			APIGroup: "rbac.authorization.k8s.io",
		}).
		Build()
}

// GenerateConfigMap generates a ConfigMap from the given defaults and workload type.
func GenerateConfigMap(obj client.Object, defs *InstanceDefaults, workloadType string) (runtime.Object, error) {
	data, ok := defs.ConfigMapData[workloadType]
	if !ok {
		return nil, fmt.Errorf("no ConfigMap data for workload type %q", workloadType)
	}

	return builders.NewConfigMap().
		WithName(obj.GetName()).
		WithNamespace(obj.GetNamespace()).
		WithLabels(obj.GetLabels()).
		WithData(data).
		Build(), nil
}
