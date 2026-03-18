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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

const (
	// ResourceTypeDeployment is the resource type for Deployment.
	ResourceTypeDeployment string = "Deployment"
	// ResourceTypeDaemonSet is the resource type for DaemonSet.
	ResourceTypeDaemonSet string = "DaemonSet"
)

// ConfigMapVolumeConfig describes how to mount the instance's ConfigMap as a volume.
// The ConfigMap name is derived from the CR name at runtime.
type ConfigMapVolumeConfig struct {
	VolumeName string
	MountPath  string
	SubPath    string
}

// InstanceDefaults defines all the default configuration for an instance controller.
// Each instance type (falco, metacollector, etc.) registers its own defaults.
type InstanceDefaults struct {
	// ResourceType is the default workload kind ("Deployment" or "DaemonSet").
	ResourceType string

	// Replicas is the default number of replicas (nil = no default, Kubernetes uses 1).
	Replicas *int32

	// Container
	ContainerName        string
	SidecarContainerName string
	ImageRepository      string
	ImageTag             string
	DefaultCommand       []string
	DefaultArgs          []string
	ImagePullPolicy      corev1.PullPolicy
	DefaultPorts         []corev1.ContainerPort
	DefaultResources     corev1.ResourceRequirements
	StartupProbe         *corev1.Probe
	LivenessProbe        *corev1.Probe
	ReadinessProbe       *corev1.Probe
	SecurityContext      *corev1.SecurityContext
	PodSecurityContext   *corev1.PodSecurityContext
	EnvVars              []corev1.EnvVar

	// Tolerations
	Tolerations []corev1.Toleration

	// Service (nil = no Service created)
	ServicePorts []corev1.ServicePort

	// RBAC (nil = no resource created)
	ClusterRoleRules []rbacv1.PolicyRule
	RoleRules        []rbacv1.PolicyRule

	// Volumes
	Volumes      []corev1.Volume
	VolumeMounts []corev1.VolumeMount

	// ConfigMap (nil = no ConfigMap created).
	// Key is the workload type ("Deployment", "DaemonSet"); value maps file names to content.
	ConfigMapData map[string]map[string]string

	// ConfigMapVolume defines how to mount the instance ConfigMap (nil = no ConfigMap volume).
	ConfigMapVolume *ConfigMapVolumeConfig

	// InitContainers are added as true init containers (run to completion before main).
	InitContainers []corev1.Container

	// Sidecar containers (nil = no sidecar).
	SidecarContainers []corev1.Container

	// SupportsDaemonSet indicates whether this instance type supports DaemonSet workloads.
	SupportsDaemonSet bool

	// DeploymentStrategy is the default deployment strategy (nil = no default).
	DeploymentStrategy *appsv1.DeploymentStrategy

	// DaemonSetUpdateStrategy is the default daemonset update strategy (nil = no default).
	DaemonSetUpdateStrategy *appsv1.DaemonSetUpdateStrategy
}
