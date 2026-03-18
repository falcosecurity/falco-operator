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
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/falcosecurity/falco-operator/internal/pkg/image"
)

const (
	// FalcosidekickTypeName is the type name for the Falcosidekick component.
	FalcosidekickTypeName = "falcosidekick"
)

// FalcosidekickDefaults holds the default configuration for the Falcosidekick component.
var FalcosidekickDefaults = &InstanceDefaults{
	ResourceType:    ResourceTypeDeployment,
	Replicas:        new(int32(2)),
	ContainerName:   "falcosidekick",
	ImageRepository: image.Registry + "/" + image.Repository + "/" + image.FalcosidekickImage,
	ImageTag:        image.FalcosidekickTag,
	ImagePullPolicy: corev1.PullIfNotPresent,
	DefaultPorts: []corev1.ContainerPort{
		{ContainerPort: 2801, Name: "http", Protocol: corev1.ProtocolTCP},
	},
	LivenessProbe: &corev1.Probe{
		InitialDelaySeconds: 10,
		TimeoutSeconds:      5,
		PeriodSeconds:       5,
		FailureThreshold:    3,
		SuccessThreshold:    1,
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path: "/ping",
				Port: intstr.FromString("http"),
			},
		},
	},
	ReadinessProbe: &corev1.Probe{
		InitialDelaySeconds: 10,
		TimeoutSeconds:      5,
		PeriodSeconds:       5,
		FailureThreshold:    3,
		SuccessThreshold:    1,
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path: "/ping",
				Port: intstr.FromString("http"),
			},
		},
	},
	PodSecurityContext: &corev1.PodSecurityContext{
		RunAsUser:  new(int64(1234)),
		RunAsGroup: new(int64(1234)),
		FSGroup:    new(int64(1234)),
	},
	ServicePorts: []corev1.ServicePort{
		{Name: "http", Protocol: corev1.ProtocolTCP, Port: 2801, TargetPort: intstr.FromString("http")},
	},
	// Falcosidekick needs to get endpoints for service discovery.
	RoleRules: []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"endpoints"},
			Verbs:     []string{"get"},
		},
	},
	SupportsDaemonSet: false,
	DeploymentStrategy: &appsv1.DeploymentStrategy{
		Type: appsv1.RollingUpdateDeploymentStrategyType,
	},
}
