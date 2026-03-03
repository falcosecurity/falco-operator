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
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/falcosecurity/falco-operator/internal/pkg/image"
)

const (
	// MetacollectorTypeName is the type name for the metacollector instance.
	MetacollectorTypeName = "metacollector"
)

// MetacollectorDefaults holds the default configuration for the Metacollector instance type.
var MetacollectorDefaults = &InstanceDefaults{
	ResourceType:    ResourceTypeDeployment,
	Replicas:        new(int32(1)),
	ContainerName:   "metacollector",
	ImageRepository: image.Registry + "/" + image.Repository + "/" + image.MetacollectorImage,
	ImageTag:        image.MetacollectorTag,
	DefaultCommand:  []string{"/meta-collector"},
	DefaultArgs:     []string{"run"},
	ImagePullPolicy: corev1.PullIfNotPresent,
	DefaultPorts: []corev1.ContainerPort{
		{Name: "metrics", ContainerPort: 8080, Protocol: corev1.ProtocolTCP},
		{Name: "health-probe", ContainerPort: 8081, Protocol: corev1.ProtocolTCP},
		{Name: "broker-grpc", ContainerPort: 45000, Protocol: corev1.ProtocolTCP},
	},
	DefaultResources: corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("100m"),
			corev1.ResourceMemory: resource.MustParse("128Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("250m"),
			corev1.ResourceMemory: resource.MustParse("256Mi"),
		},
	},
	LivenessProbe: &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path: "/healthz",
				Port: intstr.FromInt32(8081),
			},
		},
		InitialDelaySeconds: 45,
		TimeoutSeconds:      5,
		PeriodSeconds:       15,
	},
	ReadinessProbe: &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path: "/readyz",
				Port: intstr.FromInt32(8081),
			},
		},
		InitialDelaySeconds: 30,
		TimeoutSeconds:      5,
		PeriodSeconds:       15,
	},
	SecurityContext: &corev1.SecurityContext{
		AllowPrivilegeEscalation: new(false),
		Capabilities: &corev1.Capabilities{
			Drop: []corev1.Capability{"ALL"},
		},
	},
	PodSecurityContext: &corev1.PodSecurityContext{
		RunAsNonRoot: new(true),
		RunAsUser:    new(int64(1000)),
		RunAsGroup:   new(int64(1000)),
		FSGroup:      new(int64(1000)),
	},
	ServicePorts: []corev1.ServicePort{
		{Name: "metrics", Protocol: corev1.ProtocolTCP, Port: 8080, TargetPort: intstr.FromInt32(8080)},
		{Name: "health-probe", Protocol: corev1.ProtocolTCP, Port: 8081, TargetPort: intstr.FromInt32(8081)},
		{Name: "broker-grpc", Protocol: corev1.ProtocolTCP, Port: 45000, TargetPort: intstr.FromInt32(45000)},
	},
	ClusterRoleRules: []rbacv1.PolicyRule{
		{
			APIGroups: []string{"apps"},
			Resources: []string{"daemonsets", "deployments", "replicasets"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"endpoints", "namespaces", "pods", "replicationcontrollers", "services"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"discovery.k8s.io"},
			Resources: []string{"endpointslices"},
			Verbs:     []string{"get", "list", "watch"},
		},
	},
	SupportsDaemonSet: false,
}
