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
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/falcosecurity/falco-operator/internal/pkg/image"
)

const (
	// FalcosidekickUITypeName is the type name for the Falcosidekick UI component.
	FalcosidekickUITypeName = "falcosidekick-ui"

	// DefaultRedisAddress is the default Redis service address.
	// Users must provide a Redis instance at this address, or override via podTemplateSpec.
	DefaultRedisAddress = "falcosidekick-ui-redis:6379"
)

// FalcosidekickUIDefaults holds the default configuration for the Falcosidekick UI component.
// NOTE: This component requires an external Redis instance. The default configuration
// expects Redis at "falcosidekick-ui-redis:6379". If Redis is not available, the
// wait-redis init container will block and the pod will stay in Init:0/1 state.
// Users can override the Redis address via podTemplateSpec.
var FalcosidekickUIDefaults = &InstanceDefaults{
	ResourceType:    ResourceTypeDeployment,
	Replicas:        new(int32(2)),
	ContainerName:   "falcosidekick-ui",
	ImageRepository: image.Registry + "/" + image.Repository + "/" + image.FalcosidekickUIImage,
	ImageTag:        image.FalcosidekickUITag,
	DefaultArgs:     []string{"-r", DefaultRedisAddress},
	ImagePullPolicy: corev1.PullIfNotPresent,
	DefaultPorts: []corev1.ContainerPort{
		{ContainerPort: 2802, Name: "http", Protocol: corev1.ProtocolTCP},
	},
	LivenessProbe: &corev1.Probe{
		InitialDelaySeconds: 10,
		TimeoutSeconds:      5,
		PeriodSeconds:       5,
		FailureThreshold:    3,
		SuccessThreshold:    1,
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path: "/api/v1/healthz",
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
				Path: "/api/v1/healthz",
				Port: intstr.FromString("http"),
			},
		},
	},
	PodSecurityContext: &corev1.PodSecurityContext{
		RunAsUser:  new(int64(1234)),
		RunAsGroup: new(int64(1234)),
		FSGroup:    new(int64(1234)),
	},
	// Wait-redis init container: blocks until Redis is reachable.
	// If Redis is not deployed, the pod stays in Init:0/1, signaling the dependency.
	InitContainers: []corev1.Container{
		{
			Name:            "wait-redis",
			Image:           image.RedisRegistry + "/" + image.RedisRepository + "/" + image.RedisImage + ":" + image.RedisTag,
			ImagePullPolicy: corev1.PullIfNotPresent,
			Command:         []string{"sh", "-c"},
			Args: []string{
				`until redis-cli -h "$(echo $REDIS_ADDR | cut -d: -f1)" -p "$(echo $REDIS_ADDR | cut -d: -f2)" ping 2>/dev/null | grep -q PONG; do echo "Waiting for Redis at $REDIS_ADDR..."; sleep 3; done; echo "Redis is ready"`,
			},
			Env: []corev1.EnvVar{
				{Name: "REDIS_ADDR", Value: DefaultRedisAddress},
			},
		},
	},
	ServicePorts: []corev1.ServicePort{
		{Name: "http", Protocol: corev1.ProtocolTCP, Port: 2802, TargetPort: intstr.FromString("http")},
	},
	SupportsDaemonSet: false,
	DeploymentStrategy: &appsv1.DeploymentStrategy{
		Type: appsv1.RollingUpdateDeploymentStrategyType,
	},
}
