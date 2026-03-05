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

package metacollector

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
)

var (
	// DefaultArgs are the default arguments for the metacollector container.
	DefaultArgs = []string{"/meta-collector", "run"}

	// DefaultImagePullPolicy is the default image pull policy for the metacollector container.
	DefaultImagePullPolicy = corev1.PullIfNotPresent

	// DefaultPorts are the default container ports for the metacollector.
	DefaultPorts = []corev1.ContainerPort{
		{Name: "metrics", ContainerPort: 8080, Protocol: corev1.ProtocolTCP},
		{Name: "health-probe", ContainerPort: 8081, Protocol: corev1.ProtocolTCP},
		{Name: "broker-grpc", ContainerPort: 45000, Protocol: corev1.ProtocolTCP},
	}

	// DefaultResources are the default resource requirements for the metacollector container.
	DefaultResources = corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("100m"),
			corev1.ResourceMemory: resource.MustParse("128Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("250m"),
			corev1.ResourceMemory: resource.MustParse("256Mi"),
		},
	}

	// DefaultLivenessProbe is the default liveness probe for the metacollector container.
	DefaultLivenessProbe = &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path: "/healthz",
				Port: intstr.FromInt32(8081),
			},
		},
		InitialDelaySeconds: 15,
		PeriodSeconds:       20,
	}

	// DefaultReadinessProbe is the default readiness probe for the metacollector container.
	DefaultReadinessProbe = &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path: "/readyz",
				Port: intstr.FromInt32(8081),
			},
		},
		InitialDelaySeconds: 5,
		PeriodSeconds:       10,
	}

	// DefaultSecurityContext is the default security context for the metacollector container.
	DefaultSecurityContext = &corev1.SecurityContext{
		AllowPrivilegeEscalation: ptr.To(false),
		Capabilities: &corev1.Capabilities{
			Drop: []corev1.Capability{"ALL"},
		},
	}

	// DefaultPodSecurityContext is the default pod security context for the metacollector pod.
	DefaultPodSecurityContext = &corev1.PodSecurityContext{
		RunAsNonRoot: ptr.To(true),
		RunAsUser:    ptr.To(int64(1000)),
		RunAsGroup:   ptr.To(int64(1000)),
		FSGroup:      ptr.To(int64(1000)),
	}
)
