// Copyright (C) 2025 The Falco Authors
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

package falco

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
)

var (
	// DefaultFalcoImagePullPolicy is the default image pull policy for the Falco container.
	DefaultFalcoImagePullPolicy = corev1.PullIfNotPresent

	// DefaultFalcoArgs are the default arguments for the Falco container.
	DefaultFalcoArgs = []string{"/usr/bin/falco", "-pk"}

	// DefaultFalcoSecurityContext is the default security context for the Falco pod.
	DefaultFalcoSecurityContext = &corev1.SecurityContext{
		Privileged: ptr.To(true),
	}

	// DefaultFalcoEnv are the default environment variables for the Falco container.
	DefaultFalcoEnv = []corev1.EnvVar{
		{Name: "HOST_ROOT", Value: "/host"},
		{
			Name: "FALCO_HOSTNAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
			},
		},
		{
			Name: "FALCO_K8S_NODE_NAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
			},
		},
	}

	// DefaultFalcoResources are the default resource requirements for the Falco container.
	DefaultFalcoResources = corev1.ResourceRequirements{
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("1000m"),
			corev1.ResourceMemory: resource.MustParse("1024Mi"),
		},
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("100m"),
			corev1.ResourceMemory: resource.MustParse("512Mi"),
		},
	}

	// DefaultFalcoPorts are the default ports for the Falco container.
	DefaultFalcoPorts = []corev1.ContainerPort{
		{ContainerPort: 8765, Name: "web", Protocol: corev1.ProtocolTCP},
	}

	// DefaultFalcoLivenessProbe is the default liveness probe for the Falco container.
	DefaultFalcoLivenessProbe = &corev1.Probe{
		InitialDelaySeconds: 60,
		TimeoutSeconds:      5,
		PeriodSeconds:       15,
		FailureThreshold:    3,
		SuccessThreshold:    1,
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path: "/healthz",
				Port: intstr.FromInt32(8765),
			},
		},
	}

	// DefaultFalcoReadinessProbe is the default readiness probe for the Falco container.
	DefaultFalcoReadinessProbe = &corev1.Probe{
		InitialDelaySeconds: 30,
		TimeoutSeconds:      5,
		PeriodSeconds:       15,
		FailureThreshold:    3,
		SuccessThreshold:    1,
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path: "/healthz",
				Port: intstr.FromInt32(8765),
			},
		},
	}

	// DefaultFalcoVolumeMounts are the default volume mounts for the Falco container.
	DefaultFalcoVolumeMounts = []corev1.VolumeMount{
		{Name: "root-falco-fs", MountPath: "/root/.falco"},
		{Name: "proc-fs", MountPath: "/host/proc"},
		{Name: "etc-fs", MountPath: "/host/etc", ReadOnly: true},
		{Name: "dev-fs", MountPath: "/host/dev", ReadOnly: true},
		{Name: "sys-fs", MountPath: "/sys/module"},
		{Name: "docker-socket", MountPath: "/host/var/run/"},
		{Name: "containerd-socket", MountPath: "/host/run/containerd/"},
		{Name: "crio-socket", MountPath: "/host/run/crio/"},
	}

	// DefaultFalcoVolumes are the default volumes for the Falco container.
	DefaultFalcoVolumes = []corev1.Volume{
		{Name: "root-falco-fs", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		{Name: "boot-fs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/boot"}}},
		{Name: "lib-modules", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules"}}},
		{Name: "usr-fs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/usr"}}},
		{Name: "etc-fs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/etc"}}},
		{Name: "dev-fs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/dev"}}},
		{Name: "sys-fs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/module"}}},
		{Name: "docker-socket", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run"}}},
		{Name: "containerd-socket", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/containerd"}}},
		{Name: "crio-socket", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/run/crio"}}},
		{Name: "proc-fs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/proc"}}},
	}
)
