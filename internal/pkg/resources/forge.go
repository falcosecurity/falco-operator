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
	"k8s.io/apimachinery/pkg/labels"
)

// forgeMainContainer builds the main container from defaults.
func forgeMainContainer(defs *InstanceDefaults) *corev1.Container {
	return &corev1.Container{
		Name:            defs.ContainerName,
		Image:           defs.ImageRepository + ":" + defs.ImageTag,
		ImagePullPolicy: defs.ImagePullPolicy,
		Resources:       defs.DefaultResources,
		Ports:           defs.DefaultPorts,
		Command:         defs.DefaultCommand,
		Args:            defs.DefaultArgs,
		Env:             defs.EnvVars,
		VolumeMounts:    forgeVolumeMounts(defs),
		StartupProbe:    defs.StartupProbe,
		LivenessProbe:   defs.LivenessProbe,
		ReadinessProbe:  defs.ReadinessProbe,
		SecurityContext: defs.SecurityContext,
	}
}

// forgeVolumes returns defs.Volumes plus the ConfigMap volume if configured.
func forgeVolumes(crName string, defs *InstanceDefaults) []corev1.Volume {
	volumes := append([]corev1.Volume{}, defs.Volumes...)

	if defs.ConfigMapVolume != nil {
		volumes = append(volumes, corev1.Volume{
			Name: defs.ConfigMapVolume.VolumeName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: crName,
					},
				},
			},
		})
	}

	return volumes
}

// forgeVolumeMounts returns defs.VolumeMounts plus the ConfigMap mount if configured.
func forgeVolumeMounts(defs *InstanceDefaults) []corev1.VolumeMount {
	mounts := append([]corev1.VolumeMount{}, defs.VolumeMounts...)

	if defs.ConfigMapVolume != nil {
		mounts = append(mounts, corev1.VolumeMount{
			Name:      defs.ConfigMapVolume.VolumeName,
			MountPath: defs.ConfigMapVolume.MountPath,
			SubPath:   defs.ConfigMapVolume.SubPath,
		})
	}

	return mounts
}

// forgeSelectorLabels returns the standard selector labels for an instance.
func forgeSelectorLabels(name string) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":     name,
		"app.kubernetes.io/instance": name,
	}
}

// forgePodTemplateSpecLabels returns the labels for a pod template spec,
// merging base labels with the standard selector labels.
func forgePodTemplateSpecLabels(appName string, baseLabels map[string]string) map[string]string {
	return labels.Merge(baseLabels, forgeSelectorLabels(appName))
}

// forgeDeploymentStrategy returns the given strategy or defaults to RollingUpdate.
func forgeDeploymentStrategy(strategy *appsv1.DeploymentStrategy) appsv1.DeploymentStrategy {
	if strategy != nil {
		return *strategy
	}
	return appsv1.DeploymentStrategy{
		Type: appsv1.RollingUpdateDeploymentStrategyType,
	}
}

// forgeDaemonSetUpdateStrategy returns the given strategy or defaults to RollingUpdate.
func forgeDaemonSetUpdateStrategy(strategy *appsv1.DaemonSetUpdateStrategy) appsv1.DaemonSetUpdateStrategy {
	if strategy != nil {
		return *strategy
	}
	return appsv1.DaemonSetUpdateStrategy{
		Type: appsv1.RollingUpdateDaemonSetStrategyType,
	}
}
