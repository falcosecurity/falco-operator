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

package falco

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/image"
	"github.com/falcosecurity/falco-operator/internal/pkg/instance"
)

// generateApplyConfiguration generates apply configuration for falco resources.
// It creates a resource based on the falco CR and merges it with the user-defined one.
// The resource type is determined by the falco CR spec, and it can be either a Deployment or a DaemonSet.
func generateApplyConfiguration(cl client.Client, falco *v1alpha1.Falco,
	nativeSidecar bool) (*unstructured.Unstructured, error) {
	merged, err := mergeWorkloadConfiguration(nativeSidecar, falco)
	if err != nil {
		return nil, err
	}

	return instance.GenerateResource(
		cl,
		falco,
		func(_ *v1alpha1.Falco) runtime.Object { return merged },
		instance.GenerateOptions{
			SetControllerRef: true,
			IsClusterScoped:  false,
		},
	)
}

// mergeWorkloadConfiguration merges the base workload (Deployment or DaemonSet)
// with user-defined overrides from PodTemplateSpec.
func mergeWorkloadConfiguration(nativeSidecar bool, falco *v1alpha1.Falco) (*unstructured.Unstructured, error) {
	resourceType := falco.Spec.Type

	var baseResource runtime.Object
	switch resourceType {
	case instance.ResourceTypeDeployment:
		baseResource = baseDeployment(nativeSidecar, falco)
	case instance.ResourceTypeDaemonSet:
		baseResource = baseDaemonSet(nativeSidecar, falco)
	default:
		return nil, fmt.Errorf("unsupported resource type: %s", resourceType)
	}

	userUnstructured, err := generateUserDefinedResource(nativeSidecar, falco)
	if err != nil {
		return nil, err
	}

	return instance.MergeApplyConfiguration(resourceType, baseResource, userUnstructured)
}

// baseDeployment returns the base deployment for Falco with default values + metadata coming from the Falco CR.
func baseDeployment(nativeSidecar bool, falco *v1alpha1.Falco) *appsv1.Deployment {
	dpl := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      falco.Name,
			Namespace: falco.Namespace,
			Labels:    falco.Labels,
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app.kubernetes.io/name":     falco.Name,
					"app.kubernetes.io/instance": falco.Name,
				},
			},
			Replicas: falco.Spec.Replicas,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: instance.PodTemplateSpecLabels(falco.Name, falco.Labels),
				},
				Spec: corev1.PodSpec{
					Tolerations: []corev1.Toleration{
						{Key: "node-role.kubernetes.io/master", Effect: corev1.TaintEffectNoSchedule},
						{Key: "node-role.kubernetes.io/control-plane", Effect: corev1.TaintEffectNoSchedule},
					},
					ServiceAccountName: falco.Name,
					Volumes:            falcoVolumes(falco),
					Containers: []corev1.Container{
						{
							Name:            containerName,
							Image:           image.BuildFalcoImageStringFromVersion(falco.Spec.Version),
							ImagePullPolicy: DefaultFalcoImagePullPolicy,
							Resources:       DefaultFalcoResources,
							Ports:           DefaultFalcoPorts,
							Args:            DefaultFalcoArgs,
							Env:             DefaultFalcoEnv,
							VolumeMounts:    falcoVolumeMounts(),
							LivenessProbe:   DefaultFalcoLivenessProbe,
							ReadinessProbe:  DefaultFalcoReadinessProbe,
							SecurityContext: DefaultFalcoSecurityContext,
						},
					},
				},
			},
			Strategy: instance.DeploymentStrategy(falco.Spec.Strategy),
		},
	}

	if nativeSidecar {
		dpl.Spec.Template.Spec.InitContainers = append(dpl.Spec.Template.Spec.InitContainers, artifactOperatorSidecar)
	} else {
		// If the native sidecar is not enabled, we add the artifact operator sidecar to the container list.
		// And we set the restart policy to nil, otherwise we get a validation error.
		artifactOperatorSidecar.RestartPolicy = nil
		dpl.Spec.Template.Spec.Containers = append(dpl.Spec.Template.Spec.Containers, artifactOperatorSidecar)
	}

	return dpl
}

// baseDaemonSet returns the base daemonset for Falco with default values and metadata coming from the Falco CR.
func baseDaemonSet(nativeSidecar bool, falco *v1alpha1.Falco) *appsv1.DaemonSet {
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      falco.Name,
			Namespace: falco.Namespace,
			Labels:    falco.Labels,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app.kubernetes.io/name":     falco.Name,
					"app.kubernetes.io/instance": falco.Name,
				},
			},
			UpdateStrategy: instance.DaemonSetUpdateStrategy(falco.Spec.UpdateStrategy),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: instance.PodTemplateSpecLabels(falco.Name, falco.Labels),
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: falco.Name,
					Tolerations: []corev1.Toleration{
						{Key: "node-role.kubernetes.io/master", Effect: corev1.TaintEffectNoSchedule},
						{Key: "node-role.kubernetes.io/control-plane", Effect: corev1.TaintEffectNoSchedule},
					},
					Volumes: falcoVolumes(falco),
					Containers: []corev1.Container{
						{
							Name:            containerName,
							Image:           image.BuildFalcoImageStringFromVersion(falco.Spec.Version),
							ImagePullPolicy: DefaultFalcoImagePullPolicy,
							Resources:       DefaultFalcoResources,
							Ports:           DefaultFalcoPorts,
							Args:            DefaultFalcoArgs,
							Env:             DefaultFalcoEnv,
							VolumeMounts:    falcoVolumeMounts(),
							LivenessProbe:   DefaultFalcoLivenessProbe,
							ReadinessProbe:  DefaultFalcoReadinessProbe,
							SecurityContext: DefaultFalcoSecurityContext,
						},
					},
				},
			},
		},
	}

	if nativeSidecar {
		ds.Spec.Template.Spec.InitContainers = append(ds.Spec.Template.Spec.InitContainers, artifactOperatorSidecar)
	} else {
		// If the native sidecar is not enabled, we add the artifact operator sidecar to the containers list.
		// And we set the restart policy to nil otherwise we get a validation error.
		artifactOperatorSidecar.RestartPolicy = nil
		ds.Spec.Template.Spec.Containers = append(ds.Spec.Template.Spec.Containers, artifactOperatorSidecar)
	}

	return ds
}

// generateUserDefinedResource generates a user-defined resource from the falco CR.
func generateUserDefinedResource(nativeSidecar bool, falco *v1alpha1.Falco) (*unstructured.Unstructured, error) {
	// Build the default resource from the base one.
	// We use the base one as a starting point to have the same structure and, then we override the user defined fields.
	var userResource interface{}
	// Determine the resource type from the Falco object.
	resourceType := falco.Spec.Type

	switch resourceType {
	case instance.ResourceTypeDeployment:
		userResource = baseDeployment(nativeSidecar, falco)
	case instance.ResourceTypeDaemonSet:
		userResource = baseDaemonSet(nativeSidecar, falco)
	default:
		return nil, fmt.Errorf("unsupported resource type: %s", resourceType)
	}

	// Set the PodTemplateSpec to the user defined one if present, otherwise set it to an empty one.
	switch res := userResource.(type) {
	case *appsv1.Deployment:
		if falco.Spec.PodTemplateSpec != nil {
			res.Spec.Template = *falco.Spec.PodTemplateSpec
		} else {
			res.Spec.Template = corev1.PodTemplateSpec{}
		}
		if falco.Spec.Strategy != nil {
			res.Spec.Strategy = *falco.Spec.Strategy
		}
	case *appsv1.DaemonSet:
		if falco.Spec.PodTemplateSpec != nil {
			res.Spec.Template = *falco.Spec.PodTemplateSpec
		} else {
			res.Spec.Template = corev1.PodTemplateSpec{}
		}
		if falco.Spec.UpdateStrategy != nil {
			res.Spec.UpdateStrategy = *falco.Spec.UpdateStrategy
		}
	}

	// Convert to unstructured and remove the fields we don't want to compare.
	unUserResource, err := runtime.DefaultUnstructuredConverter.ToUnstructured(userResource)
	if err != nil {
		return nil, err
	}

	resource := &unstructured.Unstructured{
		Object: unUserResource,
	}

	// Remove the empty containers field if it exists.
	if instance.RemoveEmptyContainers(resource) != nil {
		return nil, err
	}

	return resource, nil
}

// falcoVolumes returns the volumes for the Falco container.
func falcoVolumes(falco *v1alpha1.Falco) []corev1.Volume {
	volumes := append([]corev1.Volume{}, DefaultFalcoVolumes...)

	// Add ConfigMap volume for Falco configuration.
	configVolume := corev1.Volume{
		Name: "falco-config-default",
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: falco.Name,
				},
			},
		},
	}

	return append(volumes, configVolume)
}

func falcoVolumeMounts() []corev1.VolumeMount {
	volumeMounts := append([]corev1.VolumeMount{}, DefaultFalcoVolumeMounts...)

	configVolumeMount := corev1.VolumeMount{
		Name:      "falco-config-default",
		MountPath: "/etc/falco/falco.yaml",
		SubPath:   "falco.yaml",
	}

	return append(volumeMounts, configVolumeMount)
}
