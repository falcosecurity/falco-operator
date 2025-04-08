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
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/image"
	"github.com/falcosecurity/falco-operator/internal/pkg/scheme"
)

const (
	resourceTypeDeployment = "Deployment"
	resourceTypeDaemonSet  = "DaemonSet"
)

// generateApplyConfiguration generates the apply configuration for the given Kubernetes resource.
func generateApplyConfiguration(ctx context.Context, cl client.Client, falco *v1alpha1.Falco, nativeSidecar bool) (*unstructured.Unstructured, error) {
	// Determine the resource type from the Falco object.
	resourceType := falco.Spec.Type

	// Build the default resource.
	var baseResource interface{}
	switch resourceType {
	case resourceTypeDeployment:
		baseResource = baseDeployment(nativeSidecar, falco)
	case resourceTypeDaemonSet:
		baseResource = baseDaemonSet(nativeSidecar, falco)
	default:
		// Should never happen, since the type is validated by the CRD.
		return nil, fmt.Errorf("unsupported resource type: %s", resourceType)
	}

	// Create a parser to merge the base resource with the user defined one.
	parser := scheme.Parser()

	// Parse the base resource.
	baseTyped, err := parser.Type("io.k8s.api.apps.v1." + resourceType).FromStructured(baseResource)
	if err != nil {
		return nil, err
	}

	// Generate the user defined resource.
	userUnstructured, err := generateUserDefinedResource(nativeSidecar, falco)
	if err != nil {
		return nil, err
	}

	// Parse the user defined resource.
	userTyped, err := parser.Type("io.k8s.api.apps.v1." + resourceType).FromUnstructured(userUnstructured.Object)
	if err != nil {
		return nil, err
	}

	// Merge the base and user defined resources.
	desiredTyped, err := baseTyped.Merge(userTyped)
	if err != nil {
		return nil, err
	}

	mergedUnstructured := (desiredTyped.AsValue().Unstructured()).(map[string]interface{})

	desiredResourceUnstructured := &unstructured.Unstructured{
		Object: mergedUnstructured,
	}

	if err := setDefaultValues(ctx, cl, desiredResourceUnstructured, schema.GroupVersionKind{
		Group:   appsv1.GroupName,
		Version: appsv1.SchemeGroupVersion.Version,
		Kind:    resourceType,
	}); err != nil {
		return nil, err
	}

	// Set the name of the resource to the name of the falco CR.
	if err := unstructured.SetNestedField(desiredResourceUnstructured.Object, falco.Name, "metadata", "name"); err != nil {
		return nil, fmt.Errorf("failed to set name field: %w", err)
	}

	// Remove unwanted fields.
	removeUnwantedFields(desiredResourceUnstructured)

	return desiredResourceUnstructured, nil
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
					Labels: podTemplateSpecLabels(falco.Name, falco.Labels),
				},
				Spec: corev1.PodSpec{
					Tolerations: []corev1.Toleration{
						{Key: "node-role.kubernetes.io/master", Effect: corev1.TaintEffectNoSchedule},
						{Key: "node-role.kubernetes.io/control-plane", Effect: corev1.TaintEffectNoSchedule},
					},
					Volumes: DefaultFalcoVolumes,
					Containers: []corev1.Container{
						{
							Name:            "falco",
							Image:           image.BuildFalcoImageStringFromVersion(falco.Spec.Version),
							ImagePullPolicy: DefaultFalcoImagePullPolicy,
							Resources:       DefaultFalcoResources,
							Ports:           DefaultFalcoPorts,
							Args:            DefaultFalcoArgs,
							Env:             DefaultFalcoEnv,
							VolumeMounts:    DefaultFalcoVolumeMounts,
							LivenessProbe:   DefaultFalcoLivenessProbe,
							ReadinessProbe:  DefaultFalcoReadinessProbe,
							SecurityContext: DefaultFalcoSecurityContext,
						},
					},
					InitContainers: []corev1.Container{
						artifactOperatorSidecar,
					},
				},
			},
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
			},
		},
	}

	if nativeSidecar {
		dpl.Spec.Template.Spec.InitContainers = append(dpl.Spec.Template.Spec.InitContainers, artifactOperatorSidecar)
	} else {
		dpl.Spec.Template.Spec.Containers = append(dpl.Spec.Template.Spec.Containers, artifactOperatorSidecar)
	}

	return dpl
}

// baseDaemonSet returns the base daemonset for Falco with default values + metadata coming from the Falco CR.
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
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: podTemplateSpecLabels(falco.Name, falco.Labels),
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
							Name:            "falco",
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
		ds.Spec.Template.Spec.Containers = append(ds.Spec.Template.Spec.Containers, artifactOperatorSidecar)
	}

	return ds
}

// generateUserDefinedResource generates a user defined resource from the falco CR.
func generateUserDefinedResource(nativeSidecar bool, falco *v1alpha1.Falco) (*unstructured.Unstructured, error) {
	// Build the default resource from the base one.
	// We use the base one as a starting point to have the same structure and, then we override the user defined fields.
	var userResource interface{}
	// Determine the resource type from the Falco object.
	resourceType := falco.Spec.Type

	switch resourceType {
	case resourceTypeDeployment:
		userResource = baseDeployment(nativeSidecar, falco)
	case resourceTypeDaemonSet:
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
	case *appsv1.DaemonSet:
		if falco.Spec.PodTemplateSpec != nil {
			res.Spec.Template = *falco.Spec.PodTemplateSpec
		} else {
			res.Spec.Template = corev1.PodTemplateSpec{}
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
	if removeEmptyContainers(resource) != nil {
		return nil, err
	}

	// Remove unwanted fields.
	removeUnwantedFields(resource)

	return resource, nil
}

// removeEmptyContainers removes the empty containers field from the unstructured DaemonSet if it exists.
func removeEmptyContainers(obj *unstructured.Unstructured) error {
	if templateSpec, found, err := unstructured.NestedMap(obj.Object, "spec", "template", "spec"); err != nil {
		return fmt.Errorf("failed to get podSpec from podTemplateSpec while generating user defined daemonset: %w", err)
	} else if !found {
		// should never happen
		return fmt.Errorf("podSpec not found in podTemplateSpec while generating user defined daemonset")
	} else {
		// Get the containers map and remove it if it's empty.
		// We can't leave an empty containers field since it will override the default one when merging with the base daemonset.
		if containers, ok := templateSpec["containers"]; ok {
			if containers == nil {
				unstructured.RemoveNestedField(obj.Object, "spec", "template", "spec", "containers")
			}
		}
	}
	return nil
}

// removeUnwantedFields removes unwanted fields from the unstructured object.
func removeUnwantedFields(obj *unstructured.Unstructured) {
	unstructured.RemoveNestedField(obj.Object, "metadata", "uid")
	unstructured.RemoveNestedField(obj.Object, "metadata", "resourceVersion")
	unstructured.RemoveNestedField(obj.Object, "metadata", "managedFields")
	unstructured.RemoveNestedField(obj.Object, "status")
	unstructured.RemoveNestedField(obj.Object, "metadata", "creationTimestamp")
	unstructured.RemoveNestedField(obj.Object, "spec", "template", "metadata", "creationTimestamp")
	unstructured.RemoveNestedField(obj.Object, "spec", "revisionHistoryLimit")
	unstructured.RemoveNestedField(obj.Object, "metadata", "generateName")
	unstructured.RemoveNestedField(obj.Object, "metadata", "generation")
	// Remove the revision field from the annotations.
	unstructured.RemoveNestedField(obj.Object, "metadata", "annotations", "deployment.kubernetes.io/revision")
	// Remove the deprecated field from the annotations.
	unstructured.RemoveNestedField(obj.Object, "metadata", "annotations", "deprecated.daemonset.template.generation")
	// If the annotations field is empty, remove it.
	if metadata, ok := obj.Object["metadata"].(map[string]interface{}); ok {
		if annotations, ok := metadata["annotations"].(map[string]interface{}); ok {
			if len(annotations) == 0 {
				unstructured.RemoveNestedField(obj.Object, "metadata", "annotations")
			}
		}
	}
	// Only for services, remove the clusterIP and clusterIPs fields.
	if obj.GetKind() == "Service" {
		unstructured.RemoveNestedField(obj.Object, "spec", "clusterIP")
		unstructured.RemoveNestedField(obj.Object, "spec", "clusterIPs")
	}
}

// podTemplateSpecLabels returns the labels for the pod template spec.
func podTemplateSpecLabels(appName string, baseLabels map[string]string) map[string]string {
	return labels.Merge(baseLabels, map[string]string{
		"app.kubernetes.io/name":     appName,
		"app.kubernetes.io/instance": appName,
	})
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

// setDefaultValues sets the default values for the unstructured object by dry-run creating it.
func setDefaultValues(ctx context.Context, cl client.Client, obj *unstructured.Unstructured, gvk schema.GroupVersionKind) error {
	if err := unstructured.SetNestedField(obj.Object, "dry-run", "metadata", "generateName"); err != nil {
		return fmt.Errorf("failed to set generateName field: %w", err)
	}

	if err := unstructured.SetNestedField(obj.Object, "", "metadata", "name"); err != nil {
		return fmt.Errorf("failed to set name field: %w", err)
	}

	obj.SetKind(gvk.Kind)
	obj.SetAPIVersion(gvk.GroupVersion().String())

	err := cl.Create(ctx, obj, &client.CreateOptions{DryRun: []string{metav1.DryRunAll}})
	if err != nil {
		return fmt.Errorf("failed to set default values by dry-run creating the object %s: %w", gvk.Kind, err)
	}

	return nil
}
