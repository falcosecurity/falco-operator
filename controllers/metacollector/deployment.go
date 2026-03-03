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
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/scheme"
)

// generateApplyConfiguration generates the apply configuration for the Metacollector Deployment.
// It creates a base Deployment and merges it with user-defined overrides from PodTemplateSpec.
func generateApplyConfiguration(cl client.Client, mc *instancev1alpha1.Metacollector) (*unstructured.Unstructured, error) {
	return generateResourceFromMetacollectorInstance(
		cl,
		mc,
		func(mc *instancev1alpha1.Metacollector) (runtime.Object, error) {
			baseResource := baseDeployment(mc)

			parser := scheme.Parser()

			baseTyped, err := parser.Type("io.k8s.api.apps.v1.Deployment").FromStructured(baseResource)
			if err != nil {
				return nil, err
			}

			userUnstructured, err := generateUserDefinedResource(mc)
			if err != nil {
				return nil, err
			}

			userTyped, err := parser.Type("io.k8s.api.apps.v1.Deployment").FromUnstructured(userUnstructured.Object)
			if err != nil {
				return nil, err
			}

			desiredTyped, err := baseTyped.Merge(userTyped)
			if err != nil {
				return nil, err
			}

			mergedUnstructured := (desiredTyped.AsValue().Unstructured()).(map[string]interface{})

			desiredResourceUnstructured := &unstructured.Unstructured{
				Object: mergedUnstructured,
			}

			desiredResourceUnstructured.SetGroupVersionKind(schema.GroupVersionKind{
				Group:   appsv1.GroupName,
				Version: appsv1.SchemeGroupVersion.Version,
				Kind:    "Deployment",
			})

			return desiredResourceUnstructured, nil
		},
		generateOptions{
			setControllerRef: true,
			isClusterScoped:  false,
		},
	)
}

// metacollectorImage builds the full image string from version.
func metacollectorImage(version string) string {
	if version == "" {
		version = DefaultVersion
	}
	return fmt.Sprintf("%s:%s", DefaultImage, version)
}

// deploymentStrategy returns the deployment strategy from the Metacollector CR or the default RollingUpdate.
func deploymentStrategy(mc *instancev1alpha1.Metacollector) appsv1.DeploymentStrategy {
	if mc.Spec.Strategy != nil {
		return *mc.Spec.Strategy
	}
	return appsv1.DeploymentStrategy{
		Type: appsv1.RollingUpdateDeploymentStrategyType,
	}
}

// baseDeployment returns the base Deployment for Metacollector with default values.
func baseDeployment(mc *instancev1alpha1.Metacollector) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      mc.Name,
			Namespace: mc.Namespace,
			Labels:    mc.Labels,
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app.kubernetes.io/name":     mc.Name,
					"app.kubernetes.io/instance": mc.Name,
				},
			},
			Replicas: mc.Spec.Replicas,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: podTemplateSpecLabels(mc.Name, mc.Labels),
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: mc.Name,
					SecurityContext:    DefaultPodSecurityContext,
					Containers: []corev1.Container{
						{
							Name:            "metacollector",
							Image:           metacollectorImage(mc.Spec.Version),
							ImagePullPolicy: DefaultImagePullPolicy,
							Args:            DefaultArgs,
							Ports:           DefaultPorts,
							Resources:       DefaultResources,
							LivenessProbe:   DefaultLivenessProbe,
							ReadinessProbe:  DefaultReadinessProbe,
							SecurityContext: DefaultSecurityContext,
						},
					},
				},
			},
			Strategy: deploymentStrategy(mc),
		},
	}
}

// generateUserDefinedResource generates a user-defined resource from the Metacollector CR.
func generateUserDefinedResource(mc *instancev1alpha1.Metacollector) (*unstructured.Unstructured, error) {
	userResource := baseDeployment(mc)

	if mc.Spec.PodTemplateSpec != nil {
		userResource.Spec.Template = *mc.Spec.PodTemplateSpec
	} else {
		userResource.Spec.Template = corev1.PodTemplateSpec{}
	}
	if mc.Spec.Strategy != nil {
		userResource.Spec.Strategy = *mc.Spec.Strategy
	}

	unUserResource, err := runtime.DefaultUnstructuredConverter.ToUnstructured(userResource)
	if err != nil {
		return nil, err
	}

	resource := &unstructured.Unstructured{
		Object: unUserResource,
	}

	if removeEmptyContainers(resource) != nil {
		return nil, err
	}

	return resource, nil
}

// removeEmptyContainers removes the empty containers field from the unstructured Deployment if it exists.
func removeEmptyContainers(obj *unstructured.Unstructured) error {
	if templateSpec, found, err := unstructured.NestedMap(obj.Object, "spec", "template", "spec"); err != nil {
		return fmt.Errorf("failed to get podSpec from podTemplateSpec: %w", err)
	} else if !found {
		return fmt.Errorf("podSpec not found in podTemplateSpec")
	} else {
		if containers, ok := templateSpec["containers"]; ok {
			if containers == nil {
				unstructured.RemoveNestedField(obj.Object, "spec", "template", "spec", "containers")
			}
		}
	}
	return nil
}

// podTemplateSpecLabels returns the labels for the pod template spec.
func podTemplateSpecLabels(appName string, baseLabels map[string]string) map[string]string {
	return labels.Merge(baseLabels, map[string]string{
		"app.kubernetes.io/name":     appName,
		"app.kubernetes.io/instance": appName,
	})
}
