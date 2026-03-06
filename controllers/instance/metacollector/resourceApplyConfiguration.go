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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/builders"
	"github.com/falcosecurity/falco-operator/internal/pkg/image"
	"github.com/falcosecurity/falco-operator/internal/pkg/instance"
)

// generateApplyConfiguration generates the apply configuration for the Metacollector Deployment.
// It creates a base Deployment and merges it with user-defined overrides from PodTemplateSpec.
func generateApplyConfiguration(cl client.Client, mc *instancev1alpha1.Metacollector) (*unstructured.Unstructured, error) {
	merged, err := mergeDeploymentConfiguration(mc)
	if err != nil {
		return nil, err
	}

	return instance.GenerateResource(
		cl,
		mc,
		func(_ *instancev1alpha1.Metacollector) runtime.Object { return merged },
		instance.GenerateOptions{
			SetControllerRef: true,
			IsClusterScoped:  false,
		},
	)
}

// mergeDeploymentConfiguration merges the base Deployment with user-defined overrides.
func mergeDeploymentConfiguration(mc *instancev1alpha1.Metacollector) (*unstructured.Unstructured, error) {
	userUnstructured, err := generateUserDefinedResource(mc)
	if err != nil {
		return nil, err
	}

	return instance.MergeApplyConfiguration(instance.ResourceTypeDeployment, baseDeployment(mc), userUnstructured)
}

// baseDeployment returns the base Deployment for Metacollector with default values.
func baseDeployment(mc *instancev1alpha1.Metacollector) *appsv1.Deployment {
	return builders.NewDeployment().
		WithName(mc.Name).
		WithNamespace(mc.Namespace).
		WithLabels(mc.Labels).
		WithSelector(map[string]string{
			"app.kubernetes.io/name":     mc.Name,
			"app.kubernetes.io/instance": mc.Name,
		}).
		WithReplicas(mc.Spec.Replicas).
		WithPodTemplateLabels(instance.PodTemplateSpecLabels(mc.Name, mc.Labels)).
		WithServiceAccount(mc.Name).
		WithPodSecurityContext(DefaultPodSecurityContext).
		AddContainer(&corev1.Container{
			Name:            containerName,
			Image:           image.BuildMetacollectorImageStringFromVersion(mc.Spec.Version),
			ImagePullPolicy: DefaultImagePullPolicy,
			Args:            DefaultArgs,
			Ports:           DefaultPorts,
			Resources:       DefaultResources,
			LivenessProbe:   DefaultLivenessProbe,
			ReadinessProbe:  DefaultReadinessProbe,
			SecurityContext: DefaultSecurityContext,
		}).
		WithStrategy(instance.DeploymentStrategy(mc.Spec.Strategy)).
		Build()
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

	if instance.RemoveEmptyContainers(resource) != nil {
		return nil, err
	}

	return resource, nil
}
