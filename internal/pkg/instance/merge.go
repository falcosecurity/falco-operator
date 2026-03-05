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

package instance

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/falcosecurity/falco-operator/internal/pkg/scheme"
)

const (
	// ResourceTypeDeployment is the resource type for Deployment.
	ResourceTypeDeployment = "Deployment"
	// ResourceTypeDaemonSet is the resource type for DaemonSet.
	ResourceTypeDaemonSet = "DaemonSet"
)

// MergeApplyConfiguration merges a base structured resource with user-defined
// overrides using structured merge diff, and returns the result as unstructured.
// The kind parameter must be an apps/v1 resource kind (e.g., "Deployment", "DaemonSet").
func MergeApplyConfiguration(kind string, baseResource runtime.Object, userOverrides *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	schemaType := "io.k8s.api.apps.v1." + kind
	parser := scheme.Parser()

	baseTyped, err := parser.Type(schemaType).FromStructured(baseResource)
	if err != nil {
		return nil, err
	}

	userTyped, err := parser.Type(schemaType).FromUnstructured(userOverrides.Object)
	if err != nil {
		return nil, err
	}

	desiredTyped, err := baseTyped.Merge(userTyped)
	if err != nil {
		return nil, err
	}

	mergedUnstructured := (desiredTyped.AsValue().Unstructured()).(map[string]interface{})

	result := &unstructured.Unstructured{
		Object: mergedUnstructured,
	}

	result.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   appsv1.GroupName,
		Version: appsv1.SchemeGroupVersion.Version,
		Kind:    kind,
	})

	return result, nil
}

// DeploymentStrategy returns the given strategy or defaults to RollingUpdate.
func DeploymentStrategy(strategy *appsv1.DeploymentStrategy) appsv1.DeploymentStrategy {
	if strategy != nil {
		return *strategy
	}
	return appsv1.DeploymentStrategy{
		Type: appsv1.RollingUpdateDeploymentStrategyType,
	}
}

// DaemonSetUpdateStrategy returns the given strategy or defaults to RollingUpdate.
func DaemonSetUpdateStrategy(strategy *appsv1.DaemonSetUpdateStrategy) appsv1.DaemonSetUpdateStrategy {
	if strategy != nil {
		return *strategy
	}
	return appsv1.DaemonSetUpdateStrategy{
		Type: appsv1.RollingUpdateDaemonSetStrategyType,
	}
}

// PodTemplateSpecLabels returns the labels for a pod template spec,
// merging base labels with the standard app.kubernetes.io/name and instance labels.
func PodTemplateSpecLabels(appName string, baseLabels map[string]string) map[string]string {
	return labels.Merge(baseLabels, map[string]string{
		"app.kubernetes.io/name":     appName,
		"app.kubernetes.io/instance": appName,
	})
}

// RemoveEmptyContainers removes the nil containers field from the unstructured resource if it exists.
// This prevents an empty containers field from overriding the default one during structured merge diff.
func RemoveEmptyContainers(obj *unstructured.Unstructured) error {
	templateSpec, found, err := unstructured.NestedMap(obj.Object, "spec", "template", "spec")
	if err != nil {
		return fmt.Errorf("failed to get podSpec from podTemplateSpec: %w", err)
	}
	if !found {
		return fmt.Errorf("podSpec not found in podTemplateSpec")
	}

	if containers, ok := templateSpec["containers"]; ok {
		if containers == nil {
			unstructured.RemoveNestedField(obj.Object, "spec", "template", "spec", "containers")
		}
	}

	return nil
}
