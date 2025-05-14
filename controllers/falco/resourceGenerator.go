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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
)

// resourceGenerator defines a function type that generates a Kubernetes resource.
type resourceGenerator func(falco *instancev1alpha1.Falco) (runtime.Object, error)

// generateResourceFromFalcoInstance is a generic function that generates Kubernetes resources.
func generateResourceFromFalcoInstance(
	ctx context.Context,
	cl client.Client,
	falco *instancev1alpha1.Falco,
	generator resourceGenerator,
	options generateOptions,
) (*unstructured.Unstructured, error) {
	if falco == nil {
		return nil, fmt.Errorf("falco instance cannot be nil")
	}

	// Generate the resource using the provided generator function
	obj, err := generator(falco)
	if err != nil {
		return nil, fmt.Errorf("failed to generate resource: %w", err)
	}

	// Set controller reference if requested.
	if options.setControllerRef {
		if err := controllerutil.SetControllerReference(falco, obj.(metav1.Object), cl.Scheme()); err != nil {
			return nil, fmt.Errorf("failed to set controller reference: %w", err)
		}
	}

	// Convert to unstructured.
	unstructuredObj, err := toUnstructured(obj)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to unstructured: %w", err)
	}

	// Set defaults.
	if err := setDefaultValues(ctx, cl, unstructuredObj); err != nil {
		return nil, fmt.Errorf("failed to set default values: %w", err)
	}

	removeUnwantedFields(unstructuredObj)

	// Set the name based on the resource scope
	if options.isClusterScoped {
		resourceName := GenerateUniqueName(falco.Name, falco.Namespace)
		if err := unstructured.SetNestedField(unstructuredObj.Object, resourceName, "metadata", "name"); err != nil {
			return nil, fmt.Errorf("failed to set name field for cluster-scoped resource: %w", err)
		}
	} else {
		if err := unstructured.SetNestedField(unstructuredObj.Object, falco.Name, "metadata", "name"); err != nil {
			return nil, fmt.Errorf("failed to set name field for namespaced resource: %w", err)
		}
	}

	return unstructuredObj, nil
}

// generateOptions defines options for resource generation.
type generateOptions struct {
	// setControllerRef indicates whether to set the controller reference.
	setControllerRef bool
	// isClusterScoped indicates whether the resource is cluster-scoped.
	isClusterScoped bool
}

// setDefaultValues sets the default values for the unstructured object by dry-run creating it.
func setDefaultValues(ctx context.Context, cl client.Client, obj *unstructured.Unstructured) error {
	if obj == nil {
		return fmt.Errorf("unstructured object cannot be nil")
	}

	if err := unstructured.SetNestedField(obj.Object, "dry-run", "metadata", "generateName"); err != nil {
		return fmt.Errorf("failed to set generateName field: %w", err)
	}

	if err := unstructured.SetNestedField(obj.Object, "", "metadata", "name"); err != nil {
		return fmt.Errorf("failed to set name field: %w", err)
	}

	err := cl.Create(ctx, obj, &client.CreateOptions{DryRun: []string{metav1.DryRunAll}})
	if err != nil {
		return fmt.Errorf("failed to set default values by dry-run creating the object %s: %w", obj.GetKind(), err)
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
