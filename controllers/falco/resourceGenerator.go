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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
)

// toUnstructured converts an object to an unstructured.Unstructured.
func toUnstructured(obj any) (*unstructured.Unstructured, error) {
	// If it's already unstructured, just return it
	if u, ok := obj.(*unstructured.Unstructured); ok {
		return u, nil
	}

	// Convert the typed object to unstructured
	unstructuredObj := &unstructured.Unstructured{}
	data, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return nil, err
	}
	unstructuredObj.SetUnstructuredContent(data)

	return unstructuredObj, nil
}

// resourceGenerator defines a function type that generates a Kubernetes resource.
type resourceGenerator func(falco *instancev1alpha1.Falco) (runtime.Object, error)

// generateResourceFromFalcoInstance is a generic function that generates Kubernetes resources.
func generateResourceFromFalcoInstance(
	cl client.Client,
	falco *instancev1alpha1.Falco,
	generator resourceGenerator,
	options generateOptions,
) (*unstructured.Unstructured, error) {
	if falco == nil {
		return nil, fmt.Errorf("falco instance cannot be nil")
	}

	if cl == nil {
		return nil, fmt.Errorf("client cannot be nil")
	}

	if generator == nil {
		return nil, fmt.Errorf("generator function cannot be nil")
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
