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
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// GenerateOptions defines options for resource generation.
type GenerateOptions struct {
	// SetControllerRef indicates whether to set the controller reference.
	SetControllerRef bool
	// IsClusterScoped indicates whether the resource is cluster-scoped.
	IsClusterScoped bool
}

// ResourceGenerator defines a function type that generates a Kubernetes resource from an instance.
type ResourceGenerator[T client.Object] func(obj T) runtime.Object

// GenerateResource generates an unstructured Kubernetes resource from an instance object.
// It calls the generator, optionally sets the controller reference, converts to unstructured,
// and sets the name (using GenerateUniqueName for cluster-scoped resources).
func GenerateResource[T client.Object](
	cl client.Client,
	obj T,
	generator ResourceGenerator[T],
	options GenerateOptions,
) (*unstructured.Unstructured, error) {
	if isNilObject(obj) {
		return nil, fmt.Errorf("instance cannot be nil")
	}

	if cl == nil {
		return nil, fmt.Errorf("client cannot be nil")
	}

	if generator == nil {
		return nil, fmt.Errorf("generator function cannot be nil")
	}

	// Generate the resource using the provided generator function.
	res := generator(obj)

	// Set controller reference if requested.
	if options.SetControllerRef {
		if err := controllerutil.SetControllerReference(obj, res.(metav1.Object), cl.Scheme()); err != nil {
			return nil, fmt.Errorf("failed to set controller reference: %w", err)
		}
	}

	// Convert to unstructured.
	unstructuredObj, err := ToUnstructured(res)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to unstructured: %w", err)
	}

	// Set the name based on the resource scope.
	if options.IsClusterScoped {
		resourceName := GenerateUniqueName(obj.GetName(), obj.GetNamespace())
		if err := unstructured.SetNestedField(unstructuredObj.Object, resourceName, "metadata", "name"); err != nil {
			return nil, fmt.Errorf("failed to set name field for cluster-scoped resource: %w", err)
		}
	} else {
		if err := unstructured.SetNestedField(unstructuredObj.Object, obj.GetName(), "metadata", "name"); err != nil {
			return nil, fmt.Errorf("failed to set name field for namespaced resource: %w", err)
		}
	}

	return unstructuredObj, nil
}

// isNilObject checks whether a client.Object interface holds a nil pointer.
func isNilObject[T client.Object](obj T) bool {
	v := reflect.ValueOf(obj)
	return !v.IsValid() || v.IsNil()
}
