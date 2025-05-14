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
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/structured-merge-diff/v4/typed"

	"github.com/falcosecurity/falco-operator/internal/pkg/scheme"
)

// diff calculates the difference between the current and desired objects.
// It accepts either unstructured.Unstructured objects or typed objects that can be converted to unstructured.
func diff(current, desired interface{}) (*typed.Comparison, error) {
	// Convert inputs to unstructured if needed
	currentUnstructured, err := toUnstructured(current)
	if err != nil {
		return nil, fmt.Errorf("failed to convert current object to unstructured: %w", err)
	}

	desiredUnstructured, err := toUnstructured(desired)
	if err != nil {
		return nil, fmt.Errorf("failed to convert desired object to unstructured: %w", err)
	}

	// Create a parser to compare the resources
	parser := scheme.Parser()

	currentTypePath := getTypePath(currentUnstructured)

	// Parse the base resource
	currentTyped, err := parser.Type(currentTypePath).FromUnstructured(currentUnstructured.Object)
	if err != nil {
		return nil, err
	}

	desiredTypePath := getTypePath(desiredUnstructured)
	// Parse the user defined resource
	desiredTyped, err := parser.Type(desiredTypePath).FromUnstructured(desiredUnstructured.Object)
	if err != nil {
		return nil, err
	}

	return currentTyped.Compare(desiredTyped)
}

// getTypePath returns the schema type path for an unstructured object.
func getTypePath(obj *unstructured.Unstructured) string {
	apiVersion := obj.GetAPIVersion()
	resourceType := obj.GetKind()
	gv := strings.Split(apiVersion, "/")

	// Build the schema path based on whether it's a core resource or not
	var typePath string
	if len(gv) == 1 {
		// Core resources like v1 have no group
		typePath = fmt.Sprintf("io.k8s.api.core.%s.%s", gv[0], resourceType)
	} else {
		// Other resources have group and version
		typePath = fmt.Sprintf("io.k8s.api.%s.%s.%s", apiGroupToSchemaGroup(gv[0]), gv[1], resourceType)
	}

	return typePath
}

func apiGroupToSchemaGroup(apiGroup string) string {
	mappings := map[string]string{
		"rbac.authorization.k8s.io":    "rbac",
		"networking.k8s.io":            "networking",
		"certificates.k8s.io":          "certificates",
		"storage.k8s.io":               "storage",
		"admissionregistration.k8s.io": "admissionregistration",
		"scheduling.k8s.io":            "scheduling",
		"coordination.k8s.io":          "coordination",
		"discovery.k8s.io":             "discovery",
	}

	if mapped, ok := mappings[apiGroup]; ok {
		return mapped
	}

	return apiGroup
}

// toUnstructured converts an object to an unstructured.Unstructured.
func toUnstructured(obj interface{}) (*unstructured.Unstructured, error) {
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
