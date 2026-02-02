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
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/structured-merge-diff/v4/typed"

	"github.com/falcosecurity/falco-operator/internal/pkg/scheme"
)

// diff calculates the difference between the current and desired objects.
// It accepts either unstructured.Unstructured objects or typed objects that can be converted to unstructured.
//
// This is used to avoid unnecessary API writes on Kubernetes versions < 1.31 where
// Server-Side Apply may cause spurious resourceVersion bumps on no-op patches to CRDs.
// See: https://github.com/kubernetes/kubernetes/issues/124605
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

	// Remove server-managed fields before comparison
	removeUnwantedFields(currentUnstructured)
	removeUnwantedFields(desiredUnstructured)

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

// removeUnwantedFields removes server-managed fields from the unstructured object
// so they don't affect the comparison.
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
