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

package managedfields

import (
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/structured-merge-diff/v4/typed"

	"github.com/falcosecurity/falco-operator/internal/pkg/scheme"
)

// GetObjectType returns a ParseableType for the given object using the Kubernetes schema.
func GetObjectType(obj runtime.Object) (typed.ParseableType, error) {
	gvk := obj.GetObjectKind().GroupVersionKind()
	if gvk.Kind == "" {
		return typed.ParseableType{}, fmt.Errorf("object has no kind set")
	}

	schemaName := deriveSchemaName(gvk.Group, gvk.Version, gvk.Kind)
	parser := scheme.Parser()
	parseableType := parser.Type(schemaName)

	if !parseableType.IsValid() {
		return typed.ParseableType{}, fmt.Errorf("schema type not found for %s (schema name: %s)", gvk, schemaName)
	}

	return parseableType, nil
}

// deriveSchemaName converts a GroupVersionKind to the schema name format used by Kubernetes.
// Pattern: io.k8s.api.<group>.<version>.<Kind>.
func deriveSchemaName(group, version, kind string) string {
	if group == "" {
		// Core resources (v1) have no group
		return fmt.Sprintf("io.k8s.api.core.%s.%s", version, kind)
	}

	// Map full API groups to schema groups
	schemaGroup := apiGroupToSchemaGroup(group)
	return fmt.Sprintf("io.k8s.api.%s.%s.%s", schemaGroup, version, kind)
}

// apiGroupToSchemaGroup maps Kubernetes API groups to their schema names.
func apiGroupToSchemaGroup(apiGroup string) string {
	mappings := map[string]string{
		"apps":                         "apps",
		"rbac.authorization.k8s.io":    "rbac",
		"networking.k8s.io":            "networking",
		"certificates.k8s.io":          "certificates",
		"storage.k8s.io":               "storage",
		"admissionregistration.k8s.io": "admissionregistration",
		"scheduling.k8s.io":            "scheduling",
		"coordination.k8s.io":          "coordination",
		"discovery.k8s.io":             "discovery",
		"batch":                        "batch",
		"autoscaling":                  "autoscaling",
		"policy":                       "policy",
		"flowcontrol.apiserver.k8s.io": "flowcontrol",
		"node.k8s.io":                  "node",
		"events.k8s.io":                "events",
		"apiextensions.k8s.io":         "apiextensions",
	}

	if mapped, ok := mappings[apiGroup]; ok {
		return mapped
	}

	// For unknown groups, try to extract the first part before the dot
	parts := strings.Split(apiGroup, ".")
	return parts[0]
}
