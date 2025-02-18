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
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/structured-merge-diff/v4/typed"

	"github.com/alacuku/falco-operator/internal/pkg/scheme"
)

// diff calculates the difference between the current and desired unstructured objects.
func diff(current, desired *unstructured.Unstructured) (*typed.Comparison, error) {
	// Make diff between the current resource and the desired one.
	// Create a parser to compare the resources.
	parser := scheme.Parser()

	resourceType := current.GetKind()

	// Parse the base resource.
	currentTyped, err := parser.Type("io.k8s.api.apps.v1." + resourceType).FromUnstructured(current.Object)
	if err != nil {
		return nil, err
	}

	// Parse the user defined resource.
	desiredTyped, err := parser.Type("io.k8s.api.apps.v1." + resourceType).FromUnstructured(desired.Object)
	if err != nil {
		return nil, err
	}

	return currentTyped.Compare(desiredTyped)
}
