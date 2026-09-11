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
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/falcosecurity/falco-operator/internal/pkg/managedfields"
	"github.com/falcosecurity/falco-operator/internal/pkg/resources"
)

// MergeApplyConfiguration merges a base workload with user-defined overrides
// and normalizes its update strategy, returning the result as unstructured.
// The kind parameter must be an apps/v1 resource kind (e.g., "Deployment", "DaemonSet").
func MergeApplyConfiguration(kind string, baseResource runtime.Object, userOverrides *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	gvk := appsv1.SchemeGroupVersion.WithKind(kind)
	// Partial overrides and base objects may omit their type metadata. Set it on
	// copies so schema lookup does not mutate the caller's objects.
	base := baseResource
	if base.GetObjectKind().GroupVersionKind() != gvk {
		base = base.DeepCopyObject()
		base.GetObjectKind().SetGroupVersionKind(gvk)
	}
	user := userOverrides.DeepCopy()
	user.SetGroupVersionKind(gvk)

	result, err := managedfields.Merge(base, user)
	if err != nil {
		return nil, err
	}

	result.SetGroupVersionKind(gvk)

	if err := enforceStrategyConstraints(result); err != nil {
		return nil, fmt.Errorf("enforcing strategy constraints: %w", err)
	}

	return result, nil
}

// enforceStrategyConstraints enforces Kubernetes strategy field
// constraints on the merged apply configuration.
func enforceStrategyConstraints(obj *unstructured.Unstructured) error {
	switch obj.GetKind() {
	case resources.ResourceTypeDeployment:
		strategyType, found, err := unstructured.NestedString(obj.Object, "spec", "strategy", "type")
		if err != nil {
			return err
		}
		if found && strategyType == string(appsv1.RecreateDeploymentStrategyType) {
			unstructured.RemoveNestedField(obj.Object, "spec", "strategy", "rollingUpdate")
		}
	case resources.ResourceTypeDaemonSet:
		strategyType, found, err := unstructured.NestedString(obj.Object, "spec", "updateStrategy", "type")
		if err != nil {
			return err
		}
		if found && strategyType == string(appsv1.OnDeleteDaemonSetStrategyType) {
			unstructured.RemoveNestedField(obj.Object, "spec", "updateStrategy", "rollingUpdate")
		}
	}
	return nil
}
