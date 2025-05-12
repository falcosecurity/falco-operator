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

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
)

// generateClusterRole creates a ClusterRole resource for the given Falco instance.
// It maps necessary permissions and sets it as an unstructured object. Returns the resource or an error.
func generateClusterRole(ctx context.Context, cl client.Client, falco *instancev1alpha1.Falco) (*unstructured.Unstructured, error) {
	resourceName := GenerateUniqueName(falco.Name, falco.Namespace)

	clusterRole := &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ClusterRole",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:   resourceName,
			Labels: falco.Labels,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"nodes"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"clusterroles", "clusterrolebindings"},
				Verbs:     []string{"get", "list", "watch"},
			},
		},
	}

	// Convert to unstructured object.
	unstructuredObj, err := toUnstructured(clusterRole)
	if err != nil {
		return nil, err
	}

	// Set the defaults by dry-run applying the object.
	if err := setDefaultValues(ctx, cl, unstructuredObj, nil); err != nil {
		return nil, err
	}

	unstructuredObj.SetName(resourceName)

	removeUnwantedFields(unstructuredObj)

	return unstructuredObj, nil
}
