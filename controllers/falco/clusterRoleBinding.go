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

// generateClusterRoleBinding creates a ClusterRoleBinding resource for the provided Falco instance in a Kubernetes cluster.
// It associates a specified ServiceAccount with a ClusterRole and ensures the object is managed by the Falco instance.
// The function converts the ClusterRoleBinding object to unstructured format and sets default values for it.
func generateClusterRoleBinding(ctx context.Context, cl client.Client, falco *instancev1alpha1.Falco) (*unstructured.Unstructured, error) {
	resourceName := GenerateUniqueName(falco.Name, falco.Namespace)

	clusterRoleBinding := &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ClusterRoleBinding",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:   resourceName,
			Labels: falco.Labels,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      falco.Name,
				Namespace: falco.Namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     resourceName,
			APIGroup: "rbac.authorization.k8s.io",
		},
	}

	unstructuredObj, err := toUnstructured(clusterRoleBinding)
	if err != nil {
		return nil, err
	}

	if err := setDefaultValues(ctx, cl, unstructuredObj); err != nil {
		return nil, err
	}

	unstructuredObj.SetName(resourceName)

	removeUnwantedFields(unstructuredObj)

	return unstructuredObj, nil
}
