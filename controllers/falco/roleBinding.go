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

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
)

// generateRoleBinding returns a RoleBinding for Falco.
func generateRoleBinding(cl client.Client, falco *instancev1alpha1.Falco) (*unstructured.Unstructured, error) {
	return generateResourceFromFalcoInstance(cl, falco,
		func(falco *instancev1alpha1.Falco) (runtime.Object, error) {
			rb := &rbacv1.RoleBinding{
				TypeMeta: metav1.TypeMeta{
					Kind:       "RoleBinding",
					APIVersion: "rbac.authorization.k8s.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Namespace:    falco.Namespace,
					Labels:       falco.Labels,
					GenerateName: fmt.Sprintf("%s-", falco.Name),
				},
				Subjects: []rbacv1.Subject{
					{
						Kind:      "ServiceAccount",
						Name:      falco.Name,
						Namespace: falco.Namespace,
					},
				},
				RoleRef: rbacv1.RoleRef{
					Kind:     "Role",
					Name:     falco.Name,
					APIGroup: "rbac.authorization.k8s.io",
				},
			}
			return rb, nil
		},
		generateOptions{
			setControllerRef: true,
			isClusterScoped:  false,
		},
	)
}
