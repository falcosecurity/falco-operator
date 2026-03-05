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
	"context"
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/instance"
)

func generateRoleBinding(falco *instancev1alpha1.Falco) runtime.Object {
	return &rbacv1.RoleBinding{
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
}

func (r *Reconciler) ensureRoleBinding(ctx context.Context, falco *instancev1alpha1.Falco) error {
	return instance.EnsureResource(ctx, r.Client, r.recorder, falco, fieldManager,
		generateRoleBinding,
		instance.GenerateOptions{SetControllerRef: true, IsClusterScoped: false},
	)
}
