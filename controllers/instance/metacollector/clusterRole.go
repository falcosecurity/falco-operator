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

package metacollector

import (
	"context"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/builders"
	"github.com/falcosecurity/falco-operator/internal/pkg/instance"
)

func generateClusterRole(mc *instancev1alpha1.Metacollector) runtime.Object {
	resourceName := instance.GenerateUniqueName(mc.Name, mc.Namespace)

	return builders.NewClusterRole().
		WithName(resourceName).
		WithLabels(mc.Labels).
		AddRule(&rbacv1.PolicyRule{
			APIGroups: []string{"apps"},
			Resources: []string{"daemonsets", "deployments", "replicasets"},
			Verbs:     []string{"get", "list", "watch"},
		}).
		AddRule(&rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"endpoints", "namespaces", "pods", "replicationcontrollers", "services"},
			Verbs:     []string{"get", "list", "watch"},
		}).
		AddRule(&rbacv1.PolicyRule{
			APIGroups: []string{"discovery.k8s.io"},
			Resources: []string{"endpointslices"},
			Verbs:     []string{"get", "list", "watch"},
		}).
		Build()
}

func (r *Reconciler) ensureClusterRole(ctx context.Context, mc *instancev1alpha1.Metacollector) error {
	return instance.EnsureResource(ctx, r.Client, r.recorder, mc, fieldManager,
		generateClusterRole,
		instance.GenerateOptions{SetControllerRef: false, IsClusterScoped: true},
	)
}
