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
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// clusterScopedResourceHandler used to handle cluster-scoped resources like ClusterRole and ClusterRoleBinding.
// It returns a list of reconcile.Requests for the Falco instance associated with the resource.
func clusterScopedResourceHandler(ctx context.Context, obj client.Object) []reconcile.Request {
	var ns types.NamespacedName

	logger := log.FromContext(ctx)

	switch obj.(type) {
	case *rbacv1.ClusterRoleBinding, *rbacv1.ClusterRole:
		// We extract the Falco instance name and namespace from the resource name.
		name, namespace, err := ParseUniqueName(obj.GetName())
		ns = types.NamespacedName{
			Name:      name,
			Namespace: namespace,
		}

		if err != nil {
			logger.V(5).Info("Failed to parse unique name", "name", obj.GetName(), "error", err)
			return nil
		}

	default:
		return nil
	}

	return []reconcile.Request{
		{
			NamespacedName: ns,
		},
	}
}
