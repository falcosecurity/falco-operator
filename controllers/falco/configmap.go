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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
)

// generateRoleBinding returns a RoleBinding for Falco.
func generateConfigmap(cl client.Client, falco *instancev1alpha1.Falco) (*unstructured.Unstructured, error) {
	return generateResourceFromFalcoInstance(cl, falco,
		func(falco *instancev1alpha1.Falco) (runtime.Object, error) {
			var config string

			switch falco.Spec.Type {
			case resourceTypeDeployment:
				config = deploymentFalcoConfig
			case resourceTypeDaemonSet:
				config = daemonsetFalcoConfig
			default:
				return nil, fmt.Errorf("unsupported falco type: %s", falco.Spec.Type)
			}

			cm := &corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ConfigMap",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      falco.Name,
					Namespace: falco.Namespace,
					Labels:    falco.Labels,
				},
				Data: map[string]string{
					"falco.yaml": config,
				},
			}

			return cm, nil
		},
		generateOptions{
			setControllerRef: true,
			isClusterScoped:  false,
		},
	)
}
