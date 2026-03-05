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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	instancev1alpha1 "github.com/falcosecurity/falco-operator/api/instance/v1alpha1"
	"github.com/falcosecurity/falco-operator/internal/pkg/instance"
)

// configmapGenerator returns a ResourceGenerator that creates a ConfigMap with the given config.
func configmapGenerator(config string) instance.ResourceGenerator[*instancev1alpha1.Falco] {
	return func(falco *instancev1alpha1.Falco) runtime.Object {
		return &corev1.ConfigMap{
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
	}
}

func (r *Reconciler) ensureConfigMap(ctx context.Context, falco *instancev1alpha1.Falco) error {
	var config string

	switch falco.Spec.Type {
	case instance.ResourceTypeDeployment:
		config = deploymentFalcoConfig
	case instance.ResourceTypeDaemonSet:
		config = daemonsetFalcoConfig
	default:
		return fmt.Errorf("unsupported falco type: %s", falco.Spec.Type)
	}

	return instance.EnsureResource(ctx, r.Client, r.recorder, falco, fieldManager,
		configmapGenerator(config),
		instance.GenerateOptions{SetControllerRef: true, IsClusterScoped: false},
	)
}
